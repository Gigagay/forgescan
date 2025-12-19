# backend/app/api/v1/billing.py
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, Any
import uuid

from app.db.database import get_db
from app.db.repositories.tenant_repository import TenantRepository
from app.db.models.user import User
from app.api.dependencies import get_current_active_user
from app.core.config import settings
from app.core.constants import PlanType
from app.services.peach_payments_service import PeachPaymentsService
from app.core.logging import logger

router = APIRouter()

# Plan pricing (update based on your pricing)
PLAN_PRICING = {
    "developer": {
        "monthly": {"usd": 9.00, "zar": 150.00, "kes": 1200.00},
        "yearly": {"usd": 90.00, "zar": 1500.00, "kes": 12000.00},
    },
    "startup": {
        "monthly": {"usd": 49.00, "zar": 800.00, "kes": 6500.00},
        "yearly": {"usd": 490.00, "zar": 8000.00, "kes": 65000.00},
    },
    "professional": {
        "monthly": {"usd": 199.00, "zar": 3200.00, "kes": 26000.00},
        "yearly": {"usd": 1990.00, "zar": 32000.00, "kes": 260000.00},
    },
}


@router.post("/create-checkout-session")
async def create_checkout_session(
    plan: str,
    billing_period: str,  # monthly or yearly
    currency: str = "USD",  # USD, ZAR, KES, etc.
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Create Peach Payments checkout session"""
    tenant_repo = TenantRepository(db)
    tenant = await tenant_repo.get_by_id(current_user.tenant_id)
    
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    
    # Validate plan
    if plan not in PLAN_PRICING:
        raise HTTPException(status_code=400, detail="Invalid plan")
    
    # Get pricing
    currency_lower = currency.lower()
    if currency_lower not in PLAN_PRICING[plan][billing_period]:
        raise HTTPException(status_code=400, detail=f"Currency {currency} not supported for this plan")
    
    amount = PLAN_PRICING[plan][billing_period][currency_lower]
    
    try:
        peach = PeachPaymentsService()
        
        # Create unique transaction ID
        transaction_id = f"sub_{tenant.id}_{uuid.uuid4().hex[:8]}"
        
        # Create recurring registration (subscription)
        result = await peach.create_recurring_registration(
            amount=amount,
            currency=currency.upper(),
            merchant_transaction_id=transaction_id,
            customer_email=current_user.email,
            customer_name=current_user.full_name or current_user.email,
            plan=plan,
            billing_period=billing_period,
        )
        
        # Store transaction info in database (optional)
        await tenant_repo.update(tenant.id, {
            "peach_transaction_id": transaction_id,
        })
        await db.commit()
        
        return {
            "checkout_url": result["checkout_url"],
            "checkout_id": result["checkout_id"],
        }
        
    except Exception as e:
        logger.error(f"Checkout creation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/checkout-status/{checkout_id}")
async def get_checkout_status(
    checkout_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """Get checkout payment status"""
    try:
        peach = PeachPaymentsService()
        status = await peach.get_payment_status(checkout_id)
        
        return status
        
    except Exception as e:
        logger.error(f"Failed to get status: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/webhook")
async def peach_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    """Handle Peach Payments webhooks"""
    
    # Get raw body for signature verification
    body = await request.body()
    signature = request.headers.get("X-Signature", "")
    
    peach = PeachPaymentsService()
    
    # Verify signature
    if not peach.verify_webhook_signature(body.decode(), signature):
        logger.warning("Invalid webhook signature")
        raise HTTPException(status_code=400, detail="Invalid signature")
    
    # Parse webhook data
    import json
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    tenant_repo = TenantRepository(db)
    
    # Handle payment success
    result_code = data.get("result", {}).get("code", "")
    
    # Peach Payments success pattern
    import re
    success_pattern = r"^(000\.000\.|000\.100\.1|000\.[36])"
    is_success = bool(re.match(success_pattern, result_code))
    
    if is_success:
        # Extract metadata
        custom_params = data.get("customParameters", {})
        plan = custom_params.get("plan")
        transaction_id = data.get("merchantTransactionId")
        registration_id = data.get("registrationId")
        
        # Find tenant by transaction ID
        # You'd need to store and query this properly
        # For now, extract from transaction_id format: sub_{tenant_id}_{random}
        if transaction_id and transaction_id.startswith("sub_"):
            parts = transaction_id.split("_")
            if len(parts) >= 2:
                tenant_id = parts[1]
                
                # Update tenant subscription
                await tenant_repo.update(tenant_id, {
                    "plan": plan,
                    "peach_registration_id": registration_id,
                    "subscription_status": "active",
                })
                await db.commit()
                
                logger.info(f"Subscription activated for tenant {tenant_id}")
    
    return {"status": "success"}


@router.post("/cancel-subscription")
async def cancel_subscription(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Cancel current subscription"""
    tenant_repo = TenantRepository(db)
    tenant = await tenant_repo.get_by_id(current_user.tenant_id)
    
    if not tenant or not tenant.peach_registration_id:
        raise HTTPException(status_code=400, detail="No active subscription")
    
    try:
        peach = PeachPaymentsService()
        success = await peach.cancel_registration(tenant.peach_registration_id)
        
        if success:
            # Downgrade to free plan
            await tenant_repo.update(tenant.id, {
                "plan": PlanType.FREE,
                "subscription_status": "cancelled",
                "peach_registration_id": None,
            })
            await db.commit()
            
            return {"message": "Subscription cancelled successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to cancel subscription")
        
    except Exception as e:
        logger.error(f"Cancellation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/usage")
async def get_usage_stats(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get current usage statistics"""
    tenant_repo = TenantRepository(db)
    tenant = await tenant_repo.get_by_id(current_user.tenant_id)
    usage_stats = await tenant_repo.get_usage_stats(current_user.tenant_id)
    
    from app.core.constants import PLAN_LIMITS
    plan_limits = PLAN_LIMITS[tenant.plan]
    
    return {
        "current_plan": tenant.plan,
        "subscription_status": tenant.subscription_status,
        "limits": plan_limits,
        "usage": usage_stats,
        "scans_remaining": max(0, plan_limits["max_scans_per_month"] - usage_stats["scans_this_month"]),
    }
