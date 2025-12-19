# backend/app/services/peach_payments_service.py
import httpx
import hashlib
import hmac
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from uuid import uuid4

from app.core.config import settings
from app.core.logging import logger


class PeachPaymentsService:
    """Service for Peach Payments integration"""
    
    def __init__(self):
        self.entity_id = settings.PEACH_ENTITY_ID
        self.access_token = settings.PEACH_ACCESS_TOKEN
        self.webhook_secret = settings.PEACH_WEBHOOK_SECRET
        self.base_url = settings.PEACH_BASE_URL or "https://eu-prod.oppwa.com"
        self.test_mode = settings.PEACH_TEST_MODE
    
    async def create_checkout(
        self,
        amount: float,
        currency: str,
        merchant_transaction_id: str,
        customer_email: str,
        customer_name: str,
        plan: str,
        billing_period: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create a Peach Payments checkout session
        
        Args:
            amount: Amount in major currency units (e.g., 9.00 for $9)
            currency: Currency code (USD, ZAR, KES, etc.)
            merchant_transaction_id: Your unique transaction ID
            customer_email: Customer email
            customer_name: Customer name
            plan: Plan type (developer, startup, professional)
            billing_period: monthly or yearly
            metadata: Additional metadata
        
        Returns:
            Dict with checkout_id and checkout_url
        """
        try:
            # Peach Payments requires amount in minor units (cents)
            amount_cents = int(amount * 100)
            
            # Prepare checkout data
            data = {
                "entityId": self.entity_id,
                "amount": f"{amount:.2f}",
                "currency": currency,
                "paymentType": "DB",  # Debit (immediate payment)
                "merchantTransactionId": merchant_transaction_id,
                "customer.email": customer_email,
                "customer.givenName": customer_name.split()[0] if customer_name else "",
                "customer.surname": customer_name.split()[-1] if customer_name else "",
                "customParameters[plan]": plan,
                "customParameters[billing_period]": billing_period,
                "billing.country": "ZA",  # Change based on your primary market
                "shopperResultUrl": f"{settings.FRONTEND_URL}/billing/success",
                "notificationUrl": f"{settings.BACKEND_URL}/api/v1/billing/webhook",
            }
            
            # Add metadata as custom parameters
            if metadata:
                for key, value in metadata.items():
                    data[f"customParameters[{key}]"] = str(value)
            
            # Create checkout
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/v1/checkouts",
                    data=data,
                    headers={
                        "Authorization": f"Bearer {self.access_token}",
                    },
                    timeout=30.0,
                )
                
                result = response.json()
                
                if response.status_code != 200:
                    logger.error(f"Peach Payments error: {result}")
                    raise Exception(f"Failed to create checkout: {result.get('result', {}).get('description', 'Unknown error')}")
                
                checkout_id = result.get("id")
                
                # Build checkout URL (customer will be redirected here)
                checkout_url = f"{settings.FRONTEND_URL}/billing/checkout?id={checkout_id}"
                
                logger.info(f"Created Peach Payments checkout: {checkout_id}")
                
                return {
                    "checkout_id": checkout_id,
                    "checkout_url": checkout_url,
                    "amount": amount,
                    "currency": currency,
                }
        
        except Exception as e:
            logger.error(f"Peach Payments checkout creation failed: {str(e)}")
            raise
    
    async def create_recurring_registration(
        self,
        amount: float,
        currency: str,
        merchant_transaction_id: str,
        customer_email: str,
        customer_name: str,
        plan: str,
        billing_period: str
    ) -> Dict[str, Any]:
        """
        Create a recurring payment registration (subscription)
        """
        try:
            data = {
                "entityId": self.entity_id,
                "amount": f"{amount:.2f}",
                "currency": currency,
                "paymentType": "RG",  # Registration for recurring
                "merchantTransactionId": merchant_transaction_id,
                "customer.email": customer_email,
                "customer.givenName": customer_name.split()[0] if customer_name else "",
                "customer.surname": customer_name.split()[-1] if customer_name else "",
                "customParameters[plan]": plan,
                "customParameters[billing_period]": billing_period,
                "recurringType": "REPEATED",
                "shopperResultUrl": f"{settings.FRONTEND_URL}/billing/success",
                "notificationUrl": f"{settings.BACKEND_URL}/api/v1/billing/webhook",
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/v1/checkouts",
                    data=data,
                    headers={
                        "Authorization": f"Bearer {self.access_token}",
                    },
                    timeout=30.0,
                )
                
                result = response.json()
                
                if response.status_code != 200:
                    raise Exception(f"Failed to create registration: {result.get('result', {}).get('description')}")
                
                return {
                    "checkout_id": result.get("id"),
                    "checkout_url": f"{settings.FRONTEND_URL}/billing/checkout?id={result.get('id')}",
                }
        
        except Exception as e:
            logger.error(f"Recurring registration failed: {str(e)}")
            raise
    
    async def get_payment_status(self, checkout_id: str) -> Dict[str, Any]:
        """
        Get payment status by checkout ID
        
        Returns:
            Dict with payment status and details
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/v1/checkouts/{checkout_id}/payment",
                    params={"entityId": self.entity_id},
                    headers={
                        "Authorization": f"Bearer {self.access_token}",
                    },
                    timeout=30.0,
                )
                
                result = response.json()
                
                # Peach Payments success codes
                success_pattern = r"^(000\.000\.|000\.100\.1|000\.[36])"
                result_code = result.get("result", {}).get("code", "")
                
                import re
                is_success = bool(re.match(success_pattern, result_code))
                
                return {
                    "success": is_success,
                    "status": "success" if is_success else "failed",
                    "result_code": result_code,
                    "description": result.get("result", {}).get("description"),
                    "transaction_id": result.get("id"),
                    "registration_id": result.get("registrationId"),
                    "amount": result.get("amount"),
                    "currency": result.get("currency"),
                    "payment_brand": result.get("paymentBrand"),
                    "custom_parameters": result.get("customParameters", {}),
                }
        
        except Exception as e:
            logger.error(f"Failed to get payment status: {str(e)}")
            raise
    
    async def charge_recurring_payment(
        self,
        registration_id: str,
        amount: float,
        currency: str,
        merchant_transaction_id: str
    ) -> Dict[str, Any]:
        """
        Charge a recurring payment using stored registration
        """
        try:
            data = {
                "entityId": self.entity_id,
                "amount": f"{amount:.2f}",
                "currency": currency,
                "paymentType": "DB",
                "merchantTransactionId": merchant_transaction_id,
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/v1/registrations/{registration_id}/payments",
                    data=data,
                    headers={
                        "Authorization": f"Bearer {self.access_token}",
                    },
                    timeout=30.0,
                )
                
                result = response.json()
                
                success_pattern = r"^(000\.000\.|000\.100\.1|000\.[36])"
                result_code = result.get("result", {}).get("code", "")
                
                import re
                is_success = bool(re.match(success_pattern, result_code))
                
                return {
                    "success": is_success,
                    "transaction_id": result.get("id"),
                    "result_code": result_code,
                    "description": result.get("result", {}).get("description"),
                }
        
        except Exception as e:
            logger.error(f"Recurring charge failed: {str(e)}")
            raise
    
    async def cancel_registration(self, registration_id: str) -> bool:
        """Cancel a recurring payment registration"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.delete(
                    f"{self.base_url}/v1/registrations/{registration_id}",
                    params={"entityId": self.entity_id},
                    headers={
                        "Authorization": f"Bearer {self.access_token}",
                    },
                    timeout=30.0,
                )
                
                return response.status_code == 200
        
        except Exception as e:
            logger.error(f"Failed to cancel registration: {str(e)}")
            return False
    
    def verify_webhook_signature(self, payload: str, signature: str) -> bool:
        """
        Verify webhook signature from Peach Payments
        
        Args:
            payload: Raw request body
            signature: X-Signature header value
        
        Returns:
            True if signature is valid
        """
        if not self.webhook_secret:
            logger.warning("Webhook secret not configured")
            return True  # Skip verification in development
        
        try:
            # Peach Payments uses HMAC SHA-256
            expected_signature = hmac.new(
                self.webhook_secret.encode(),
                payload.encode(),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(signature, expected_signature)
        
        except Exception as e:
            logger.error(f"Webhook signature verification failed: {str(e)}")
            return False

