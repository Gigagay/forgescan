# backend/app/core/zero_trust.py
"""
Zero-Trust Security Implementation
Never trust, always verify
"""

from enum import Enum
from typing import Optional
from datetime import datetime, timedelta


class TrustLevel(str, Enum):
    """Trust levels for zero-trust model"""
    UNTRUSTED = "untrusted"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERIFIED = "verified"


class ZeroTrustValidator:
    """Implement zero-trust security model"""
    
    def __init__(self):
        self.redis = redis.Redis()
    
    async def calculate_trust_score(
        self,
        user_id: str,
        ip_address: str,
        user_agent: str,
        mfa_verified: bool
    ) -> TrustLevel:
        """
        Calculate trust level based on multiple factors
        
        Factors:
        - Known device/IP
        - MFA verification
        - Recent suspicious activity
        - Geolocation anomalies
        - Time-based patterns
        """
        
        score = 0
        
        # Check if device is known
        if await self._is_known_device(user_id, ip_address, user_agent):
            score += 30
        
        # MFA verification
        if mfa_verified:
            score += 40
        
        # Check login history
        if await self._has_recent_successful_logins(user_id):
            score += 20
        
        # Check for suspicious activity
        if await self._has_suspicious_activity(user_id):
            score -= 50
        
        # Geolocation check
        if await self._is_expected_location(user_id, ip_address):
            score += 10
        
        # Map score to trust level
        if score >= 80:
            return TrustLevel.VERIFIED
        elif score >= 60:
            return TrustLevel.HIGH
        elif score >= 40:
            return TrustLevel.MEDIUM
        elif score >= 20:
            return TrustLevel.LOW
        else:
            return TrustLevel.UNTRUSTED
    
    async def _is_known_device(
        self,
        user_id: str,
        ip_address: str,
        user_agent: str
    ) -> bool:
        """Check if device/IP is recognized"""
        
        device_fingerprint = hashlib.sha256(
            f"{ip_address}:{user_agent}".encode()
        ).hexdigest()
        
        key = f"known_device:{user_id}:{device_fingerprint}"
        return self.redis.exists(key)
    
    async def register_trusted_device(
        self,
        user_id: str,
        ip_address: str,
        user_agent: str
    ):
        """Register device as trusted"""
        
        device_fingerprint = hashlib.sha256(
            f"{ip_address}:{user_agent}".encode()
        ).hexdigest()
        
        key = f"known_device:{user_id}:{device_fingerprint}"
        
        # Store for 90 days
        self.redis.setex(key, 90 * 24 * 3600, "trusted")
    
    async def require_step_up_auth(
        self,
        user_id: str,
        trust_level: TrustLevel,
        action_sensitivity: str
    ) -> bool:
        """
        Determine if step-up authentication is required
        
        Sensitive actions require higher trust levels
        """
        
        # Define sensitivity requirements
        requirements = {
            'low': TrustLevel.LOW,
            'medium': TrustLevel.MEDIUM,
            'high': TrustLevel.HIGH,
            'critical': TrustLevel.VERIFIED
        }
        
        required_level = requirements.get(action_sensitivity, TrustLevel.MEDIUM)
        
        # Compare trust levels
        trust_order = [
            TrustLevel.UNTRUSTED,
            TrustLevel.LOW,
            TrustLevel.MEDIUM,
            TrustLevel.HIGH,
            TrustLevel.VERIFIED
        ]
        
        current_index = trust_order.index(trust_level)
        required_index = trust_order.index(required_level)
        
        return current_index < required_index


# Middleware for zero-trust
async def verify_trust_level(
    request: Request,
    required_trust: TrustLevel = TrustLevel.MEDIUM
):
    """Verify request meets trust level requirements"""
    
    user = request.state.user
    
    validator = ZeroTrustValidator()
    
    trust_level = await validator.calculate_trust_score(
        user_id=str(user.id),
        ip_address=request.client.host,
        user_agent=request.headers.get('User-Agent', ''),
        mfa_verified=getattr(user, 'mfa_verified', False)
    )
    
    if trust_level.value < required_trust.value:
        raise HTTPException(
            status_code=403,
            detail="Insufficient trust level. Additional verification required."
        )
    
    # Store trust level in request state
    request.state.trust_level = trust_level

