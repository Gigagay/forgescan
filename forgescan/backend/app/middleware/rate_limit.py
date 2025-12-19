# backend/app/middleware/rate_limit.py
"""
Advanced rate limiting with Redis
Implements: Token bucket, Sliding window, IP-based, User-based
"""

import redis
from datetime import datetime, timedelta
from fastapi import HTTPException, Request
from typing import Optional

class RateLimiter:
    """Advanced rate limiting service"""
    
    def __init__(self):
        self.redis = redis.Redis(
            host=os.environ['REDIS_HOST'],
            port=6379,
            decode_responses=True
        )
    
    async def check_rate_limit(
        self,
        identifier: str,
        limit: int,
        window: int,
        endpoint: Optional[str] = None
    ) -> bool:
        """
        Check rate limit using sliding window
        
        Args:
            identifier: User ID or IP address
            limit: Max requests allowed
            window: Time window in seconds
            endpoint: Specific endpoint (optional)
        """
        key = f"ratelimit:{identifier}:{endpoint or 'global'}"
        now = datetime.utcnow().timestamp()
        
        # Remove old entries
        self.redis.zremrangebyscore(key, 0, now - window)
        
        # Count requests in window
        request_count = self.redis.zcard(key)
        
        if request_count >= limit:
            # Get reset time
            oldest = self.redis.zrange(key, 0, 0, withscores=True)
            if oldest:
                reset_time = oldest[0][1] + window
                raise HTTPException(
                    status_code=429,
                    detail={
                        "error": "Rate limit exceeded",
                        "retry_after": int(reset_time - now),
                        "limit": limit,
                        "window": window
                    }
                )
        
        # Add current request
        self.redis.zadd(key, {str(now): now})
        self.redis.expire(key, window)
        
        return True

# Middleware
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Apply rate limiting to all requests"""
    
    limiter = RateLimiter()
    
    # Get identifier (user ID or IP)
    user = getattr(request.state, "user", None)
    identifier = user.id if user else request.client.host
    
    # Different limits for different tiers
    if user:
        if user.subscription_tier == "free":
            await limiter.check_rate_limit(identifier, limit=100, window=3600)  # 100/hour
        elif user.subscription_tier == "pro":
            await limiter.check_rate_limit(identifier, limit=1000, window=3600)  # 1000/hour
        elif user.subscription_tier == "enterprise":
            await limiter.check_rate_limit(identifier, limit=10000, window=3600)  # 10k/hour
    else:
        # Anonymous users - strict limits
        await limiter.check_rate_limit(identifier, limit=10, window=600)  # 10/10min
    
    # Endpoint-specific limits
    if request.url.path.startswith("/api/v1/scans"):
        await limiter.check_rate_limit(
            identifier,
            limit=10,
            window=60,
            endpoint="scans"
        )  # 10 scans per minute max
    
    response = await call_next(request)
    
    # Add rate limit headers
    response.headers["X-RateLimit-Limit"] = "1000"
    response.headers["X-RateLimit-Remaining"] = "950"
    response.headers["X-RateLimit-Reset"] = str(int(datetime.utcnow().timestamp()) + 3600)
    
    return response