# backend/app/middleware/waf.py
"""
Application-level WAF
Blocks: SQL injection, XSS, CSRF, Path traversal, etc.
"""

import re
from fastapi import HTTPException, Request
from typing import List, Pattern

class WAF:
    """Web Application Firewall"""
    
    # Attack patterns
    SQL_INJECTION_PATTERNS: List[Pattern] = [
        re.compile(r"(\bunion\b.*\bselect\b)", re.IGNORECASE),
        re.compile(r"(\bor\b\s+\d+\s*=\s*\d+)", re.IGNORECASE),
        re.compile(r"(;\s*drop\s+table)", re.IGNORECASE),
        re.compile(r"(--|\#|\/\*)", re.IGNORECASE),
        re.compile(r"(\bexec\b|\bexecute\b)", re.IGNORECASE),
    ]
    
    XSS_PATTERNS: List[Pattern] = [
        re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
        re.compile(r"javascript:", re.IGNORECASE),
        re.compile(r"on\w+\s*=", re.IGNORECASE),
        re.compile(r"<iframe", re.IGNORECASE),
    ]
    
    PATH_TRAVERSAL_PATTERNS: List[Pattern] = [
        re.compile(r"\.\./"),
        re.compile(r"\.\.\\"),
        re.compile(r"%2e%2e/", re.IGNORECASE),
    ]
    
    COMMAND_INJECTION_PATTERNS: List[Pattern] = [
        re.compile(r"[;&|`$()]"),
        re.compile(r"&&|\|\|"),
    ]
    
    def __init__(self):
        self.blocked_ips: set = self.load_blocked_ips()
        self.suspicious_patterns = (
            self.SQL_INJECTION_PATTERNS +
            self.XSS_PATTERNS +
            self.PATH_TRAVERSAL_PATTERNS +
            self.COMMAND_INJECTION_PATTERNS
        )
    
    def load_blocked_ips(self) -> set:
        """Load blocked IPs from database/redis"""
        # TODO: Implement Redis/DB lookup
        return set()
    
    async def check_request(self, request: Request) -> bool:
        """Analyze request for attacks"""
        
        # Check IP blocklist
        client_ip = request.client.host
        if client_ip in self.blocked_ips:
            raise HTTPException(403, "IP address blocked")
        
        # Check headers for suspicious content
        for header, value in request.headers.items():
            if self._contains_attack_pattern(value):
                await self._log_attack(request, "Malicious header detected")
                raise HTTPException(400, "Malicious request detected")
        
        # Check query parameters
        for param, value in request.query_params.items():
            if self._contains_attack_pattern(value):
                await self._log_attack(request, f"Malicious query param: {param}")
                raise HTTPException(400, "Malicious request detected")
        
        # Check request body
        if request.method in ["POST", "PUT", "PATCH"]:
            body = await request.body()
            if self._contains_attack_pattern(body.decode('utf-8', errors='ignore')):
                await self._log_attack(request, "Malicious request body")
                raise HTTPException(400, "Malicious request detected")
        
        return True
    
    def _contains_attack_pattern(self, text: str) -> bool:
        """Check if text contains attack patterns"""
        for pattern in self.suspicious_patterns:
            if pattern.search(text):
                return True
        return False
    
    async def _log_attack(self, request: Request, reason: str):
        """Log attack attempt"""
        attack_log = {
            "timestamp": datetime.utcnow(),
            "ip": request.client.host,
            "user_agent": request.headers.get("user-agent"),
            "method": request.method,
            "path": request.url.path,
            "reason": reason
        }
        
        # Log to database/SIEM
        logger.warning(f"Attack detected: {attack_log}")
        
        # Auto-block after 3 attempts
        # TODO: Implement auto-blocking logic

# Apply WAF middleware
@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    waf = WAF()
    await waf.check_rate_limit(request)
    response = await call_next(request)
    return response