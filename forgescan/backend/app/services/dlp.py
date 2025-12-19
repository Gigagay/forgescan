# backend/app/services/dlp.py
"""
Data Loss Prevention System
Prevents sensitive data from leaving the system
"""

import re
from typing import List, Dict, Tuple

class DLPService:
    """Detect and prevent data leaks"""
    
    # Sensitive data patterns
    PATTERNS = {
        'credit_card': re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
        'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        'api_key': re.compile(r'\b[A-Za-z0-9_-]{32,}\b'),
        'private_key': re.compile(r'-----BEGIN (RSA |)PRIVATE KEY-----'),
        'aws_key': re.compile(r'AKIA[0-9A-Z]{16}'),
        'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'ip_address': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
    }
    
    async def scan_content(self, content: str) -> List[Dict]:
        """Scan content for sensitive data"""
        
        findings = []
        
        for data_type, pattern in self.PATTERNS.items():
            matches = pattern.finditer(content)
            
            for match in matches:
                findings.append({
                    "type": data_type,
                    "value": match.group(),
                    "position": match.span(),
                    "severity": self._get_severity(data_type)
                })
        
        return findings
    
    async def sanitize_logs(self, log_message: str) -> str:
        """Remove sensitive data from logs"""
        
        sanitized = log_message
        
        for data_type, pattern in self.PATTERNS.items():
            sanitized = pattern.sub(f'[REDACTED_{data_type.upper()}]', sanitized)
        
        return sanitized
    
    async def check_export(self, data: Dict) -> Tuple[bool, List[str]]:
        """Check if data export contains sensitive information"""
        
        violations = []
        content = json.dumps(data)
        
        findings = await self.scan_content(content)
        
        for finding in findings:
            if finding['severity'] in ['high', 'critical']:
                violations.append(
                    f"Attempted export of {finding['type']}: {finding['value'][:10]}..."
                )
        
        if violations:
            # Log security incident
            await SecurityMonitor().track_dlp_violation(violations)
            return False, violations
        
        return True, []
    
    def _get_severity(self, data_type: str) -> str:
        """Determine severity of data type"""
        
        high_severity = ['credit_card', 'ssn', 'private_key', 'aws_key']
        
        return 'critical' if data_type in high_severity else 'medium'

# Middleware to prevent sensitive data in responses
@app.middleware("http")
async def dlp_middleware(request: Request, call_next):
    """Scan responses for sensitive data"""
    
    response = await call_next(request)
    
    # Only scan text responses
    if response.headers.get("content-type", "").startswith("application/json"):
        body = b""
        async for chunk in response.body_iterator:
            body += chunk
        
        content = body.decode()
        
        # Scan for sensitive data
        dlp = DLPService()
        findings = await dlp.scan_content(content)
        
        if findings:
            # Log incident
            logger.warning(f"DLP: Sensitive data detected in response: {findings}")
            
            # Optionally block response
            if any(f['severity'] == 'critical' for f in findings):
                return JSONResponse(
                    status_code=451,
                    content={"error": "Response blocked by DLP policy"}
                )
        
        return Response(content=body, headers=dict(response.headers))
    
    return response