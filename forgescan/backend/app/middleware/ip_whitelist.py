# backend/app/middleware/ip_whitelist.py
"""
IP whitelisting for sensitive endpoints
"""

from fastapi import Request, HTTPException
from typing import List, Set
import ipaddress


class IPWhitelist:
    """IP-based access control"""
    
    def __init__(self):
        self.whitelisted_ips: Set[str] = set()
        self.whitelisted_ranges: List[ipaddress.IPv4Network] = []
        
        # Load from config/database
        self._load_whitelist()
    
    def _load_whitelist(self):
        """Load IP whitelist from configuration"""
        
        # Example: Load from environment or database
        whitelist = os.getenv('IP_WHITELIST', '').split(',')
        
        for entry in whitelist:
            entry = entry.strip()
            if not entry:
                continue
            
            try:
                # Check if it's a CIDR range
                if '/' in entry:
                    network = ipaddress.IPv4Network(entry)
                    self.whitelisted_ranges.append(network)
                else:
                    self.whitelisted_ips.add(entry)
            except ValueError:
                logger.warning(f"Invalid IP/range in whitelist: {entry}")
    
    def is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted"""
        
        # Check exact match
        if ip in self.whitelisted_ips:
            return True
        
        # Check IP ranges
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            
            for network in self.whitelisted_ranges:
                if ip_obj in network:
                    return True
        except ValueError:
            return False
        
        return False


# Middleware
ip_whitelist = IPWhitelist()


def require_whitelisted_ip(request: Request):
    """Dependency to require whitelisted IP"""
    
    client_ip = request.client.host
    
    # Check X-Forwarded-For header (when behind proxy)
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        client_ip = forwarded_for.split(',')[0].strip()
    
    if not ip_whitelist.is_whitelisted(client_ip):
        raise HTTPException(
            status_code=403,
            detail="Access denied: IP not whitelisted"
        )


# Usage in routes
@router.post("/admin/dangerous-action")
async def dangerous_action(
    request: Request,
    _: None = Depends(require_whitelisted_ip)  # IP check
):
    """Only accessible from whitelisted IPs"""
    pass
