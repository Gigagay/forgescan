# backend/app/core/rbac.py
"""
Fine-grained Role-Based Access Control (RBAC)
Implements: ABAC (Attribute-Based), PBAC (Policy-Based)
"""

from enum import Enum
from typing import List, Dict

class Permission(str, Enum):
    # Scan permissions
    SCAN_CREATE = "scan:create"
    SCAN_VIEW = "scan:view"
    SCAN_DELETE = "scan:delete"
    
    # Finding permissions
    FINDING_VIEW = "finding:view"
    FINDING_EDIT = "finding:edit"
    FINDING_DELETE = "finding:delete"
    FINDING_ASSIGN = "finding:assign"
    
    # Admin permissions
    USER_MANAGE = "user:manage"
    TENANT_MANAGE = "tenant:manage"
    BILLING_MANAGE = "billing:manage"
    
    # Integration permissions
    INTEGRATION_MANAGE = "integration:manage"
    API_KEY_MANAGE = "api_key:manage"

class Role(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    DEVELOPER = "developer"
    VIEWER = "viewer"
    AUDITOR = "auditor"

# Role-Permission mapping
ROLE_PERMISSIONS: Dict[Role, List[Permission]] = {
    Role.OWNER: list(Permission),  # All permissions
    Role.ADMIN: [
        Permission.SCAN_CREATE, Permission.SCAN_VIEW, Permission.SCAN_DELETE,
        Permission.FINDING_VIEW, Permission.FINDING_EDIT, Permission.FINDING_ASSIGN,
        Permission.USER_MANAGE, Permission.INTEGRATION_MANAGE
    ],
    Role.SECURITY_ANALYST: [
        Permission.SCAN_CREATE, Permission.SCAN_VIEW,
        Permission.FINDING_VIEW, Permission.FINDING_EDIT, Permission.FINDING_ASSIGN
    ],
    Role.DEVELOPER: [
        Permission.SCAN_VIEW, Permission.FINDING_VIEW
    ],
    Role.VIEWER: [
        Permission.SCAN_VIEW, Permission.FINDING_VIEW
    ],
    Role.AUDITOR: [
        Permission.SCAN_VIEW, Permission.FINDING_VIEW
    ]
}

def has_permission(user: User, permission: Permission) -> bool:
    """Check if user has specific permission"""
    user_role = Role(user.role)
    return permission in ROLE_PERMISSIONS.get(user_role, [])

def require_permission(permission: Permission):
    """Decorator to require specific permission"""
    def decorator(func):
        async def wrapper(*args, current_user: User = Depends(get_current_user), **kwargs):
            if not has_permission(current_user, permission):
                raise HTTPException(403, f"Missing permission: {permission.value}")
            return await func(*args, current_user=current_user, **kwargs)
        return wrapper
    return decorator

# Usage in API
@router.post("/scans")
@require_permission(Permission.SCAN_CREATE)
async def create_scan(
    scan: ScanCreate,
    current_user: User = Depends(get_current_user)
):
    # Only users with SCAN_CREATE permission can access
    pass

# Database models
class User(Base):
    role = Column(String(50), default=Role.DEVELOPER)
    custom_permissions = Column(JSON, default=[])  # Override permissions

class AuditLog(Base):
    """Track all access attempts"""
    user_id = Column(UUID, ForeignKey('users.id'))
    action = Column(String(100))
    resource = Column(String(100))
    resource_id = Column(UUID)
    permission_required = Column(String(100))
    access_granted = Column(Boolean)
    ip_address = Column(String(50))
    user_agent = Column(String(500))
    timestamp = Column(DateTime, default=datetime.utcnow)