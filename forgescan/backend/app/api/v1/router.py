from fastapi import APIRouter
from app.api.v1 import auth, scans, users, tenants, findings, billing, websocket, remediation, enforcement, evidence, metrics

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(scans.router, prefix="/scans", tags=["scans"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(tenants.router, prefix="/tenants", tags=["tenants"])
api_router.include_router(findings.router, prefix="/findings", tags=["findings"])
api_router.include_router(billing.router, prefix="/billing", tags=["billing"])
api_router.include_router(remediation.router, tags=["remediation"])
api_router.include_router(enforcement.router, tags=["enforcement"])
api_router.include_router(evidence.router, tags=["evidence"])
api_router.include_router(metrics.router, tags=["metrics"])

