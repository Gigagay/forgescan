# backend/app/core/gdpr.py
"""
GDPR Compliance Implementation
Handles: Right to access, erasure, portability, rectification
"""

from datetime import datetime, timedelta
from typing import Dict, List
import json

class GDPRService:
    """GDPR compliance service"""
    
    async def export_user_data(self, user_id: UUID) -> Dict:
        """
        Right to Data Portability (Article 20)
        Export all user data in machine-readable format
        """
        
        async with get_db() as db:
            user = await db.get(User, user_id)
            
            # Collect all user data
            user_data = {
                "personal_information": {
                    "email": user.email,
                    "full_name": user.full_name,
                    "created_at": user.created_at.isoformat(),
                    "last_login": user.last_login.isoformat() if user.last_login else None,
                },
                "scans": await self._get_user_scans(user_id, db),
                "findings": await self._get_user_findings(user_id, db),
                "audit_logs": await self._get_user_audit_logs(user_id, db),
                "subscription": await self._get_subscription_info(user_id, db),
            }
            
            # Log the export
            await AuditLogger().log_event(
                event_type=AuditEventType.DATA_EXPORTED,
                user_id=user_id,
                tenant_id=user.tenant_id,
                details={"export_size_bytes": len(json.dumps(user_data))}
            )
            
            return user_data
    
    async def delete_user_data(self, user_id: UUID, reason: str = "user_request"):
        """
        Right to Erasure / Right to be Forgotten (Article 17)
        Permanently delete all user data
        """
        
        async with get_db() as db:
            user = await db.get(User, user_id)
            
            # Log deletion before it happens
            await AuditLogger().log_event(
                event_type=AuditEventType.DATA_DELETED,
                user_id=user_id,
                tenant_id=user.tenant_id,
                details={
                    "reason": reason,
                    "requested_by": user_id,
                    "deletion_type": "full"
                }
            )
            
            # Delete associated data
            await self._delete_user_scans(user_id, db)
            await self._delete_user_findings(user_id, db)
            await self._delete_user_assignments(user_id, db)
            
            # Anonymize audit logs (can't delete for compliance)
            await self._anonymize_audit_logs(user_id, db)
            
            # Finally delete user record
            await db.delete(user)
            await db.commit()
    
    async def anonymize_user_data(self, user_id: UUID):
        """
        Anonymize user data instead of deletion
        Used when deletion would break referential integrity
        """
        
        async with get_db() as db:
            user = await db.get(User, user_id)
            
            # Anonymize PII
            user.email = f"anonymized_{uuid.uuid4()}@deleted.local"
            user.full_name = "Deleted User"
            user.phone = None
            user.address = None
            
            # Mark as anonymized
            user.anonymized_at = datetime.utcnow()
            user.anonymized_reason = "user_request"
            
            await db.commit()
    
    async def get_consent_status(self, user_id: UUID) -> Dict:
        """
        Track user consent for data processing
        Required under GDPR Article 7
        """
        
        async with get_db() as db:
            consents = await db.execute(
                select(UserConsent).where(UserConsent.user_id == user_id)
            )
            
            return {
                consent.consent_type: {
                    "given": consent.given,
                    "timestamp": consent.timestamp.isoformat(),
                    "withdrawn_at": consent.withdrawn_at.isoformat() if consent.withdrawn_at else None
                }
                for consent in consents.scalars().all()
            }
    
    async def record_consent(
        self,
        user_id: UUID,
        consent_type: str,
        given: bool,
        ip_address: str
    ):
        """Record user consent"""
        
        async with get_db() as db:
            consent = UserConsent(
                user_id=user_id,
                consent_type=consent_type,
                given=given,
                ip_address=ip_address,
                timestamp=datetime.utcnow()
            )
            
            db.add(consent)
            await db.commit()
    
    async def schedule_data_retention(self):
        """
        Automatically delete old data per retention policy
        GDPR Article 5(1)(e) - Storage Limitation
        """
        
        retention_periods = {
            'audit_logs': 365,        # 1 year
            'scan_results': 90,       # 90 days
            'temp_files': 7,          # 7 days
            'deleted_users': 30,      # 30 days grace period
        }
        
        async with get_db() as db:
            for data_type, days in retention_periods.items():
                cutoff_date = datetime.utcnow() - timedelta(days=days)
                
                if data_type == 'audit_logs':
                    # Anonymize old audit logs
                    await db.execute(
                        update(AuditLog)
                        .where(AuditLog.timestamp < cutoff_date)
                        .values(
                            user_id=None,
                            ip_address="0.0.0.0",
                            user_agent="anonymized"
                        )
                    )
                
                elif data_type == 'scan_results':
                    # Delete old scan results
                    await db.execute(
                        delete(Scan)
                        .where(
                            and_(
                                Scan.created_at < cutoff_date,
                                Scan.archived == False
                            )
                        )
                    )

# Database models
class UserConsent(Base):
    """Track user consent for GDPR compliance"""
    __tablename__ = "user_consents"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID, ForeignKey('users.id'))
    
    consent_type = Column(String(100))  # marketing, analytics, data_processing
    given = Column(Boolean, default=False)
    
    ip_address = Column(String(50))
    timestamp = Column(DateTime, default=datetime.utcnow)
    withdrawn_at = Column(DateTime)

class DataProcessingRecord(Base):
    """Record of processing activities (GDPR Article 30)"""
    __tablename__ = "data_processing_records"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    processing_activity = Column(String(255))
    purpose = Column(Text)
    legal_basis = Column(String(100))  # consent, contract, legitimate_interest
    data_categories = Column(JSON)
    recipients = Column(JSON)
    retention_period = Column(String(100))
    security_measures = Column(Text)
    
    created_at = Column(DateTime, default=datetime.utcnow)

# API endpoints
@router.get("/gdpr/export")
async def export_my_data(current_user: User = Depends(get_current_user)):
    """Export all user data (GDPR Article 20)"""
    
    gdpr = GDPRService()
    data = await gdpr.export_user_data(current_user.id)
    
    return Response(
        content=json.dumps(data, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=my_data_{datetime.utcnow().strftime('%Y%m%d')}.json"
        }
    )

@router.delete("/gdpr/delete-account")
async def delete_my_account(
    confirmation: str,
    current_user: User = Depends(get_current_user)
):
    """Delete user account and all data (GDPR Article 17)"""
    
    if confirmation != "DELETE MY ACCOUNT":
        raise HTTPException(400, "Invalid confirmation")
    
    gdpr = GDPRService()
    await gdpr.delete_user_data(current_user.id, reason="user_request")
    
    return {"message": "Account deletion scheduled. All data will be permanently deleted within 30 days."}