# tests/test_compliance.py
"""
Compliance and regulatory tests
Tests: GDPR, SOC2, audit logging, data retention
"""

import pytest
from datetime import datetime, timedelta

class TestGDPRCompliance:
    """Test GDPR compliance features"""
    
    @pytest.mark.asyncio
    async def test_data_export(self, client, auth_headers, test_user):
        """Test user can export their data (GDPR Article 20)"""
        
        response = client.get("/api/v1/gdpr/export", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify all user data is included
        assert "personal_information" in data
        assert "scans" in data
        assert "findings" in data
        assert data["personal_information"]["email"] == test_user.email
    
    @pytest.mark.asyncio
    async def test_account_deletion(self, client, auth_headers, test_user, db_session):
        """Test user can delete their account (GDPR Article 17)"""
        
        response = client.delete("/api/v1/gdpr/delete-account",
            headers=auth_headers,
            json={"confirmation": "DELETE MY ACCOUNT"}
        )
        
        assert response.status_code == 200
        
        # Verify user is marked for deletion
        await db_session.refresh(test_user)
        assert test_user.deletion_scheduled_at is not None
    
    @pytest.mark.asyncio
    async def test_consent_tracking(self, client, auth_headers):
        """Test consent is properly tracked"""
        
        # Record consent
        response = client.post("/api/v1/gdpr/consent",
            headers=auth_headers,
            json={
                "consent_type": "marketing",
                "given": True
            }
        )
        
        assert response.status_code == 200
        
        # Retrieve consent
        consent_response = client.get("/api/v1/gdpr/consent", headers=auth_headers)
        
        consents = consent_response.json()
        assert "marketing" in consents
        assert consents["marketing"]["given"] == True
    
    @pytest.mark.asyncio
    async def test_data_retention_policy(self, db_session):
        """Test old data is automatically deleted"""
        
        from app.core.gdpr import GDPRService
        
        # Create old scan (120 days ago)
        old_scan = Scan(
            tenant_id="test-tenant",
            scanner_type="web",
            target="https://example.com",
            status="completed",
            created_at=datetime.utcnow() - timedelta(days=120)
        )
        
        db_session.add(old_scan)
        await db_session.commit()
        
        # Run retention policy
        gdpr = GDPRService()
        await gdpr.schedule_data_retention()
        
        # Verify old scan was deleted
        scan = await db_session.get(Scan, old_scan.id)
        assert scan is None


class TestAuditLogging:
    """Test audit logging for compliance"""
    
    @pytest.mark.asyncio
    async def test_all_actions_logged(self, client, auth_headers, db_session):
        """Test all user actions are logged"""
        
        from app.db.models.audit_log import AuditLog
        
        # Perform action
        client.post("/api/v1/scans",
            headers=auth_headers,
            json={
                "scanner_type": "web",
                "target": "https://example.com"
            }
        )
        
        # Verify it was logged
        stmt = select(AuditLog).where(
            AuditLog.event_type == "scan.created"
        ).order_by(AuditLog.timestamp.desc())
        
        result = await db_session.execute(stmt)
        log = result.scalar_one_or_none()
        
        assert log is not None
        assert log.event_type == "scan.created"
        assert log.user_id is not None
    
    @pytest.mark.asyncio
    async def test_failed_login_logged(self, client, db_session):
        """Test failed login attempts are logged"""
        
        from app.db.models.audit_log import AuditLog
        
        # Failed login
        client.post("/api/v1/auth/login",
            json={
                "email": "test@example.com",
                "password": "WrongPassword!"
            }
        )
        
        # Verify it was logged
        stmt = select(AuditLog).where(
            AuditLog.event_type == "auth.login.failure"
        ).order_by(AuditLog.timestamp.desc())
        
        result = await db_session.execute(stmt)
        log = result.scalar_one_or_none()
        
        assert log is not None
        assert log.ip_address is not None
    
    @pytest.mark.asyncio
    async def test_audit_logs_immutable(self, db_session):
        """Test audit logs cannot be modified"""
        
        from app.db.models.audit_log import AuditLog
        
        log = AuditLog(
            event_type="test.event",
            user_id=uuid4(),
            tenant_id="test-tenant"
        )
        
        db_session.add(log)
        await db_session.commit()
        
        # Try to modify
        log.event_type = "modified.event"
        
        with pytest.raises(Exception):
            await db_session.commit()

