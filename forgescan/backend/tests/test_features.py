# tests/test_features.py
"""
Feature-specific tests
Tests: Scheduled scans, assignments, profiles, reports
"""

import pytest

class TestScheduledScans:
    """Test scheduled scan feature"""
    
    @pytest.mark.asyncio
    async def test_create_scheduled_scan(self, client, auth_headers):
        """Test creating a scheduled scan"""
        
        response = client.post("/api/v1/scheduled-scans",
            headers=auth_headers,
            json={
                "name": "Daily Security Scan",
                "scanner_type": "web",
                "target": "https://example.com",
                "schedule": "0 2 * * *",  # Daily at 2 AM
                "timezone": "Africa/Johannesburg"
            }
        )
        
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Daily Security Scan"
        assert data["schedule"] == "0 2 * * *"
    
    @pytest.mark.asyncio
    async def test_invalid_cron_rejected(self, client, auth_headers):
        """Test invalid cron expression is rejected"""
        
        response = client.post("/api/v1/scheduled-scans",
            headers=auth_headers,
            json={
                "name": "Test Scan",
                "scanner_type": "web",
                "target": "https://example.com",
                "schedule": "invalid cron"
            }
        )
        
        assert response.status_code == 400
    
    @pytest.mark.asyncio
    async def test_scheduled_scan_execution(self, db_session):
        """Test scheduled scan is executed"""
        
        from app.workers.scheduled_tasks import check_scheduled_scans
        from app.db.models.scheduled_scan import ScheduledScan
        
        # Create overdue scheduled scan
        scheduled_scan = ScheduledScan(
            tenant_id="test-tenant",
            name="Test Scan",
            scanner_type="web",
            target="https://example.com",
            schedule="0 * * * *",
            next_run=datetime.utcnow() - timedelta(minutes=5),  # Overdue
            enabled=True
        )
        
        db_session.add(scheduled_scan)
        await db_session.commit()
        
        # Run scheduled task
        await check_scheduled_scans()
        
        # Verify scan was triggered
        await db_session.refresh(scheduled_scan)
        assert scheduled_scan.last_run is not None


class TestAssignmentSystem:
    """Test finding assignment feature"""
    
    @pytest.mark.asyncio
    async def test_assign_finding(self, client, auth_headers, test_user, db_session):
        """Test assigning finding to team member"""
        
        # Create finding
        from app.db.models.finding import Finding
        finding = Finding(
            tenant_id=test_user.tenant_id,
            scan_id=uuid4(),
            title="Test Vulnerability",
            severity="high",
            category="xss"
        )
        db_session.add(finding)
        await db_session.commit()
        
        # Assign it
        response = client.post("/api/v1/assignments",
            headers=auth_headers,
            json={
                "finding_id": str(finding.id),
                "assigned_to": str(test_user.id),
                "due_date": (datetime.utcnow() + timedelta(days=7)).isoformat(),
                "priority": "high"
            }
        )
        
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "assigned"
    
    @pytest.mark.asyncio
    async def test_get_my_assignments(self, client, auth_headers):
        """Test retrieving user's assignments"""
        
        response = client.get("/api/v1/assignments/me", headers=auth_headers)
        
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    
    @pytest.mark.asyncio
    async def test_update_assignment_status(self, client, auth_headers, db_session, test_user):
        """Test updating assignment status"""
        
        # Create assignment
        from app.db.models.finding_assignment import FindingAssignment
        from app.db.models.finding import Finding
        
        finding = Finding(
            tenant_id=test_user.tenant_id,
            scan_id=uuid4(),
            title="Test",
            severity="high"
        )
        db_session.add(finding)
        await db_session.commit()
        
        assignment = FindingAssignment(
            finding_id=finding.id,
            assigned_to=test_user.id,
            assigned_by=test_user.id,
            status="assigned"
        )
        db_session.add(assignment)
        await db_session.commit()
        
        # Update status
        response = client.patch(f"/api/v1/assignments/{assignment.id}",
            headers=auth_headers,
            json={"status": "in_progress"}
        )
        
        assert response.status_code == 200
        
        # Verify status changed
        await db_session.refresh(assignment)
        assert assignment.status == "in_progress"


class TestScanProfiles:
    """Test custom scan profiles"""
    
    @pytest.mark.asyncio
    async def test_create_scan_profile(self, client, auth_headers):
        """Test creating custom scan profile"""
        
        response = client.post("/api/v1/profiles",
            headers=auth_headers,
            json={
                "name": "Quick Scan",
                "scanner_type": "web",
                "description": "Fast scan for CI/CD",
                "options": {
                    "depth": 1,
                    "timeout": 60,
                    "check_ssl": False
                }
            }
        )
        
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Quick Scan"
    
    @pytest.mark.asyncio
    async def test_use_scan_profile(self, client, auth_headers, db_session, test_user):
        """Test using a scan profile"""
        
        from app.db.models.scan_profile import ScanProfile
        
        # Create profile
        profile = ScanProfile(
            tenant_id=test_user.tenant_id,
            name="Test Profile",
            scanner_type="web",
            options={"depth": 2}
        )
        db_session.add(profile)
        await db_session.commit()
        
        # Use profile in scan
        response = client.post("/api/v1/scans",
            headers=auth_headers,
            json={
                "scanner_type": "web",
                "target": "https://example.com",
                "profile_id": str(profile.id)
            }
        )
        
        assert response.status_code == 201
        # Verify profile options were applied
        scan = response.json()
        assert scan["options"]["depth"] == 2


class TestReportGeneration:
    """Test PDF report generation"""
    
    @pytest.mark.asyncio
    async def test_generate_pdf_report(self, client, auth_headers, db_session, test_user):
        """Test generating PDF report"""
        
        # Create scan with findings
        from app.db.models.scan import Scan
        from app.db.models.finding import Finding
        
        scan = Scan(
            tenant_id=test_user.tenant_id,
            scanner_type="web",
            target="https://example.com",
            status="completed"
        )
        db_session.add(scan)
        await db_session.commit()
        
        finding = Finding(
            tenant_id=test_user.tenant_id,
            scan_id=scan.id,
            title="XSS Vulnerability",
            severity="high",
            category="xss"
        )
        db_session.add(finding)
        await db_session.commit()
        
        # Generate report
        response = client.get(f"/api/v1/scans/{scan.id}/report/pdf",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert len(response.content) > 0

