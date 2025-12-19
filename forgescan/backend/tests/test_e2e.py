# tests/test_e2e.py
"""
End-to-end user journey tests
Tests: Complete user workflows from start to finish
"""

import pytest

class TestUserJourneys:
    """Test complete user journeys"""
    
    @pytest.mark.e2e
    @pytest.mark.asyncio
    async def test_new_user_onboarding(self, client, db_session):
        """Test complete new user onboarding flow"""
        
        # 1. Register
        register_response = client.post("/api/v1/auth/register",
            json={
                "email": "newuser@startup.com",
                "password": "SecurePass123!",
                "full_name": "New User",
                "company_name": "Startup Inc"
            }
        )
        
        assert register_response.status_code == 201
        access_token = register_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {access_token}"}
        
        # 2. Verify email (simulated)
        # In real test, would check email service
        
        # 3. Create first scan
        scan_response = client.post("/api/v1/scans",
            headers=headers,
            json={
                "scanner_type": "web",
                "target": "https://mystartup.com"
            }
        )
        
        assert scan_response.status_code == 201
        scan_id = scan_response.json()["id"]
        
        # 4. Wait for scan completion
        # (In real test, would poll until completed)
        
        # 5. View results
        results_response = client.get(f"/api/v1/scans/{scan_id}",
            headers=headers
        )
        
        assert results_response.status_code == 200
        
        # 6. Upgrade to paid plan
        subscription_response = client.post("/api/v1/subscriptions",
            headers=headers,
            json={
                "plan": "developer",
                "currency": "USD"
            }
        )
        
        assert subscription_response.status_code == 201
    
    @pytest.mark.e2e
    @pytest.mark.asyncio
    async def test_team_collaboration_workflow(self, client, db_session):
        """Test team collaboration workflow"""
        
        # 1. Admin creates team
        admin_token = create_access_token(data={"sub": "admin@company.com"})
        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        
        # 2. Admin invites team member
        invite_response = client.post("/api/v1/users",
            headers=admin_headers,
            json={
                "email": "developer@company.com",
                "full_name": "Team Developer",
                "role": "developer"
            }
        )
        
        assert invite_response.status_code == 201
        
        # 3. Team member accepts and logs in
        dev_token = create_access_token(data={"sub": "developer@company.com"})
        dev_headers = {"Authorization": f"Bearer {dev_token}"}
        
        # 4. Admin runs scan
        scan_response = client.post("/api/v1/scans",
            headers=admin_headers,
            json={
                "scanner_type": "web",
                "target": "https://company.com"
            }
        )
        
        scan_id = scan_response.json()["id"]
        
        # 5. Admin assigns finding to developer
        # (Assuming finding was created)
        
        # 6. Developer views assigned findings
        assignments_response = client.get("/api/v1/assignments/me",
            headers=dev_headers
        )
        
        assert assignments_response.status_code == 200
    
    @pytest.mark.e2e
    @pytest.mark.asyncio
    async def test_ci_cd_integration_workflow(self, client):
        """Test CI/CD integration workflow"""
        
        # 1. Setup GitHub integration
        setup_response = client.post("/api/v1/integrations/github/setup",
            json={
                "repo_full_name": "company/app",
                "github_token": "ghp_test_token",
                "scanner_types": ["web", "sca"],
                "fail_on_severity": ["critical", "high"]
            }
        )
        
        assert setup_response.status_code == 200
        webhook_url = setup_response.json()["webhook_url"]
        
        # 2. Simulate PR webhook
        pr_payload = {
            "action": "opened",
            "pull_request": {
                "number": 42,
                "html_url": "https://github.com/company/app/pull/42",
                "head": {"ref": "feature-branch", "sha": "abc123"}
            },
            "repository": {"full_name": "company/app"}
        }
        
        webhook_response = client.post("/api/v1/integrations/github/webhook",
            json=pr_payload,
            headers={"X-GitHub-Event": "pull_request"}
        )
        
        assert webhook_response.status_code == 200
        
        # 3. Verify scan was triggered
        # 4. Verify PR comment was posted
        # (Would verify with mock GitHub API)
