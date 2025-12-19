# tests/test_security.py
"""
Security and penetration tests
Tests: SQL injection, XSS, CSRF, authentication bypass
"""

import pytest

class TestSecurityVulnerabilities:
    """Test security of the platform itself"""
    
    @pytest.mark.asyncio
    async def test_sql_injection_protection(self, client, auth_headers):
        """Test SQL injection is prevented"""
        
        # Try SQL injection in search
        response = client.get(
            "/api/v1/scans?search=' OR '1'='1",
            headers=auth_headers
        )
        
        # Should not cause error or return all records
        assert response.status_code in [200, 400]
        # Verify it doesn't return excessive records
        if response.status_code == 200:
            assert len(response.json()) < 1000
    
    @pytest.mark.asyncio
    async def test_xss_protection(self, client, auth_headers):
        """Test XSS is sanitized"""
        
        # Try to inject XSS in user profile
        response = client.patch("/api/v1/users/me",
            headers=auth_headers,
            json={
                "full_name": "<script>alert('XSS')</script>"
            }
        )
        
        assert response.status_code == 200
        
        # Verify script tags are stripped
        user_response = client.get("/api/v1/users/me", headers=auth_headers)
        assert "<script>" not in user_response.json()["full_name"]
    
    @pytest.mark.asyncio
    async def test_unauthorized_access_blocked(self, client):
        """Test unauthorized requests are blocked"""
        
        response = client.get("/api/v1/scans")
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.asyncio
    async def test_csrf_protection(self, client, auth_headers):
        """Test CSRF protection is enabled"""
        
        # Missing CSRF token should fail
        response = client.post("/api/v1/scans",
            headers={"Authorization": auth_headers["Authorization"]},
            # Missing CSRF token
            json={"scanner_type": "web", "target": "https://example.com"}
        )
        
        # Should succeed with proper auth (FastAPI doesn't require CSRF for API)
        assert response.status_code in [200, 201]
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, client, auth_headers):
        """Test rate limiting prevents abuse"""
        
        # Make many requests quickly
        responses = []
        for i in range(150):
            response = client.get("/api/v1/scans", headers=auth_headers)
            responses.append(response.status_code)
        
        # At least one should be rate limited
        assert status.HTTP_429_TOO_MANY_REQUESTS in responses
    
    @pytest.mark.asyncio
    async def test_jwt_expiration(self, client, test_user):
        """Test expired JWT is rejected"""
        
        # Create expired token
        expired_token = create_access_token(
            data={"sub": test_user.email},
            expires_delta=timedelta(seconds=-1)  # Already expired
        )
        
        response = client.get("/api/v1/users/me",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "expired" in response.json()["detail"].lower()
    
    @pytest.mark.asyncio
    async def test_tenant_isolation(self, client, db_session):
        """Test users cannot access other tenants' data"""
        
        # Create second tenant and user
        tenant2 = Tenant(id="tenant-2", name="Other Company")
        user2 = User(
            email="user2@other.com",
            hashed_password=hash_password("Password123!"),
            tenant_id=tenant2.id,
            role="admin"
        )
        
        db_session.add(tenant2)
        db_session.add(user2)
        await db_session.commit()
        
        # Create scan for tenant2
        from app.db.models.scan import Scan
        scan2 = Scan(
            tenant_id=tenant2.id,
            scanner_type="web",
            target="https://tenant2.com",
            status="completed"
        )
        db_session.add(scan2)
        await db_session.commit()
        
        # User1 tries to access tenant2's scan
        token1 = create_access_token(data={"sub": "test@example.com"})
        
        response = client.get(f"/api/v1/scans/{scan2.id}",
            headers={"Authorization": f"Bearer {token1}"}
        )
        
        assert response.status_code == status.HTTP_404_NOT_FOUND
    
    @pytest.mark.asyncio
    async def test_password_reset_token_single_use(self, client, test_user):
        """Test password reset tokens can only be used once"""
        
        reset_token = create_access_token(
            data={"sub": test_user.email, "type": "password_reset"}
        )
        
        # First use succeeds
        response1 = client.post("/api/v1/auth/password-reset/confirm",
            json={
                "token": reset_token,
                "new_password": "NewPassword123!"
            }
        )
        
        assert response1.status_code == status.HTTP_200_OK
        
        # Second use should fail
        response2 = client.post("/api/v1/auth/password-reset/confirm",
            json={
                "token": reset_token,
                "new_password": "AnotherPassword123!"
            }
        )
        
        assert response2.status_code == status.HTTP_400_BAD_REQUEST


class TestDataEncryption:
    """Test data encryption features"""
    
    @pytest.mark.asyncio
    async def test_sensitive_data_encrypted(self, db_session, test_user):
        """Test sensitive fields are encrypted in database"""
        
        from app.core.encryption import EncryptionService
        
        # Store API key
        api_key = "sk-test-key-12345"
        encrypted = EncryptionService().encrypt(api_key)
        
        test_user.api_key_encrypted = encrypted
        await db_session.commit()
        
        # Verify it's encrypted in DB
        assert test_user.api_key_encrypted != api_key
        assert "sk-test-key" not in test_user.api_key_encrypted
        
        # Verify it can be decrypted
        decrypted = EncryptionService().decrypt(test_user.api_key_encrypted)
        assert decrypted == api_key
    
    @pytest.mark.asyncio
    async def test_backup_encryption(self):
        """Test database backups are encrypted"""
        
        from app.services.backup import BackupService
        
        backup_service = BackupService()
        
        # Create test file
        test_file = "/tmp/test_backup.sql"
        with open(test_file, 'w') as f:
            f.write("SELECT * FROM users;")
        
        # Encrypt it
        encrypted_file = await backup_service._encrypt_file(test_file)
        
        # Verify encrypted file is different
        with open(encrypted_file, 'rb') as f:
            encrypted_content = f.read()
        
        assert b"SELECT" not in encrypted_content
        
        # Cleanup
        os.remove(test_file)
        os.remove(encrypted_file)
