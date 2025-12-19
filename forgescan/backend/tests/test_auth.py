# tests/test_auth.py
"""
Authentication and authorization tests
Tests: Registration, login, JWT, MFA, SSO, permissions
"""

import pytest
from fastapi import status
from datetime import datetime, timedelta

class TestAuthentication:
    """Test authentication flows"""
    
    @pytest.mark.asyncio
    async def test_user_registration(self, client, db_session):
        """Test user registration with valid data"""
        
        response = client.post("/api/v1/auth/register", json={
            "email": "newuser@example.com",
            "password": "SecurePassword123!",
            "full_name": "New User",
            "company_name": "Test Company"
        })
        
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["email"] == "newuser@example.com"
        assert "id" in data
        assert "access_token" in data
    
    @pytest.mark.asyncio
    async def test_duplicate_email_registration(self, client, test_user):
        """Test registration with existing email fails"""
        
        response = client.post("/api/v1/auth/register", json={
            "email": test_user.email,
            "password": "SecurePassword123!",
            "full_name": "Duplicate User"
        })
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "already exists" in response.json()["detail"].lower()
    
    @pytest.mark.asyncio
    async def test_weak_password_rejected(self, client):
        """Test weak password is rejected"""
        
        response = client.post("/api/v1/auth/register", json={
            "email": "user@example.com",
            "password": "weak",  # Too weak
            "full_name": "Test User"
        })
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "password" in response.json()["detail"].lower()
    
    @pytest.mark.asyncio
    async def test_login_success(self, client, test_user):
        """Test successful login"""
        
        response = client.post("/api/v1/auth/login", json={
            "email": test_user.email,
            "password": "TestPassword123!"
        })
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
    
    @pytest.mark.asyncio
    async def test_login_wrong_password(self, client, test_user):
        """Test login with wrong password"""
        
        response = client.post("/api/v1/auth/login", json={
            "email": test_user.email,
            "password": "WrongPassword123!"
        })
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.asyncio
    async def test_login_nonexistent_user(self, client):
        """Test login with nonexistent user"""
        
        response = client.post("/api/v1/auth/login", json={
            "email": "nonexistent@example.com",
            "password": "Password123!"
        })
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.asyncio
    async def test_token_refresh(self, client, test_user, auth_headers):
        """Test refresh token flow"""
        
        # Login to get refresh token
        login_response = client.post("/api/v1/auth/login", json={
            "email": test_user.email,
            "password": "TestPassword123!"
        })
        
        refresh_token = login_response.json()["refresh_token"]
        
        # Use refresh token
        response = client.post("/api/v1/auth/refresh", json={
            "refresh_token": refresh_token
        })
        
        assert response.status_code == status.HTTP_200_OK
        assert "access_token" in response.json()
    
    @pytest.mark.asyncio
    async def test_logout(self, client, auth_headers):
        """Test logout invalidates token"""
        
        response = client.post("/api/v1/auth/logout", headers=auth_headers)
        
        assert response.status_code == status.HTTP_200_OK
        
        # Try to use token after logout
        response = client.get("/api/v1/users/me", headers=auth_headers)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.asyncio
    async def test_password_reset_request(self, client, test_user):
        """Test password reset email is sent"""
        
        response = client.post("/api/v1/auth/password-reset", json={
            "email": test_user.email
        })
        
        assert response.status_code == status.HTTP_200_OK
        assert "email sent" in response.json()["message"].lower()
    
    @pytest.mark.asyncio
    async def test_password_reset_confirm(self, client, test_user, db_session):
        """Test password reset with valid token"""
        
        # Generate reset token
        reset_token = create_access_token(
            data={"sub": test_user.email, "type": "password_reset"},
            expires_delta=timedelta(hours=1)
        )
        
        response = client.post("/api/v1/auth/password-reset/confirm", json={
            "token": reset_token,
            "new_password": "NewPassword123!"
        })
        
        assert response.status_code == status.HTTP_200_OK
        
        # Try login with new password
        login_response = client.post("/api/v1/auth/login", json={
            "email": test_user.email,
            "password": "NewPassword123!"
        })
        
        assert login_response.status_code == status.HTTP_200_OK


class TestMultiFactorAuthentication:
    """Test MFA functionality"""
    
    @pytest.mark.asyncio
    async def test_mfa_setup(self, client, auth_headers):
        """Test MFA setup generates QR code"""
        
        response = client.post("/api/v1/auth/mfa/setup", headers=auth_headers)
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "qr_code" in data
        assert "backup_codes" in data
        assert len(data["backup_codes"]) == 10
    
    @pytest.mark.asyncio
    async def test_mfa_enable(self, client, auth_headers, test_user):
        """Test enabling MFA with valid token"""
        
        # Setup MFA first
        setup_response = client.post("/api/v1/auth/mfa/setup", headers=auth_headers)
        
        # Generate valid TOTP token (mocked)
        import pyotp
        secret = setup_response.json()["secret"]
        totp = pyotp.TOTP(secret)
        token = totp.now()
        
        response = client.post("/api/v1/auth/mfa/enable", 
            headers=auth_headers,
            json={"token": token}
        )
        
        assert response.status_code == status.HTTP_200_OK
    
    @pytest.mark.asyncio
    async def test_login_with_mfa(self, client, test_user):
        """Test login requires MFA token when enabled"""
        
        # Enable MFA for user
        test_user.mfa_enabled = True
        
        response = client.post("/api/v1/auth/login", json={
            "email": test_user.email,
            "password": "TestPassword123!"
        })
        
        assert response.status_code == status.HTTP_200_OK
        assert "mfa_required" in response.json()
        assert response.json()["mfa_required"] == True


class TestRoleBasedAccessControl:
    """Test RBAC permissions"""
    
    @pytest.mark.asyncio
    async def test_admin_can_create_user(self, client, auth_headers):
        """Test admin can create new users"""
        
        response = client.post("/api/v1/users", 
            headers=auth_headers,
            json={
                "email": "newteammember@example.com",
                "full_name": "New Team Member",
                "role": "developer"
            }
        )
        
        assert response.status_code == status.HTTP_201_CREATED
    
    @pytest.mark.asyncio
    async def test_developer_cannot_create_user(self, client, test_user, db_session):
        """Test developer role cannot create users"""
        
        # Change user role to developer
        test_user.role = "developer"
        await db_session.commit()
        
        # Generate token for developer
        token = create_access_token(data={"sub": test_user.email})
        headers = {"Authorization": f"Bearer {token}"}
        
        response = client.post("/api/v1/users",
            headers=headers,
            json={
                "email": "newuser@example.com",
                "full_name": "New User",
                "role": "developer"
            }
        )
        
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    @pytest.mark.asyncio
    async def test_viewer_cannot_delete_scan(self, client, test_user, db_session):
        """Test viewer role cannot delete scans"""
        
        test_user.role = "viewer"
        await db_session.commit()
        
        token = create_access_token(data={"sub": test_user.email})
        headers = {"Authorization": f"Bearer {token}"}
        
        response = client.delete("/api/v1/scans/some-scan-id", headers=headers)
        
        assert response.status_code == status.HTTP_403_FORBIDDEN

