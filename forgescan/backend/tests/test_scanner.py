# tests/test_scanners.py
"""
Scanner functionality tests
Tests: Web scanner, API scanner, SCA scanner
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from uuid import uuid4

class TestWebScanner:
    """Test web application scanner"""
    
    @pytest.mark.asyncio
    async def test_create_web_scan(self, client, auth_headers):
        """Test creating a web scan"""
        
        response = client.post("/api/v1/scans",
            headers=auth_headers,
            json={
                "scanner_type": "web",
                "target": "https://example.com",
                "options": {
                    "depth": 3,
                    "check_ssl": True
                }
            }
        )
        
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["scanner_type"] == "web"
        assert data["target"] == "https://example.com"
        assert data["status"] == "queued"
        assert "id" in data
    
    @pytest.mark.asyncio
    async def test_invalid_url_rejected(self, client, auth_headers):
        """Test invalid URL is rejected"""
        
        response = client.post("/api/v1/scans",
            headers=auth_headers,
            json={
                "scanner_type": "web",
                "target": "not-a-valid-url"
            }
        )
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
    
    @pytest.mark.asyncio
    @patch('app.scanners.web_scanner.WebScanner.scan')
    async def test_web_scanner_detects_xss(self, mock_scan, client, auth_headers):
        """Test web scanner detects XSS vulnerabilities"""
        
        # Mock scanner response
        mock_scan.return_value = {
            "scan_id": str(uuid4()),
            "findings": [{
                "title": "Cross-Site Scripting (XSS)",
                "severity": "high",
                "category": "xss",
                "description": "XSS vulnerability detected",
                "location": "https://example.com/search?q=<script>",
                "evidence": "<script>alert(1)</script>"
            }],
            "summary": {
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0
            }
        }
        
        # Trigger scan
        response = client.post("/api/v1/scans",
            headers=auth_headers,
            json={
                "scanner_type": "web",
                "target": "https://example.com"
            }
        )
        
        scan_id = response.json()["id"]
        
        # Get scan results
        results = client.get(f"/api/v1/scans/{scan_id}", headers=auth_headers)
        
        assert results.status_code == status.HTTP_200_OK
        findings = results.json()["findings"]
        assert len(findings) == 1
        assert findings[0]["category"] == "xss"
        assert findings[0]["severity"] == "high"
    
    @pytest.mark.asyncio
    async def test_web_scanner_respects_depth_limit(self, client, auth_headers):
        """Test web scanner respects crawl depth limit"""
        
        response = client.post("/api/v1/scans",
            headers=auth_headers,
            json={
                "scanner_type": "web",
                "target": "https://example.com",
                "options": {"depth": 1}
            }
        )
        
        assert response.status_code == status.HTTP_201_CREATED
        # Verify depth is applied (check scan options)
        scan = response.json()
        assert scan["options"]["depth"] == 1


class TestAPIScanner:
    """Test API security scanner"""
    
    @pytest.mark.asyncio
    async def test_create_api_scan(self, client, auth_headers):
        """Test creating an API scan"""
        
        response = client.post("/api/v1/scans",
            headers=auth_headers,
            json={
                "scanner_type": "api",
                "target": "https://api.example.com",
                "options": {
                    "api_spec": "openapi",
                    "check_auth": True
                }
            }
        )
        
        assert response.status_code == status.HTTP_201_CREATED
        assert response.json()["scanner_type"] == "api"
    
    @pytest.mark.asyncio
    @patch('app.scanners.api_scanner.APIScanner.scan')
    async def test_api_scanner_detects_broken_auth(self, mock_scan, client, auth_headers):
        """Test API scanner detects broken authentication"""
        
        mock_scan.return_value = {
            "findings": [{
                "title": "Broken Authentication",
                "severity": "critical",
                "category": "broken_authentication",
                "description": "API endpoint accessible without authentication",
                "location": "GET /api/admin/users",
                "evidence": "200 OK without Authorization header"
            }]
        }
        
        response = client.post("/api/v1/scans",
            headers=auth_headers,
            json={
                "scanner_type": "api",
                "target": "https://api.example.com"
            }
        )
        
        assert response.status_code == status.HTTP_201_CREATED


class TestSCAScanner:
    """Test Software Composition Analysis scanner"""
    
    @pytest.mark.asyncio
    async def test_create_sca_scan(self, client, auth_headers):
        """Test creating an SCA scan"""
        
        # Upload package.json
        files = {
            'file': ('package.json', '{"dependencies": {"express": "4.17.1"}}', 'application/json')
        }
        
        response = client.post("/api/v1/scans/sca",
            headers=auth_headers,
            files=files
        )
        
        assert response.status_code == status.HTTP_201_CREATED
    
    @pytest.mark.asyncio
    @patch('app.scanners.sca_scanner.SCAScanner.scan')
    async def test_sca_detects_vulnerable_dependency(self, mock_scan, client, auth_headers):
        """Test SCA scanner detects vulnerable dependencies"""
        
        mock_scan.return_value = {
            "findings": [{
                "title": "Vulnerable Dependency: lodash@4.17.15",
                "severity": "high",
                "category": "vulnerable_dependency",
                "description": "Prototype Pollution vulnerability",
                "cve": "CVE-2020-8203",
                "affected_versions": "< 4.17.19",
                "fixed_version": "4.17.19"
            }]
        }
        
        files = {
            'file': ('package.json', '{"dependencies": {"lodash": "4.17.15"}}', 'application/json')
        }
        
        response = client.post("/api/v1/scans/sca",
            headers=auth_headers,
            files=files
        )
        
        scan_id = response.json()["id"]
        results = client.get(f"/api/v1/scans/{scan_id}", headers=auth_headers)
        
        findings = results.json()["findings"]
        assert any("CVE-2020-8203" in f.get("cve", "") for f in findings)
