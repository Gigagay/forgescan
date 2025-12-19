# backend/app/scanners/api_scanner.py
import aiohttp
import json
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import asyncio

from app.scanners.base import BaseScannerPlugin, ScanResult, ScanStatus
from app.core.constants import SeverityLevel, OWASP_API_TOP_10
from app.core.logging import logger


class APIScanner(BaseScannerPlugin):
    """API security scanner"""
    
    name = "api_scanner"
    version = "1.0.0"
    description = "REST API security scanner"
    supported_protocols = ["http", "https"]
    
    def __init__(self):
        self.timeout = aiohttp.ClientTimeout(total=300)
        self.session: Optional[aiohttp.ClientSession] = None
        self.findings: List[Dict[str, Any]] = []
    
    async def initialize(self) -> None:
        """Initialize HTTP session"""
        self.session = aiohttp.ClientSession(timeout=self.timeout)
    
    async def cleanup(self) -> None:
        """Close HTTP session"""
        if self.session:
            await self.session.close()
    
    async def validate_target(self, target: str) -> bool:
        """Validate target URL"""
        try:
            parsed = urlparse(target)
            return parsed.scheme in self.supported_protocols and bool(parsed.netloc)
        except Exception:
            return False
    
    async def scan(
        self,
        target: str,
        scan_id: str,
        tenant_id: str,
        options: Optional[Dict[str, Any]] = None
    ) -> ScanResult:
        """Execute API security scan"""
        self.findings = []
        options = options or {}
        
        try:
            logger.info(f"Starting API scan for {target}", extra={"scan_id": scan_id})
            
            # Perform API-specific security checks
            await self._check_authentication(target, options)
            await self._check_authorization(target, options)
            await self._check_rate_limiting(target)
            await self._check_input_validation(target)
            await self._check_http_methods(target)
            await self._check_api_versioning(target)
            await self._check_error_handling(target)
            await self._check_data_exposure(target)
            
            # Calculate summary
            summary = self._calculate_summary()
            
            return ScanResult(
                status=ScanStatus.COMPLETED,
                findings=self.findings,
                summary=summary,
                metadata={
                    "target": target,
                    "total_requests": len(self.findings),
                    "scan_id": scan_id,
                }
            )
            
        except Exception as e:
            logger.error(f"API scan failed: {str(e)}", exc_info=True)
            return ScanResult(
                status=ScanStatus.FAILED,
                findings=self.findings,
                summary=self._calculate_summary(),
                metadata={"target": target},
                error=str(e)
            )
    
    async def _check_authentication(self, target: str, options: Dict[str, Any]):
        """Check authentication mechanisms"""
        # Test without authentication
        try:
            async with self.session.get(target) as response:
                if response.status == 200:
                    self.findings.append({
                        "title": "API Accessible Without Authentication",
                        "description": "API endpoint is accessible without any authentication",
                        "severity": SeverityLevel.HIGH,
                        "url": target,
                        "method": "GET",
                        "owasp_category": "API2:2023-Broken Authentication",
                        "cwe_id": "CWE-306",
                        "remediation": "Implement proper authentication mechanism (OAuth2, API keys, JWT)",
                        "references": ["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"]
                    })
        except Exception as e:
            logger.debug(f"Error checking authentication: {str(e)}")
        
        # Test weak authentication
        weak_tokens = ["test", "admin", "123456", "token"]
        for token in weak_tokens:
            try:
                headers = {"Authorization": f"Bearer {token}"}
                async with self.session.get(target, headers=headers) as response:
                    if response.status == 200:
                        self.findings.append({
                            "title": "Weak Authentication Token Accepted",
                            "description": f"API accepts weak/predictable authentication token: {token}",
                            "severity": SeverityLevel.CRITICAL,
                            "url": target,
                            "method": "GET",
                            "evidence": f"Token: {token}",
                            "owasp_category": "API2:2023-Broken Authentication",
                            "cwe_id": "CWE-521",
                            "remediation": "Implement strong token generation and validation",
                            "references": ["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"]
                        })
                        break
            except Exception as e:
                logger.debug(f"Error testing weak token: {str(e)}")
    
    async def _check_authorization(self, target: str, options: Dict[str, Any]):
        """Check for broken object level authorization"""
        # Test IDOR (Insecure Direct Object Reference)
        test_ids = ["1", "2", "999", "admin"]
        
        for test_id in test_ids:
            test_url = f"{target.rstrip('/')}/{test_id}"
            
            try:
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        # Check if we can access other users' data
                        self.findings.append({
                            "title": "Potential Broken Object Level Authorization",
                            "description": "API may allow access to unauthorized resources through direct object references",
                            "severity": SeverityLevel.HIGH,
                            "url": test_url,
                            "method": "GET",
                            "parameter": "id",
                            "owasp_category": "API1:2023-Broken Object Level Authorization",
                            "cwe_id": "CWE-639",
                            "remediation": "Implement proper authorization checks for all object access",
                            "references": ["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"]
                        })
                        break
            except Exception as e:
                logger.debug(f"Error testing IDOR: {str(e)}")
    
    async def _check_rate_limiting(self, target: str):
        """Check for rate limiting"""
        # Make multiple rapid requests
        requests = []
        for _ in range(100):
            requests.append(self.session.get(target))
        
        try:
            responses = await asyncio.gather(*requests, return_exceptions=True)
            
            # Check if all requests succeeded (no rate limiting)
            success_count = sum(1 for r in responses if not isinstance(r, Exception) and r.status == 200)
            
            if success_count >= 95:  # If 95%+ requests succeeded
                self.findings.append({
                    "title": "No Rate Limiting Detected",
                    "description": "API does not implement rate limiting, allowing potential abuse",
                    "severity": SeverityLevel.MEDIUM,
                    "url": target,
                    "evidence": f"{success_count}/100 requests succeeded",
                    "owasp_category": "API4:2023-Unrestricted Resource Consumption",
                    "cwe_id": "CWE-770",
                    "remediation": "Implement rate limiting to prevent abuse",
                    "references": ["https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"]
                })
        except Exception as e:
            logger.debug(f"Error checking rate limiting: {str(e)}")
    
    async def _check_input_validation(self, target: str):
        """Check input validation"""
        # Test with malicious payloads
        payloads = {
            "xss": "<script>alert('XSS')</script>",
            "sqli": "' OR '1'='1",
            "xxe": "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
            "overflow": "A" * 10000,
        }
        
        for payload_type, payload in payloads.items():
            try:
                # Test as query parameter
                test_url = f"{target}?input={payload}"
                async with self.session.get(test_url) as response:
                    text = await response.text()
                    
                    # Check if payload is reflected
                    if payload in text:
                        self.findings.append({
                            "title": f"Insufficient Input Validation ({payload_type.upper()})",
                            "description": "API does not properly validate/sanitize input",
                            "severity": SeverityLevel.HIGH,
                            "url": test_url,
                            "parameter": "input",
                            "evidence": f"Payload type: {payload_type}",
                            "owasp_category": "API8:2023-Security Misconfiguration",
                            "cwe_id": "CWE-20",
                            "remediation": "Implement strict input validation and sanitization",
                            "references": ["https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"]
                        })
            except Exception as e:
                logger.debug(f"Error testing input validation: {str(e)}")
    
    async def _check_http_methods(self, target: str):
        """Check for unrestricted HTTP methods"""
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]
        allowed_methods = []
        
        for method in methods:
            try:
                async with self.session.request(method, target) as response:
                    if response.status not in [405, 501]:  # Not Method Not Allowed
                        allowed_methods.append(method)
            except Exception as e:
                logger.debug(f"Error testing HTTP method {method}: {str(e)}")
        
        # Check for potentially dangerous methods
        dangerous_methods = set(allowed_methods) & {"TRACE", "TRACK"}
        if dangerous_methods:
            self.findings.append({
                "title": "Dangerous HTTP Methods Enabled",
                "description": f"API allows potentially dangerous HTTP methods: {', '.join(dangerous_methods)}",
                "severity": SeverityLevel.MEDIUM,
                "url": target,
                "evidence": f"Allowed methods: {', '.join(allowed_methods)}",
                "owasp_category": "API8:2023-Security Misconfiguration",
                "cwe_id": "CWE-16",
                "remediation": "Disable unnecessary HTTP methods",
                "references": ["https://owasp.org/www-community/vulnerabilities/Unsafe_HTTP_Methods"]
            })
    
    async def _check_api_versioning(self, target: str):
        """Check API versioning"""
        # Check if old API versions are accessible
        version_patterns = ["/v1/", "/v2/", "/api/v1/", "/api/v2/"]
        
        for pattern in version_patterns:
            if pattern not in target:
                test_url = target.replace("/api/", pattern)
                
                try:
                    async with self.session.get(test_url) as response:
                        if response.status == 200:
                            self.findings.append({
                                "title": "Multiple API Versions Accessible",
                                "description": "Old API versions remain accessible, potentially containing unfixed vulnerabilities",
                                "severity": SeverityLevel.MEDIUM,
                                "url": test_url,
                                "owasp_category": "API9:2023-Improper Inventory Management",
                                "cwe_id": "CWE-1059",
                                "remediation": "Deprecate and remove old API versions",
                                "references": ["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"]
                            })
                except Exception as e:
                    logger.debug(f"Error checking API version: {str(e)}")
    
    async def _check_error_handling(self, target: str):
        """Check error handling"""
        # Trigger errors and check responses
        error_triggers = [
            ("invalid_json", '{"invalid": json}', "application/json"),
            ("malformed_request", "not a valid request", "text/plain"),
        ]
        
        for trigger_name, payload, content_type in error_triggers:
            try:
                headers = {"Content-Type": content_type}
                async with self.session.post(target, data=payload, headers=headers) as response:
                    text = await response.text()
                    
                    # Check for information disclosure in error messages
                    disclosure_patterns = [
                        "stacktrace", "traceback", "exception", "file path",
                        "database", "sql", "connection string"
                    ]
                    
                    if any(pattern in text.lower() for pattern in disclosure_patterns):
                        self.findings.append({
                            "title": "Verbose Error Messages",
                            "description": "API returns detailed error messages that may leak sensitive information",
                            "severity": SeverityLevel.MEDIUM,
                            "url": target,
                            "method": "POST",
                            "evidence": f"Trigger: {trigger_name}",
                            "owasp_category": "API8:2023-Security Misconfiguration",
                            "cwe_id": "CWE-209",
                            "remediation": "Implement generic error messages and log detailed errors server-side",
                            "references": ["https://owasp.org/www-community/Improper_Error_Handling"]
                        })
                        break
            except Exception as e:
                logger.debug(f"Error checking error handling: {str(e)}")
    
    async def _check_data_exposure(self, target: str):
        """Check for excessive data exposure"""
        try:
            async with self.session.get(target) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                        
                        # Check for sensitive fields
                        sensitive_fields = [
                            "password", "secret", "token", "api_key",
                            "ssn", "credit_card", "private_key"
                        ]
                        
                        def check_dict(d, path=""):
                            found = []
                            if isinstance(d, dict):
                                for key, value in d.items():
                                    current_path = f"{path}.{key}" if path else key
                                    if any(field in key.lower() for field in sensitive_fields):
                                        found.append(current_path)
                                    if isinstance(value, (dict, list)):
                                        found.extend(check_dict(value, current_path))
                            elif isinstance(d, list):
                                for i, item in enumerate(d):
                                    found.extend(check_dict(item, f"{path}[{i}]"))
                            return found
                        
                        exposed_fields = check_dict(data)
                        
                        if exposed_fields:
                            self.findings.append({
                                "title": "Excessive Data Exposure",
                                "description": "API response contains potentially sensitive fields",
                                "severity": SeverityLevel.HIGH,
                                "url": target,
                                "method": "GET",
                                "evidence": f"Exposed fields: {', '.join(exposed_fields[:5])}",
                                "owasp_category": "API3:2023-Broken Object Property Level Authorization",
                                "cwe_id": "CWE-359",
                                "remediation": "Implement response filtering to return only necessary data",
                                "references": ["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"]
                            })
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            logger.debug(f"Error checking data exposure: {str(e)}")
    
    def _calculate_summary(self) -> Dict[str, Any]:
        """Calculate summary statistics"""
        severity_counts = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 0,
            SeverityLevel.MEDIUM: 0,
            SeverityLevel.LOW: 0,
            SeverityLevel.INFO: 0,
        }
        
        for finding in self.findings:
            severity = finding.get("severity")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Calculate risk score
        risk_score = (
            severity_counts[SeverityLevel.CRITICAL] * 10 +
            severity_counts[SeverityLevel.HIGH] * 7 +
            severity_counts[SeverityLevel.MEDIUM] * 4 +
            severity_counts[SeverityLevel.LOW] * 2 +
            severity_counts[SeverityLevel.INFO] * 0
        )
        
        risk_score = min(risk_score, 100)
        
        return {
            "total_findings": len(self.findings),
            "critical_count": severity_counts[SeverityLevel.CRITICAL],
            "high_count": severity_counts[SeverityLevel.HIGH],
            "medium_count": severity_counts[SeverityLevel.MEDIUM],
            "low_count": severity_counts[SeverityLevel.LOW],
            "info_count": severity_counts[SeverityLevel.INFO],
            "risk_score": risk_score,
        }

