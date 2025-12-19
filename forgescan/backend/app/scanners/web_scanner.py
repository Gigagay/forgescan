# backend/app/scanners/web_scanner.py
import aiohttp
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import asyncio

from app.scanners.base import BaseScannerPlugin, ScanResult, ScanStatus
from app.core.constants import SeverityLevel, OWASP_WEB_TOP_10
from app.core.logging import logger


class WebScanner(BaseScannerPlugin):
    """Web application vulnerability scanner"""
    
    name = "web_scanner"
    version = "1.0.0"
    description = "Web application security scanner"
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
        """Execute web security scan"""
        self.findings = []
        options = options or {}
        
        try:
            logger.info(f"Starting web scan for {target}", extra={"scan_id": scan_id})
            
            # Perform various security checks
            await self._check_ssl_tls(target)
            await self._check_security_headers(target)
            await self._check_xss_vulnerabilities(target)
            await self._check_sql_injection(target)
            await self._check_directory_listing(target)
            await self._check_sensitive_files(target)
            await self._check_cors_misconfiguration(target)
            
            # Optional: Deeper crawl if enabled
            if options.get("deep_crawl", False):
                await self._crawl_and_test(target, max_depth=2)
            
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
            logger.error(f"Web scan failed: {str(e)}", exc_info=True)
            return ScanResult(
                status=ScanStatus.FAILED,
                findings=self.findings,
                summary=self._calculate_summary(),
                metadata={"target": target},
                error=str(e)
            )
    
    async def _check_ssl_tls(self, target: str):
        """Check SSL/TLS configuration"""
        if not target.startswith("https://"):
            self.findings.append({
                "title": "Missing HTTPS",
                "description": "Website is not using HTTPS encryption",
                "severity": SeverityLevel.HIGH,
                "url": target,
                "owasp_category": "A02:2021-Cryptographic Failures",
                "cwe_id": "CWE-319",
                "remediation": "Implement HTTPS with a valid SSL/TLS certificate",
                "references": ["https://owasp.org/www-project-web-security-testing-guide/"]
            })
    
    async def _check_security_headers(self, target: str):
        """Check for security headers"""
        try:
            async with self.session.get(target) as response:
                headers = response.headers
                
                # Check for missing security headers
                required_headers = {
                    "X-Frame-Options": ("Clickjacking Protection Missing", SeverityLevel.MEDIUM),
                    "X-Content-Type-Options": ("MIME Type Sniffing Prevention Missing", SeverityLevel.MEDIUM),
                    "Strict-Transport-Security": ("HSTS Header Missing", SeverityLevel.MEDIUM),
                    "Content-Security-Policy": ("Content Security Policy Missing", SeverityLevel.MEDIUM),
                    "X-XSS-Protection": ("XSS Protection Header Missing", SeverityLevel.LOW),
                }
                
                for header, (title, severity) in required_headers.items():
                    if header.lower() not in [h.lower() for h in headers.keys()]:
                        self.findings.append({
                            "title": title,
                            "description": f"Missing security header: {header}",
                            "severity": severity,
                            "url": target,
                            "owasp_category": "A05:2021-Security Misconfiguration",
                            "cwe_id": "CWE-16",
                            "remediation": f"Add {header} header to HTTP responses",
                            "references": ["https://owasp.org/www-project-secure-headers/"]
                        })
        
        except Exception as e:
            logger.error(f"Error checking security headers: {str(e)}")
    
    async def _check_xss_vulnerabilities(self, target: str):
        """Check for XSS vulnerabilities"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
        ]
        
        # Parse URL for testing
        parsed = urlparse(target)
        
        # Test common parameters
        test_params = ["q", "search", "query", "id", "page"]
        
        for param in test_params:
            for payload in xss_payloads:
                test_url = f"{target}?{param}={payload}"
                
                try:
                    async with self.session.get(test_url, allow_redirects=False) as response:
                        text = await response.text()
                        
                        # Check if payload is reflected without encoding
                        if payload in text:
                            self.findings.append({
                                "title": "Potential Cross-Site Scripting (XSS)",
                                "description": f"XSS payload reflected in response without proper encoding",
                                "severity": SeverityLevel.HIGH,
                                "url": test_url,
                                "parameter": param,
                                "evidence": f"Payload: {payload}",
                                "owasp_category": "A03:2021-Injection",
                                "cwe_id": "CWE-79",
                                "remediation": "Implement proper input validation and output encoding",
                                "references": ["https://owasp.org/www-community/attacks/xss/"]
                            })
                            break  # Found XSS, move to next parameter
                
                except Exception as e:
                    logger.debug(f"Error testing XSS: {str(e)}")
    
    async def _check_sql_injection(self, target: str):
        """Check for SQL injection vulnerabilities"""
        sql_payloads = [
            "' OR '1'='1",
            "1' OR '1'='1",
            "admin'--",
            "1 UNION SELECT NULL--",
        ]
        
        test_params = ["id", "user", "page", "search"]
        
        sql_error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"Driver.*SQL Server",
            r"OLE DB.*SQL Server",
            r"SQLServer JDBC Driver",
            r"Microsoft SQL Native Client error",
        ]
        
        for param in test_params:
            for payload in sql_payloads:
                test_url = f"{target}?{param}={payload}"
                
                try:
                    async with self.session.get(test_url, allow_redirects=False) as response:
                        text = await response.text()
                        
                        # Check for SQL error messages
                        for pattern in sql_error_patterns:
                            if re.search(pattern, text, re.IGNORECASE):
                                self.findings.append({
                                    "title": "Potential SQL Injection",
                                    "description": "SQL error message detected, indicating possible SQL injection vulnerability",
                                    "severity": SeverityLevel.CRITICAL,
                                    "url": test_url,
                                    "parameter": param,
                                    "evidence": f"Payload: {payload}",
                                    "owasp_category": "A03:2021-Injection",
                                    "cwe_id": "CWE-89",
                                    "remediation": "Use parameterized queries or prepared statements",
                                    "references": ["https://owasp.org/www-community/attacks/SQL_Injection"]
                                })
                                break
                
                except Exception as e:
                    logger.debug(f"Error testing SQL injection: {str(e)}")
    
    async def _check_directory_listing(self, target: str):
        """Check for directory listing vulnerabilities"""
        common_dirs = ["/admin", "/backup", "/config", "/uploads", "/images", "/css", "/js"]
        
        for directory in common_dirs:
            test_url = urljoin(target, directory)
            
            try:
                async with self.session.get(test_url, allow_redirects=False) as response:
                    text = await response.text()
                    
                    # Look for directory listing indicators
                    if any(indicator in text.lower() for indicator in ["index of", "parent directory", "[dir]"]):
                        self.findings.append({
                            "title": "Directory Listing Enabled",
                            "description": f"Directory listing is enabled for {directory}",
                            "severity": SeverityLevel.MEDIUM,
                            "url": test_url,
                            "owasp_category": "A05:2021-Security Misconfiguration",
                            "cwe_id": "CWE-548",
                            "remediation": "Disable directory listing in web server configuration",
                            "references": ["https://owasp.org/www-community/vulnerabilities/Directory_Listing"]
                        })
            
            except Exception as e:
                logger.debug(f"Error checking directory listing: {str(e)}")
    
    async def _check_sensitive_files(self, target: str):
        """Check for exposed sensitive files"""
        sensitive_files = [
            "/.git/config",
            "/.env",
            "/backup.sql",
            "/database.sql",
            "/config.php.bak",
            "/web.config",
            "/.htaccess",
            "/phpinfo.php",
            "/robots.txt",  # Not sensitive but informative
        ]
        
        for file_path in sensitive_files:
            test_url = urljoin(target, file_path)
            
            try:
                async with self.session.get(test_url, allow_redirects=False) as response:
                    if response.status == 200:
                        severity = SeverityLevel.CRITICAL if file_path != "/robots.txt" else SeverityLevel.INFO
                        
                        self.findings.append({
                            "title": f"Sensitive File Exposed: {file_path}",
                            "description": f"Sensitive file is publicly accessible",
                            "severity": severity,
                            "url": test_url,
                            "owasp_category": "A05:2021-Security Misconfiguration",
                            "cwe_id": "CWE-538",
                            "remediation": "Remove or restrict access to sensitive files",
                            "references": ["https://owasp.org/www-project-web-security-testing-guide/"]
                        })
            
            except Exception as e:
                logger.debug(f"Error checking sensitive files: {str(e)}")
    
    async def _check_cors_misconfiguration(self, target: str):
        """Check for CORS misconfiguration"""
        try:
            headers = {"Origin": "https://evil.com"}
            async with self.session.get(target, headers=headers) as response:
                cors_header = response.headers.get("Access-Control-Allow-Origin", "")
                
                if cors_header == "*":
                    self.findings.append({
                        "title": "Overly Permissive CORS Policy",
                        "description": "CORS policy allows any origin (*)",
                        "severity": SeverityLevel.MEDIUM,
                        "url": target,
                        "evidence": f"Access-Control-Allow-Origin: {cors_header}",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "cwe_id": "CWE-942",
                        "remediation": "Restrict CORS to specific trusted origins",
                        "references": ["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"]
                    })
                
                elif cors_header == "https://evil.com":
                    self.findings.append({
                        "title": "CORS Reflects Arbitrary Origins",
                        "description": "CORS policy reflects the Origin header without validation",
                        "severity": SeverityLevel.HIGH,
                        "url": target,
                        "evidence": f"Access-Control-Allow-Origin: {cors_header}",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "cwe_id": "CWE-942",
                        "remediation": "Implement proper origin validation for CORS",
                        "references": ["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"]
                    })
        
        except Exception as e:
            logger.debug(f"Error checking CORS: {str(e)}")
    
    async def _crawl_and_test(self, target: str, max_depth: int = 2):
        """Crawl website and test discovered pages"""
        visited = set()
        to_visit = [(target, 0)]
        
        while to_visit and len(visited) < 50:  # Limit crawl
            current_url, depth = to_visit.pop(0)
            
            if current_url in visited or depth > max_depth:
                continue
            
            visited.add(current_url)
            
            try:
                async with self.session.get(current_url) as response:
                    if response.status == 200:
                        text = await response.text()
                        soup = BeautifulSoup(text, 'html.parser')
                        
                        # Find all links
                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            absolute_url = urljoin(current_url, href)
                            
                            # Only crawl same domain
                            if urlparse(absolute_url).netloc == urlparse(target).netloc:
                                to_visit.append((absolute_url, depth + 1))
            
            except Exception as e:
                logger.debug(f"Error crawling {current_url}: {str(e)}")
    
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
        
        # Calculate risk score (weighted by severity)
        risk_score = (
            severity_counts[SeverityLevel.CRITICAL] * 10 +
            severity_counts[SeverityLevel.HIGH] * 7 +
            severity_counts[SeverityLevel.MEDIUM] * 4 +
            severity_counts[SeverityLevel.LOW] * 2 +
            severity_counts[SeverityLevel.INFO] * 0
        )
        
        risk_score = min(risk_score, 100)  # Cap at 100
        
        return {
            "total_findings": len(self.findings),
            "critical_count": severity_counts[SeverityLevel.CRITICAL],
            "high_count": severity_counts[SeverityLevel.HIGH],
            "medium_count": severity_counts[SeverityLevel.MEDIUM],
            "low_count": severity_counts[SeverityLevel.LOW],
            "info_count": severity_counts[SeverityLevel.INFO],
            "risk_score": risk_score,
        }