# backend/app/scanners/sca_scanner.py
"""
Software Composition Analysis (SCA) Scanner
Detects vulnerabilities in dependencies (npm, pip, maven, composer, etc.)
"""

import asyncio
import json
import re
from typing import Dict, Any, List, Optional, Set
from datetime import datetime
import httpx
import hashlib

from app.scanners.base import BaseScannerPlugin, ScanResult, ScanStatus
from app.core.constants import SeverityLevel
from app.core.logging import logger


class SCAScanner(BaseScannerPlugin):
    """Software Composition Analysis Scanner"""
    
    name = "sca_scanner"
    version = "1.0.0"
    description = "Dependency vulnerability scanner supporting npm, pip, maven, composer"
    supported_protocols = ["file", "git"]
    
    # Supported package managers
    PACKAGE_MANAGERS = {
        "npm": {
            "files": ["package.json", "package-lock.json"],
            "ecosystem": "npm",
        },
        "pip": {
            "files": ["requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock"],
            "ecosystem": "pypi",
        },
        "maven": {
            "files": ["pom.xml"],
            "ecosystem": "maven",
        },
        "composer": {
            "files": ["composer.json", "composer.lock"],
            "ecosystem": "packagist",
        },
        "bundler": {
            "files": ["Gemfile", "Gemfile.lock"],
            "ecosystem": "rubygems",
        },
        "nuget": {
            "files": ["packages.config", "*.csproj"],
            "ecosystem": "nuget",
        },
    }
    
    def __init__(self):
        self.timeout = httpx.AsyncClient(timeout=30.0)
        self.findings: List[Dict[str, Any]] = []
        self.dependencies: Dict[str, List[Dict]] = {}
        
        # OSS Index API (Sonatype)
        self.oss_index_url = "https://ossindex.sonatype.org/api/v3/component-report"
        
        # NVD API
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # GitHub Advisory Database
        self.github_advisory_url = "https://api.github.com/advisories"
    
    async def initialize(self) -> None:
        """Initialize scanner"""
        self.client = httpx.AsyncClient(timeout=30.0)
    
    async def cleanup(self) -> None:
        """Cleanup resources"""
        if self.client:
            await self.client.close()
    
    async def validate_target(self, target: str) -> bool:
        """Validate if target can be scanned"""
        # For now, assume target is a git repo URL or file path
        return True
    
    async def scan(
        self,
        target: str,
        scan_id: str,
        tenant_id: str,
        options: Optional[Dict[str, Any]] = None
    ) -> ScanResult:
        """Execute SCA scan"""
        self.findings = []
        self.dependencies = {}
        options = options or {}
        
        try:
            logger.info(f"Starting SCA scan for {target}", extra={"scan_id": scan_id})
            
            # Step 1: Detect package managers and parse dependencies
            detected_managers = await self._detect_package_managers(target, options)
            
            if not detected_managers:
                return ScanResult(
                    status=ScanStatus.COMPLETED,
                    findings=[],
                    summary={"message": "No package managers detected"},
                    metadata={"target": target}
                )
            
            logger.info(f"Detected package managers: {list(detected_managers.keys())}")
            
            # Step 2: Parse dependencies for each package manager
            for pm_name, pm_data in detected_managers.items():
                deps = await self._parse_dependencies(pm_name, pm_data, target)
                self.dependencies[pm_name] = deps
            
            # Step 3: Check vulnerabilities for all dependencies
            all_deps = []
            for deps in self.dependencies.values():
                all_deps.extend(deps)
            
            logger.info(f"Found {len(all_deps)} dependencies to check")
            
            # Step 4: Query vulnerability databases
            vulnerabilities = await self._check_vulnerabilities(all_deps)
            
            # Step 5: Create findings
            for vuln in vulnerabilities:
                self.findings.append(self._create_finding(vuln))
            
            # Step 6: Calculate summary
            summary = self._calculate_summary()
            
            logger.info(f"SCA scan completed. Found {len(self.findings)} vulnerabilities")
            
            return ScanResult(
                status=ScanStatus.COMPLETED,
                findings=self.findings,
                summary=summary,
                metadata={
                    "target": target,
                    "package_managers": list(detected_managers.keys()),
                    "total_dependencies": len(all_deps),
                    "scan_id": scan_id,
                }
            )
            
        except Exception as e:
            logger.error(f"SCA scan failed: {str(e)}", exc_info=True)
            return ScanResult(
                status=ScanStatus.FAILED,
                findings=self.findings,
                summary=self._calculate_summary(),
                metadata={"target": target},
                error=str(e)
            )
    
    async def _detect_package_managers(
        self,
        target: str,
        options: Dict[str, Any]
    ) -> Dict[str, Dict]:
        """Detect which package managers are used in the project"""
        detected = {}
        
        # If target is file content (for testing)
        if options.get("file_content"):
            content = options["file_content"]
            filename = options.get("filename", "package.json")
            
            for pm_name, pm_info in self.PACKAGE_MANAGERS.items():
                if filename in pm_info["files"]:
                    detected[pm_name] = {
                        "files": [filename],
                        "content": {filename: content},
                        "ecosystem": pm_info["ecosystem"]
                    }
        
        # TODO: Add git repo cloning and file detection
        # For MVP, we'll support direct file content
        
        return detected
    
    async def _parse_dependencies(
        self,
        pm_name: str,
        pm_data: Dict,
        target: str
    ) -> List[Dict[str, Any]]:
        """Parse dependencies from package manager files"""
        
        if pm_name == "npm":
            return await self._parse_npm(pm_data)
        elif pm_name == "pip":
            return await self._parse_pip(pm_data)
        elif pm_name == "maven":
            return await self._parse_maven(pm_data)
        elif pm_name == "composer":
            return await self._parse_composer(pm_data)
        
        return []
    
    async def _parse_npm(self, pm_data: Dict) -> List[Dict[str, Any]]:
        """Parse npm dependencies"""
        dependencies = []
        
        for filename, content in pm_data["content"].items():
            if filename == "package.json":
                try:
                    data = json.loads(content)
                    
                    # Parse dependencies
                    for dep_type in ["dependencies", "devDependencies"]:
                        if dep_type in data:
                            for name, version in data[dep_type].items():
                                # Clean version (remove ^, ~, etc.)
                                clean_version = re.sub(r'[^\d.]', '', version)
                                
                                dependencies.append({
                                    "name": name,
                                    "version": clean_version,
                                    "ecosystem": "npm",
                                    "purl": f"pkg:npm/{name}@{clean_version}",
                                    "type": dep_type,
                                })
                
                except json.JSONDecodeError:
                    logger.error(f"Failed to parse {filename}")
        
        return dependencies
    
    async def _parse_pip(self, pm_data: Dict) -> List[Dict[str, Any]]:
        """Parse pip dependencies"""
        dependencies = []
        
        for filename, content in pm_data["content"].items():
            if filename == "requirements.txt":
                for line in content.split('\n'):
                    line = line.strip()
                    
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse package==version or package>=version
                    match = re.match(r'([a-zA-Z0-9\-_]+)(==|>=|<=|>|<)([0-9.]+)', line)
                    if match:
                        name = match.group(1)
                        version = match.group(3)
                        
                        dependencies.append({
                            "name": name,
                            "version": version,
                            "ecosystem": "pypi",
                            "purl": f"pkg:pypi/{name}@{version}",
                            "type": "dependencies",
                        })
        
        return dependencies
    
    async def _parse_maven(self, pm_data: Dict) -> List[Dict[str, Any]]:
        """Parse Maven dependencies from pom.xml"""
        dependencies = []
        
        for filename, content in pm_data["content"].items():
            if filename == "pom.xml":
                # Simple XML parsing (for MVP)
                # In production, use xml.etree.ElementTree
                dep_pattern = r'<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>.*?</dependency>'
                matches = re.findall(dep_pattern, content, re.DOTALL)
                
                for group_id, artifact_id, version in matches:
                    dependencies.append({
                        "name": f"{group_id}:{artifact_id}",
                        "version": version.strip(),
                        "ecosystem": "maven",
                        "purl": f"pkg:maven/{group_id}/{artifact_id}@{version}",
                        "type": "dependencies",
                    })
        
        return dependencies
    
    async def _parse_composer(self, pm_data: Dict) -> List[Dict[str, Any]]:
        """Parse Composer dependencies"""
        dependencies = []
        
        for filename, content in pm_data["content"].items():
            if filename == "composer.json":
                try:
                    data = json.loads(content)
                    
                    for dep_type in ["require", "require-dev"]:
                        if dep_type in data:
                            for name, version in data[dep_type].items():
                                # Skip PHP itself
                                if name == "php":
                                    continue
                                
                                # Clean version
                                clean_version = re.sub(r'[^\d.]', '', version)
                                
                                dependencies.append({
                                    "name": name,
                                    "version": clean_version,
                                    "ecosystem": "packagist",
                                    "purl": f"pkg:composer/{name}@{clean_version}",
                                    "type": dep_type,
                                })
                
                except json.JSONDecodeError:
                    logger.error(f"Failed to parse {filename}")
        
        return dependencies
    
    async def _check_vulnerabilities(
        self,
        dependencies: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Check dependencies against vulnerability databases"""
        
        vulnerabilities = []
        
        # Split into batches (OSS Index allows 128 per request)
        batch_size = 100
        for i in range(0, len(dependencies), batch_size):
            batch = dependencies[i:i + batch_size]
            
            # Query OSS Index
            oss_vulns = await self._query_oss_index(batch)
            vulnerabilities.extend(oss_vulns)
            
            # Add small delay to avoid rate limiting
            await asyncio.sleep(1)
        
        return vulnerabilities
    
    async def _query_oss_index(
        self,
        dependencies: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Query Sonatype OSS Index for vulnerabilities"""
        
        vulnerabilities = []
        
        try:
            # Prepare coordinates
            coordinates = [dep["purl"] for dep in dependencies]
            
            # Query OSS Index
            response = await self.client.post(
                self.oss_index_url,
                json={"coordinates": coordinates},
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                results = response.json()
                
                for result in results:
                    if result.get("vulnerabilities"):
                        # Find matching dependency
                        dep = next(
                            (d for d in dependencies if d["purl"] == result["coordinates"]),
                            None
                        )
                        
                        if not dep:
                            continue
                        
                        for vuln in result["vulnerabilities"]:
                            vulnerabilities.append({
                                "dependency": dep,
                                "cve_id": vuln.get("cve") or vuln.get("id"),
                                "title": vuln.get("title"),
                                "description": vuln.get("description"),
                                "cvss_score": vuln.get("cvssScore", 0),
                                "cvss_vector": vuln.get("cvssVector"),
                                "severity": self._map_cvss_to_severity(vuln.get("cvssScore", 0)),
                                "reference": vuln.get("reference"),
                                "published_date": vuln.get("publishedDate"),
                                "fixed_versions": self._extract_fixed_versions(vuln),
                            })
            
        except Exception as e:
            logger.error(f"OSS Index query failed: {str(e)}")
        
        return vulnerabilities
    
    def _map_cvss_to_severity(self, cvss_score: float) -> str:
        """Map CVSS score to severity level"""
        if cvss_score >= 9.0:
            return SeverityLevel.CRITICAL
        elif cvss_score >= 7.0:
            return SeverityLevel.HIGH
        elif cvss_score >= 4.0:
            return SeverityLevel.MEDIUM
        elif cvss_score > 0:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO
    
    def _extract_fixed_versions(self, vuln: Dict) -> List[str]:
        """Extract fixed versions from vulnerability data"""
        fixed_versions = []
        
        # Try to extract from description or references
        description = vuln.get("description", "")
        
        # Common patterns: "Fixed in version X.Y.Z" or "Upgrade to X.Y.Z"
        patterns = [
            r'[Ff]ixed in (?:version )?([0-9.]+)',
            r'[Uu]pgrade to ([0-9.]+)',
            r'[Pp]atched in ([0-9.]+)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, description)
            fixed_versions.extend(matches)
        
        return list(set(fixed_versions))  # Remove duplicates
    
    def _create_finding(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Create a finding from vulnerability data"""
        
        dep = vuln["dependency"]
        
        # Build remediation advice
        remediation = f"Upgrade {dep['name']} to a patched version"
        if vuln.get("fixed_versions"):
            remediation += f": {', '.join(vuln['fixed_versions'])}"
        
        return {
            "title": f"{vuln['cve_id']}: {dep['name']}@{dep['version']}",
            "description": vuln.get("description", "No description available"),
            "severity": vuln["severity"],
            "dependency_name": dep["name"],
            "dependency_version": dep["version"],
            "dependency_ecosystem": dep["ecosystem"],
            "cve_id": vuln.get("cve_id"),
            "cvss_score": vuln.get("cvss_score"),
            "cvss_vector": vuln.get("cvss_vector"),
            "owasp_category": "A06:2021-Vulnerable and Outdated Components",
            "remediation": remediation,
            "fixed_versions": vuln.get("fixed_versions", []),
            "references": [vuln.get("reference")] if vuln.get("reference") else [],
            "published_date": vuln.get("published_date"),
        }
    
    def _calculate_summary(self) -> Dict[str, Any]:
        """Calculate scan summary"""
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
        
        # Count unique dependencies with vulnerabilities
        vulnerable_deps = set()
        for finding in self.findings:
            dep_name = finding.get("dependency_name")
            if dep_name:
                vulnerable_deps.add(dep_name)
        
        return {
            "total_findings": len(self.findings),
            "critical_count": severity_counts[SeverityLevel.CRITICAL],
            "high_count": severity_counts[SeverityLevel.HIGH],
            "medium_count": severity_counts[SeverityLevel.MEDIUM],
            "low_count": severity_counts[SeverityLevel.LOW],
            "info_count": severity_counts[SeverityLevel.INFO],
            "risk_score": risk_score,
            "vulnerable_dependencies": len(vulnerable_deps),
            "total_dependencies": sum(len(deps) for deps in self.dependencies.values()),
        }
