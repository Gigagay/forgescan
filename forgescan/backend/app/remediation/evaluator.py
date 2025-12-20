import re
from typing import List, Dict, Any

from .models import Remediation, Priority
from .priorities import BusinessImpactScore, calculate_priority
from .rules import RULES


def map_business_impact(impact_str: str) -> BusinessImpactScore:
    """Convert string business impact to BusinessImpactScore enum"""
    mapping = {
        "LOW": BusinessImpactScore.LOW,
        "MEDIUM": BusinessImpactScore.MEDIUM,
        "HIGH": BusinessImpactScore.HIGH,
        "CRITICAL": BusinessImpactScore.CRITICAL,
    }
    return mapping.get(impact_str.upper(), BusinessImpactScore.LOW)


def find_matching_rule(finding: Dict[str, Any]) -> Dict[str, Any] | None:
    """
    Match a finding against remediation rules by description.
    
    Uses case-insensitive regex matching on rule matchers.
    Returns first matching rule or None.
    """
    finding_desc = finding.get("description", "").lower()
    finding_title = finding.get("title", "").lower()
    
    for rule in RULES:
        matcher = rule.get("matcher", "").lower()
        # Split by pipe for multiple match patterns
        patterns = [p.strip() for p in matcher.split("|")]
        
        for pattern in patterns:
            if re.search(pattern, finding_desc) or re.search(pattern, finding_title):
                return rule
    
    return None


def extract_technical_severity(finding: Dict[str, Any]) -> int:
    """
    Extract technical severity as 1-10 scale.
    
    Mapping from normalized severity to numeric scale:
    - critical: 9
    - high: 7
    - medium: 5
    - low: 3
    - info: 1
    """
    severity_mapping = {
        "critical": 9,
        "high": 7,
        "medium": 5,
        "low": 3,
        "info": 1,
    }
    
    severity = finding.get("severity", "low").lower()
    return severity_mapping.get(severity, 3)


def extract_exploitability(finding: Dict[str, Any]) -> int:
    """
    Extract exploitability multiplier (1-10).
    
    Default 1. Can be enhanced by:
    - Public exploit availability (5-7)
    - Active exploitation observed (8-10)
    - Configuration-based exploitation (2-3)
    """
    # TODO: Integrate with threat intelligence / CVE data
    return 1


def evaluate_scan(findings: List[Dict[str, Any]]) -> List[Remediation]:
    """
    Convert raw scanner findings into prioritized remediation items.
    
    Process:
    1. Match each finding against remediation rules
    2. Extract/calculate technical severity and business impact
    3. Calculate priority using formula
    4. Create Remediation object
    5. Sort by priority (P0 first)
    
    Args:
        findings: List of raw scanner findings with at minimum:
            {
                "description": str,
                "title": str,
                "severity": str (critical|high|medium|low|info),
                ...
            }
    
    Returns:
        List[Remediation] sorted by priority descending
    """
    remediations = []

    for finding in findings:
        # Match a rule based on description/title
        rule_match = find_matching_rule(finding)

        if rule_match:
            # Extract severity and business impact
            technical_severity = extract_technical_severity(finding)
            business_impact = map_business_impact(rule_match["business_impact"])
            exploitability = extract_exploitability(finding)
            
            # Calculate priority using combined formula
            priority = calculate_priority(
                technical_severity=technical_severity,
                business_impact=business_impact,
                exploitability=exploitability
            )

            remediation = Remediation(
                priority=priority,
                action=rule_match["action"],
                timeframe=rule_match["timeframe"],
                business_risk=f"Impact on business: {rule_match['business_impact']}",
                technical_risk=finding.get("description", "N/A"),
                justification=f"Matched rule: {rule_match['description']}",
                confidence=rule_match["confidence"]
            )
            remediations.append(remediation)

    # Sort by priority (P0 first)
    priority_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
    remediations.sort(key=lambda x: priority_order.get(x.priority, 999))
    
    return remediations


def evaluate_scan_json(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Evaluate scan and return remediations as JSON-serializable dicts.
    
    Useful for API responses that need plain dict format.
    """
    remediations = evaluate_scan(findings)
    return [r.dict() for r in remediations]
