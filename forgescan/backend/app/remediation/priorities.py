from enum import Enum


class BusinessImpactScore(Enum):
    """
    Multiplier values for business impact calculation.
    
    Powers of two for clean priority boundaries:
    - LOW (1): operational convenience
    - MEDIUM (2): customer experience or internal systems
    - HIGH (4): revenue/compliance impact
    - CRITICAL (8): data breach or legal liability
    """
    LOW = 1
    MEDIUM = 2
    HIGH = 4
    CRITICAL = 8


def calculate_priority(
    technical_severity: int,
    business_impact: BusinessImpactScore,
    exploitability: int = 1
) -> str:
    """
    Calculate remediation priority using formula:
    priority_score = technical_severity * exploitability * business_impact_value
    
    Args:
        technical_severity: 1-10 scale from scanner
        business_impact: BusinessImpactScore enum
        exploitability: 1-10 scale (default 1, set higher if easily exploitable)
    
    Returns:
        Priority level: P0, P1, P2, P3, or P4
    
    Examples:
        - High severity (7) + HIGH impact (4) + normal exploit (1) = 28 → P0
        - Medium severity (5) + MEDIUM impact (2) + normal exploit (1) = 10 → P2
        - Low severity (3) + LOW impact (1) + normal exploit (1) = 3 → P4
    """
    score = technical_severity * exploitability * business_impact.value

    if score >= 24:
        return "P0"
    elif score >= 16:
        return "P1"
    elif score >= 8:
        return "P2"
    elif score >= 4:
        return "P3"
    else:
        return "P4"
