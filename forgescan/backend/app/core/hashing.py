import hashlib


def fingerprint_finding(
    scanner: str,
    rule_id: str,
    file: str | None,
    line: int | None,
    title: str,
) -> str:
    """
    Generate a deterministic fingerprint for a finding.
    
    Deduplication depends on stable hashing. Every invocation with
    identical inputs must produce identical output.
    
    Args:
        scanner: Scanner name (e.g., "bandit", "semgrep")
        rule_id: Rule ID from scanner
        file: File path (can be None)
        line: Line number (can be None)
        title: Finding title
    
    Returns:
        SHA256 hexdigest of normalized finding signature
    """
    raw = f"{scanner}:{rule_id}:{file}:{line}:{title}"
    return hashlib.sha256(raw.encode()).hexdigest()
