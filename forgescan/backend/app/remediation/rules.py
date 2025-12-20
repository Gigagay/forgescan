# Business-context-aware remediation rules
# Each rule includes: detection, technical_severity, business_impact, recommended_action
#
# Rules are matched against finding descriptions and used to:
# 1. Calculate priority using business impact + technical severity
# 2. Provide actionable remediation guidance
# 3. Establish timeframes for remediation
#
# Structure allows easy addition of new rules as threat landscape evolves.

RULES = [
    {
        "id": "R001",
        "description": "Missing rate limiting on public authentication endpoints",
        "matcher": "rate limit",
        "technical_severity": 3,
        "business_impact": "CRITICAL",
        "action": "Implement rate limiting and CAPTCHA on all auth endpoints",
        "timeframe": "Immediate",
        "confidence": "High"
    },
    {
        "id": "R002",
        "description": "Use of weak cipher TLS configuration",
        "matcher": "weak cipher|tls|ssl",
        "technical_severity": 7,
        "business_impact": "HIGH",
        "action": "Disable weak ciphers and enforce TLS 1.2+ with modern suites",
        "timeframe": "Within 24 hours",
        "confidence": "High"
    },
    {
        "id": "R003",
        "description": "Exposed internal dev endpoints",
        "matcher": "debug|dev endpoint|internal",
        "technical_severity": 5,
        "business_impact": "MEDIUM",
        "action": "Restrict dev endpoints to VPN or internal network only",
        "timeframe": "Within 48 hours",
        "confidence": "High"
    },
    {
        "id": "R004",
        "description": "SCA dev-only dependency vulnerability",
        "matcher": "dev dependency|devDependencies",
        "technical_severity": 6,
        "business_impact": "LOW",
        "action": "Update dev dependencies; no production impact",
        "timeframe": "Next sprint",
        "confidence": "Medium"
    },
    {
        "id": "R005",
        "description": "Hardcoded secrets or credentials",
        "matcher": "hardcoded|secret|password|api.?key|token",
        "technical_severity": 9,
        "business_impact": "CRITICAL",
        "action": "Rotate credentials immediately; remove from codebase; use secrets manager",
        "timeframe": "Immediate",
        "confidence": "High"
    },
    {
        "id": "R006",
        "description": "SQL injection vulnerability",
        "matcher": "sql injection|sqlmap",
        "technical_severity": 8,
        "business_impact": "CRITICAL",
        "action": "Use parameterized queries or ORM; validate all user input",
        "timeframe": "Immediate",
        "confidence": "High"
    },
    {
        "id": "R007",
        "description": "Cross-site scripting (XSS) vulnerability",
        "matcher": "xss|cross.?site.*script",
        "technical_severity": 7,
        "business_impact": "HIGH",
        "action": "Sanitize all user input; use Content Security Policy headers",
        "timeframe": "Within 24 hours",
        "confidence": "High"
    },
    {
        "id": "R008",
        "description": "Missing CORS headers or overly permissive CORS",
        "matcher": "cors|cross.?origin",
        "technical_severity": 4,
        "business_impact": "MEDIUM",
        "action": "Implement strict CORS policy; restrict to trusted origins only",
        "timeframe": "Within 48 hours",
        "confidence": "High"
    },
    {
        "id": "R009",
        "description": "Unsafe cryptography or weak hashing",
        "matcher": "md5|sha1|weak hash|unsafe crypto",
        "technical_severity": 8,
        "business_impact": "HIGH",
        "action": "Use PBKDF2, bcrypt, or Argon2 for passwords; SHA256+ for other data",
        "timeframe": "Within 48 hours",
        "confidence": "High"
    },
    {
        "id": "R010",
        "description": "Missing security headers",
        "matcher": "security header|x-frame|x-content|csp",
        "technical_severity": 3,
        "business_impact": "MEDIUM",
        "action": "Add CSP, X-Frame-Options, X-Content-Type-Options headers",
        "timeframe": "Within 48 hours",
        "confidence": "Medium"
    },
]
