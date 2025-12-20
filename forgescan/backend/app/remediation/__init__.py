"""
ForgeScan Business-Impact-Driven Remediation Engine

This module provides intelligent prioritization of security findings by
combining technical severity with business context.

Core components:
- models: Pydantic data structures for Priority, BusinessImpact, Remediation
- priorities: Scoring algorithm that combines severity + business impact
- rules: Hard-coded remediation rules with context
- evaluator: Engine that matches findings to rules and calculates priorities

Usage:
    from app.remediation.evaluator import evaluate_scan
    
    findings = [...]  # from scanner output
    remediations = evaluate_scan(findings)
    
    for r in remediations:
        print(r.priority, r.action)  # P0 first
"""

from .models import Priority, BusinessImpact, Remediation
from .evaluator import evaluate_scan, evaluate_scan_json

__all__ = [
    "Priority",
    "BusinessImpact",
    "Remediation",
    "evaluate_scan",
    "evaluate_scan_json",
]
