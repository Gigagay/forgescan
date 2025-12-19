# backend/app/api/v1/executive.py
"""
Executive Dashboard API - C-Level Security Metrics
Provides high-level security posture insights for executives
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select, and_
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging

from app.db.session import get_db
from app.core.auth import get_current_active_user
from app.db.models.user import User
from app.db.models.scan import Scan
from app.db.models.finding import Finding
from app.db.models.finding_assignment import FindingAssignment

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/dashboard")
async def get_executive_dashboard(
    date_range: int = Query(30, description="Days to analyze"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
) -> Dict:
    """
    Get executive-level security metrics and trends
    
    Returns:
        - Security posture score (0-100)
        - Trend analysis
        - Critical/High issue counts
        - Mean time to remediation
        - Compliance status
        - Risk breakdown by category
        - Timeline data for charts
    """
    
    tenant_id = current_user.tenant_id
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=date_range)
    previous_start = start_date - timedelta(days=date_range)
    
    # Calculate security posture score
    current_score = await calculate_security_posture(
        db, tenant_id, start_date, end_date
    )
    previous_score = await calculate_security_posture(
        db, tenant_id, previous_start, start_date
    )
    
    trend_percentage = round(
        ((current_score - previous_score) / previous_score * 100) if previous_score else 0,
        1
    )
    
    # Get current critical/high issues
    critical_count = await get_open_findings_count(
        db, tenant_id, "critical"
    )
    high_count = await get_open_findings_count(
        db, tenant_id, "high"
    )
    
    # Calculate mean time to remediate
    mttr = await calculate_mttr(db, tenant_id, start_date, end_date)
    
    # Get compliance status
    compliance = await get_compliance_status(db, tenant_id)
    
    # Get risk breakdown
    risk_by_category = await get_risk_by_category(db, tenant_id)
    
    # Get timeline data
    timeline = await get_security_timeline(
        db, tenant_id, start_date, end_date
    )
    
    # Get top vulnerabilities
    top_vulns = await get_top_vulnerabilities(db, tenant_id, limit=5)
    
    return {
        "security_posture_score": current_score,
        "trend": f"{'+' if trend_percentage > 0 else ''}{trend_percentage}%",
        "critical_issues": critical_count,
        "high_issues": high_count,
        "total_open_findings": critical_count + high_count,
        "mean_time_to_remediate": f"{mttr:.1f} days",
        "compliance_status": compliance,
        "risk_by_category": risk_by_category,
        "timeline": timeline,
        "top_vulnerabilities": top_vulns,
        "metadata": {
            "date_range": date_range,
            "generated_at": datetime.utcnow().isoformat(),
            "tenant_id": tenant_id
        }
    }


async def calculate_security_posture(
    db: AsyncSession,
    tenant_id: str,
    start_date: datetime,
    end_date: datetime
) -> int:
    """
    Calculate security posture score (0-100)
    
    Factors:
    - Critical findings: -10 points each
    - High findings: -5 points each
    - Medium findings: -2 points each
    - Resolved findings: +3 points each
    - Recent scans: +10 points
    """
    
    # Get findings breakdown
    stmt = select(
        Finding.severity,
        Finding.status,
        func.count(Finding.id).label('count')
    ).where(
        and_(
            Finding.tenant_id == tenant_id,
            Finding.created_at >= start_date,
            Finding.created_at <= end_date
        )
    ).group_by(Finding.severity, Finding.status)
    
    result = await db.execute(stmt)
    findings = result.fetchall()
    
    # Start with perfect score
    score = 100
    
    for severity, status, count in findings:
        if status == 'open':
            if severity == 'critical':
                score -= count * 10
            elif severity == 'high':
                score -= count * 5
            elif severity == 'medium':
                score -= count * 2
        elif status == 'resolved':
            score += count * 3  # Bonus for fixing issues
    
    # Check for recent scans (activity bonus)
    recent_scans = await db.execute(
        select(func.count(Scan.id)).where(
            and_(
                Scan.tenant_id == tenant_id,
                Scan.created_at >= end_date - timedelta(days=7)
            )
        )
    )
    if recent_scans.scalar() > 0:
        score += 10
    
    # Clamp between 0-100
    return max(0, min(100, score))


async def get_open_findings_count(
    db: AsyncSession,
    tenant_id: str,
    severity: str
) -> int:
    """Get count of open findings by severity"""
    
    stmt = select(func.count(Finding.id)).where(
        and_(
            Finding.tenant_id == tenant_id,
            Finding.severity == severity,
            Finding.status == 'open'
        )
    )
    
    result = await db.execute(stmt)
    return result.scalar() or 0


async def calculate_mttr(
    db: AsyncSession,
    tenant_id: str,
    start_date: datetime,
    end_date: datetime
) -> float:
    """Calculate mean time to remediate (in days)"""
    
    stmt = select(
        Finding.created_at,
        Finding.resolved_at
    ).where(
        and_(
            Finding.tenant_id == tenant_id,
            Finding.status == 'resolved',
            Finding.resolved_at.isnot(None),
            Finding.resolved_at >= start_date,
            Finding.resolved_at <= end_date
        )
    )
    
    result = await db.execute(stmt)
    findings = result.fetchall()
    
    if not findings:
        return 0.0
    
    total_days = sum(
        (resolved - created).days
        for created, resolved in findings
    )
    
    return total_days / len(findings)


async def get_compliance_status(
    db: AsyncSession,
    tenant_id: str
) -> Dict[str, str]:
    """
    Calculate compliance scores for major frameworks
    Based on OWASP Top 10, PCI-DSS, and SOC2 controls
    """
    
    # Get all findings with their categories
    stmt = select(
        Finding.category,
        Finding.severity,
        func.count(Finding.id).label('count')
    ).where(
        and_(
            Finding.tenant_id == tenant_id,
            Finding.status == 'open'
        )
    ).group_by(Finding.category, Finding.severity)
    
    result = await db.execute(stmt)
    findings = result.fetchall()
    
    # OWASP Top 10 categories
    owasp_categories = {
        'injection', 'broken_authentication', 'sensitive_data_exposure',
        'xxe', 'broken_access_control', 'security_misconfiguration',
        'xss', 'insecure_deserialization', 'using_components_with_known_vulnerabilities',
        'insufficient_logging'
    }
    
    # Calculate scores (100 - penalty for each finding)
    owasp_score = 100
    pci_score = 100
    soc2_score = 100
    
    for category, severity, count in findings:
        penalty = count * (10 if severity == 'critical' else 5 if severity == 'high' else 2)
        
        if category in owasp_categories:
            owasp_score -= penalty
        
        # PCI-DSS focuses on data protection
        if category in ['injection', 'sensitive_data_exposure', 'broken_authentication']:
            pci_score -= penalty
        
        # SOC2 focuses on security controls
        if category in ['broken_access_control', 'security_misconfiguration']:
            soc2_score -= penalty
    
    return {
        "OWASP_Top_10": f"{max(0, owasp_score)}%",
        "PCI_DSS": f"{max(0, pci_score)}%",
        "SOC2": f"{max(0, soc2_score)}%"
    }


async def get_risk_by_category(
    db: AsyncSession,
    tenant_id: str
) -> List[Dict]:
    """Get risk breakdown by vulnerability category"""
    
    stmt = select(
        Finding.category,
        Finding.severity,
        func.count(Finding.id).label('count')
    ).where(
        and_(
            Finding.tenant_id == tenant_id,
            Finding.status == 'open'
        )
    ).group_by(Finding.category, Finding.severity).order_by(
        func.count(Finding.id).desc()
    ).limit(10)
    
    result = await db.execute(stmt)
    categories = result.fetchall()
    
    return [
        {
            "category": cat.replace('_', ' ').title(),
            "count": count,
            "severity": severity
        }
        for cat, severity, count in categories
    ]


async def get_security_timeline(
    db: AsyncSession,
    tenant_id: str,
    start_date: datetime,
    end_date: datetime
) -> List[Dict]:
    """Get security posture over time for charting"""
    
    timeline = []
    current = start_date
    
    while current <= end_date:
        next_date = current + timedelta(days=7)  # Weekly intervals
        
        score = await calculate_security_posture(
            db, tenant_id, current, next_date
        )
        
        timeline.append({
            "date": current.strftime("%Y-%m-%d"),
            "score": score
        })
        
        current = next_date
    
    return timeline


async def get_top_vulnerabilities(
    db: AsyncSession,
    tenant_id: str,
    limit: int = 5
) -> List[Dict]:
    """Get most common vulnerability types"""
    
    stmt = select(
        Finding.title,
        Finding.severity,
        func.count(Finding.id).label('count')
    ).where(
        and_(
            Finding.tenant_id == tenant_id,
            Finding.status == 'open'
        )
    ).group_by(Finding.title, Finding.severity).order_by(
        func.count(Finding.id).desc()
    ).limit(limit)
    
    result = await db.execute(stmt)
    vulns = result.fetchall()
    
    return [
        {
            "title": title,
            "severity": severity,
            "count": count
        }
        for title, severity, count in vulns
    ]


@router.get("/dashboard/export")
async def export_executive_report(
    date_range: int = Query(30),
    format: str = Query("json", regex="^(json|csv)$"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Export executive dashboard data"""
    
    data = await get_executive_dashboard(date_range, current_user, db)
    
    if format == "csv":
        # Convert to CSV format for easy import into Excel/Google Sheets
        import io
        import csv
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow(["Metric", "Value"])
        writer.writerow(["Security Posture Score", data["security_posture_score"]])
        writer.writerow(["Trend", data["trend"]])
        writer.writerow(["Critical Issues", data["critical_issues"]])
        writer.writerow(["High Issues", data["high_issues"]])
        writer.writerow(["MTTR (days)", data["mean_time_to_remediate"]])
        
        return {
            "content": output.getvalue(),
            "filename": f"executive_report_{datetime.utcnow().strftime('%Y%m%d')}.csv"
        }
    
    return data