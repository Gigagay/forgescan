# ------------------------------------------------------------------------------
# FILE 2: Backend API - GitHub Webhook Handler
# Save as: backend/app/api/v1/integrations/github.py
# ------------------------------------------------------------------------------
"""
GitHub Integration API
Handles webhook events and provides CI/CD scanning capabilities
"""

from fastapi import APIRouter, Request, HTTPException, Depends, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import hmac
import hashlib
import json
from typing import Dict, Optional
from datetime import datetime

from app.db.session import get_db
from app.db.models.user import User
from app.db.models.ci_integration import CIIntegration, CIScanRun
from app.core.auth import get_current_active_user
from app.workers.scanner_manager import scan_orchestrator
from app.core.config import settings

router = APIRouter()


@router.post("/webhook")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """
    Handle GitHub webhook events
    Supports: push, pull_request, and schedule events
    """
    
    # Verify webhook signature
    signature = request.headers.get("X-Hub-Signature-256")
    if not signature:
        raise HTTPException(status_code=401, detail="Missing signature")
    
    body = await request.body()
    
    # Validate signature
    expected_signature = "sha256=" + hmac.new(
        settings.GITHUB_WEBHOOK_SECRET.encode(),
        body,
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(signature, expected_signature):
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    # Parse event
    event_type = request.headers.get("X-GitHub-Event")
    payload = json.loads(body)
    
    # Get CI integration record
    repo_full_name = payload["repository"]["full_name"]
    installation_id = payload.get("installation", {}).get("id")
    
    stmt = select(CIIntegration).where(
        CIIntegration.repo_full_name == repo_full_name,
        CIIntegration.enabled == True
    )
    result = await db.execute(stmt)
    ci_integration = result.scalar_one_or_none()
    
    if not ci_integration:
        return {"status": "ignored", "reason": "No active integration"}
    
    # Handle different event types
    if event_type == "pull_request":
        await handle_pull_request(payload, ci_integration, background_tasks, db)
    elif event_type == "push":
        await handle_push(payload, ci_integration, background_tasks, db)
    
    return {"status": "processed"}


async def handle_pull_request(
    payload: Dict,
    ci_integration: CIIntegration,
    background_tasks: BackgroundTasks,
    db: AsyncSession
):
    """Handle pull request events"""
    
    action = payload["action"]
    if action not in ["opened", "synchronize", "reopened"]:
        return
    
    pr = payload["pull_request"]
    pr_number = pr["number"]
    pr_url = pr["html_url"]
    branch = pr["head"]["ref"]
    commit_sha = pr["head"]["sha"]
    
    # Create scan run record
    scan_run = CIScanRun(
        ci_integration_id=ci_integration.id,
        tenant_id=ci_integration.tenant_id,
        event_type="pull_request",
        pr_number=pr_number,
        branch=branch,
        commit_sha=commit_sha,
        status="pending"
    )
    db.add(scan_run)
    await db.commit()
    await db.refresh(scan_run)
    
    # Trigger scan in background
    background_tasks.add_task(
        execute_ci_scan,
        scan_run.id,
        ci_integration,
        pr_url,
        db
    )


async def handle_push(
    payload: Dict,
    ci_integration: CIIntegration,
    background_tasks: BackgroundTasks,
    db: AsyncSession
):
    """Handle push events to main/master branch"""
    
    ref = payload["ref"]
    if ref not in ["refs/heads/main", "refs/heads/master"]:
        return  # Only scan main branch pushes
    
    commit_sha = payload["after"]
    repo_url = payload["repository"]["html_url"]
    
    # Create scan run
    scan_run = CIScanRun(
        ci_integration_id=ci_integration.id,
        tenant_id=ci_integration.tenant_id,
        event_type="push",
        branch="main",
        commit_sha=commit_sha,
        status="pending"
    )
    db.add(scan_run)
    await db.commit()
    await db.refresh(scan_run)
    
    # Trigger scan
    background_tasks.add_task(
        execute_ci_scan,
        scan_run.id,
        ci_integration,
        repo_url,
        db
    )


async def execute_ci_scan(
    scan_run_id: str,
    ci_integration: CIIntegration,
    target_url: str,
    db: AsyncSession
):
    """Execute security scan for CI/CD"""
    
    try:
        # Update status
        scan_run = await db.get(CIScanRun, scan_run_id)
        scan_run.status = "running"
        scan_run.started_at = datetime.utcnow()
        await db.commit()
        
        # Trigger scan using orchestrator
        scan_result = await scan_orchestrator.execute_scan(
            tenant_id=ci_integration.tenant_id,
            scanner_type="web",  # Or parse from config
            target=target_url,
            options=ci_integration.scan_options or {}
        )
        
        # Update with results
        scan_run.status = "completed"
        scan_run.completed_at = datetime.utcnow()
        scan_run.scan_id = scan_result["scan_id"]
        scan_run.findings_summary = scan_result["summary"]
        await db.commit()
        
        # Post results to GitHub PR
        if scan_run.pr_number:
            await post_github_pr_comment(
                ci_integration,
                scan_run.pr_number,
                scan_result
            )
        
        # Check if should fail build
        if should_fail_build(scan_result, ci_integration):
            scan_run.status = "failed"
            await db.commit()
            
    except Exception as e:
        scan_run.status = "error"
        scan_run.error_message = str(e)
        await db.commit()


def should_fail_build(scan_result: Dict, ci_integration: CIIntegration) -> bool:
    """Determine if build should fail based on findings"""
    
    fail_on = ci_integration.fail_on_severity or []
    summary = scan_result.get("summary", {})
    
    if "critical" in fail_on and summary.get("critical", 0) > 0:
        return True
    if "high" in fail_on and summary.get("high", 0) > 0:
        return True
    
    return False


async def post_github_pr_comment(
    ci_integration: CIIntegration,
    pr_number: int,
    scan_result: Dict
):
    """Post scan results as PR comment"""
    
    import httpx
    
    summary = scan_result.get("summary", {})
    
    comment = f"""## 🔒 ForgeScan Security Report

**Scan Status:** ✅ Complete

### Findings Summary
- 🔴 Critical: {summary.get('critical', 0)}
- 🟠 High: {summary.get('high', 0)}
- 🟡 Medium: {summary.get('medium', 0)}
- 🟢 Low: {summary.get('low', 0)}

[📊 View Full Report]({settings.FRONTEND_URL}/scans/{scan_result['scan_id']})

---
*Powered by [ForgeScan](https://forgescan.com)*
"""
    
    # Post using GitHub API
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"https://api.github.com/repos/{ci_integration.repo_full_name}/issues/{pr_number}/comments",
            headers={
                "Authorization": f"Bearer {ci_integration.github_token}",
                "Accept": "application/vnd.github.v3+json"
            },
            json={"body": comment}
        )
    
    return response.status_code == 201


@router.post("/setup")
async def setup_github_integration(
    repo_full_name: str,
    github_token: str,
    scanner_types: list[str] = ["web", "api", "sca"],
    fail_on_severity: list[str] = ["critical"],
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Setup GitHub integration for a repository"""
    
    ci_integration = CIIntegration(
        tenant_id=current_user.tenant_id,
        provider="github",
        repo_full_name=repo_full_name,
        github_token=github_token,
        scanner_types=scanner_types,
        fail_on_severity=fail_on_severity,
        enabled=True
    )
    
    db.add(ci_integration)
    await db.commit()
    await db.refresh(ci_integration)
    
    # Generate webhook URL
    webhook_url = f"{settings.API_URL}/api/v1/integrations/github/webhook"
    
    return {
        "id": ci_integration.id,
        "webhook_url": webhook_url,
        "webhook_secret": settings.GITHUB_WEBHOOK_SECRET,
        "instructions": """
        1. Go to your repository settings
        2. Navigate to Webhooks
        3. Click 'Add webhook'
        4. Set Payload URL to: {webhook_url}
        5. Set Content type to: application/json
        6. Set Secret to: {webhook_secret}
        7. Select events: Pull requests, Pushes
        8. Click 'Add webhook'
        """
    }


@router.get("/runs")
async def get_ci_runs(
    limit: int = 20,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get recent CI scan runs"""
    
    stmt = select(CIScanRun).where(
        CIScanRun.tenant_id == current_user.tenant_id
    ).order_by(CIScanRun.created_at.desc()).limit(limit)
    
    result = await db.execute(stmt)
    runs = result.scalars().all()
    
    return [
        {
            "id": run.id,
            "event_type": run.event_type,
            "branch": run.branch,
            "status": run.status,
            "pr_number": run.pr_number,
            "findings_summary": run.findings_summary,
            "created_at": run.created_at,
            "completed_at": run.completed_at
        }
        for run in runs
    ]

