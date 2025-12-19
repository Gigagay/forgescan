# backend/app/workers/scanner_worker.py
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional
from celery import Task

from app.workers.celery_app import celery_app
from app.core.logging import logger


class ScannerTask(Task):
    """Custom task class for scanner tasks"""
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Handle task failure"""
        logger.error(f"Scan task {task_id} failed: {exc}", exc_info=True)


@celery_app.task(bind=True, base=ScannerTask, name="execute_scan")
def execute_scan_task(
    self,
    scan_id: str,
    tenant_id: str,
    scanner_type: str,
    target: str,
    options: Optional[Dict[str, Any]] = None
):
    """Execute scan in background worker"""
    try:
        # Run async scan function
        result = asyncio.run(
            _execute_scan_async(scan_id, tenant_id, scanner_type, target, options)
        )
        return result
    except Exception as e:
        logger.error(f"Scan execution failed: {str(e)}", exc_info=True)
        # Update scan status to failed
        asyncio.run(_update_scan_failed(scan_id, tenant_id, str(e)))
        raise


async def _execute_scan_async(
    scan_id: str,
    tenant_id: str,
    scanner_type: str,
    target: str,
    options: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Async scan execution logic"""
    from app.db.database import async_session_local, set_tenant_context
    from app.db.repositories.scan_repository import ScanRepository
    from app.db.repositories.finding_repository import FindingRepository
    from app.scanners.plugin_manager import PluginManager
    from uuid import UUID
    
    async with async_session_local() as session:
        # Set tenant context
        await set_tenant_context(session, tenant_id)
        
        # Initialize repositories
        scan_repo = ScanRepository(session)
        finding_repo = FindingRepository(session)
        
        # Initialize plugin manager
        plugin_manager = PluginManager()
        await plugin_manager.initialize()
        
        try:
            # Update scan status to running
            scan = await scan_repo.get(UUID(scan_id))
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")
            
            await scan_repo.update(UUID(scan_id), {
                "status": "running",
                "started_at": datetime.utcnow(),
                "progress": 0,
            })
            await session.commit()
            
            # Get scanner plugin
            scanner = await plugin_manager.get_scanner(scanner_type, target)
            if not scanner:
                raise ValueError(f"No suitable scanner for {scanner_type}")
            
            # Execute scan
            result = await scanner.scan(
                target=target,
                scan_id=scan_id,
                tenant_id=tenant_id,
                options=options or {}
            )
            
            # Store findings
            for finding_data in result.findings:
                finding_data["scan_id"] = UUID(scan_id)
                finding_data["tenant_id"] = tenant_id
                await finding_repo.create(finding_data)
            
            await session.commit()
            
            # Update scan with results
            duration = (datetime.utcnow() - scan.started_at).total_seconds() if scan.started_at else 0
            
            await scan_repo.update(UUID(scan_id), {
                "status": "completed" if result.status == "completed" else "failed",
                "completed_at": datetime.utcnow(),
                "duration_seconds": int(duration),
                "findings_summary": result.summary,
                "risk_score": result.summary.get("risk_score"),
                "progress": 100,
                "error_message": result.error if result.error else None,
            })
            await session.commit()
            
            logger.info(f"Scan {scan_id} completed successfully")
            
            return {
                "scan_id": scan_id,
                "status": result.status,
                "findings_count": len(result.findings),
                "summary": result.summary,
            }
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}", exc_info=True)
            
            # Update scan status
            await scan_repo.update(UUID(scan_id), {
                "status": "failed",
                "completed_at": datetime.utcnow(),
                "error_message": str(e),
                "progress": 0,
            })
            await session.commit()
            
            raise
        
        finally:
            await plugin_manager.cleanup_all()
    # After scan completes successfully
    if result.status == "completed":
        # Send email notification
        email_service = EmailService()
        scan_url = f"{settings.FRONTEND_URL}/scans/{scan_id}"
        
        # Get user email
        user = await user_repo.get(scan.user_id)
        if user and user.email:
            await email_service.send_scan_complete_email(
                email=user.email,
                scan_target=target,
                findings_summary=result.summary,
                scan_url=scan_url
            )



async def _update_scan_failed(scan_id: str, tenant_id: str, error_message: str):
    """Update scan status to failed"""
    from app.db.database import async_session_local, set_tenant_context
    from app.db.repositories.scan_repository import ScanRepository
    from uuid import UUID
    
    async with async_session_local() as session:
        await set_tenant_context(session, tenant_id)
        
        scan_repo = ScanRepository(session)
        await scan_repo.update(UUID(scan_id), {
            "status": "failed",
            "completed_at": datetime.utcnow(),
            "error_message": error_message,
        })
        await session.commit()
        
