# backend/app/services/security_monitor.py
"""
Real-time security monitoring and alerting
Detects anomalies and suspicious behavior
"""

from datetime import datetime, timedelta
from typing import Dict, List
import asyncio

class SecurityMonitor:
    """Monitor and detect security threats in real-time"""
    
    def __init__(self):
        self.redis = redis.Redis()
        self.alert_thresholds = {
            'failed_logins': 5,  # per 10 minutes
            'api_errors': 50,     # per minute
            'permission_denials': 10,  # per hour
            'data_exports': 5,    # per day
        }
    
    async def track_failed_login(self, user_email: str, ip_address: str):
        """Track failed login attempts"""
        
        key = f"failed_login:{ip_address}"
        count = self.redis.incr(key)
        self.redis.expire(key, 600)  # 10 minutes
        
        if count >= self.alert_thresholds['failed_logins']:
            await self._trigger_alert(
                severity="high",
                alert_type="brute_force_attempt",
                details={
                    "ip_address": ip_address,
                    "user_email": user_email,
                    "attempts": count
                }
            )
            
            # Auto-block IP
            await self._block_ip(ip_address, duration=3600)
    
    async def detect_anomaly(self, user_id: UUID, action: str):
        """Detect unusual user behavior"""
        
        # Get user's normal behavior pattern
        normal_pattern = await self._get_user_pattern(user_id)
        
        # Check for anomalies
        if self._is_anomalous(action, normal_pattern):
            await self._trigger_alert(
                severity="medium",
                alert_type="anomalous_behavior",
                details={
                    "user_id": str(user_id),
                    "action": action,
                    "reason": "Unusual activity pattern detected"
                }
            )
    
    async def monitor_data_access(
        self,
        user_id: UUID,
        resource_type: str,
        resource_id: UUID,
        action: str
    ):
        """Monitor sensitive data access"""
        
        # Track data access patterns
        key = f"data_access:{user_id}:{resource_type}"
        
        access_log = {
            "timestamp": datetime.utcnow().isoformat(),
            "resource_id": str(resource_id),
            "action": action
        }
        
        self.redis.lpush(key, json.dumps(access_log))
        self.redis.ltrim(key, 0, 99)  # Keep last 100 entries
        
        # Check for mass data access
        recent_count = self.redis.llen(key)
        if recent_count > 50:  # 50 accesses in short period
            await self._trigger_alert(
                severity="critical",
                alert_type="potential_data_exfiltration",
                details={
                    "user_id": str(user_id),
                    "resource_type": resource_type,
                    "access_count": recent_count
                }
            )
    
    async def _trigger_alert(
        self,
        severity: str,
        alert_type: str,
        details: Dict
    ):
        """Trigger security alert"""
        
        alert = SecurityAlert(
            severity=severity,
            alert_type=alert_type,
            details=details,
            timestamp=datetime.utcnow(),
            status="open"
        )
        
        # Save to database
        async with get_db() as db:
            db.add(alert)
            await db.commit()
        
        # Send notifications
        if severity in ["high", "critical"]:
            await self._notify_security_team(alert)
            
            # Send to Slack/PagerDuty
            await SlackService().send_security_alert(alert)
    
    async def _notify_security_team(self, alert: SecurityAlert):
        """Notify security team of critical alerts"""
        
        # Email security team
        security_emails = await self._get_security_team_emails()
        
        for email in security_emails:
            await send_email(
                to=email,
                subject=f"🚨 Security Alert: {alert.alert_type}",
                body=f"""
                Severity: {alert.severity.upper()}
                Type: {alert.alert_type}
                Time: {alert.timestamp}
                
                Details:
                {json.dumps(alert.details, indent=2)}
                
                Action Required: Review immediately in ForgeScan dashboard
                """
            )
    
    async def _block_ip(self, ip_address: str, duration: int):
        """Temporarily block IP address"""
        
        key = f"blocked_ip:{ip_address}"
        self.redis.setex(key, duration, "1")
        
        # Log the block
        logger.warning(f"IP blocked: {ip_address} for {duration}s")

# Database model
class SecurityAlert(Base):
    """Security alerts and incidents"""
    __tablename__ = "security_alerts"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    severity = Column(String(20))  # low, medium, high, critical
    alert_type = Column(String(100))
    details = Column(JSON)
    status = Column(String(20), default="open")  # open, investigating, resolved, false_positive
    
    assigned_to = Column(UUID, ForeignKey('users.id'))
    resolved_at = Column(DateTime)
    resolution_notes = Column(Text)
    
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

# Background task to monitor continuously
@celery_app.task
async def continuous_security_monitoring():
    """Run continuous security monitoring"""
    
    monitor = SecurityMonitor()
    
    while True:
        # Check for suspicious patterns
        await monitor.check_suspicious_activity()
        
        # Check for compromised accounts
        await monitor.check_compromised_accounts()
        
        # Monitor system health
        await monitor.check_system_health()
        
        await asyncio.sleep(60)  # Check every minute