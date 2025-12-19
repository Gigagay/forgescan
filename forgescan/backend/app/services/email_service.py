# backend/app/services/email_service.py
from typing import List, Dict, Any
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import aiosmtplib
from jinja2 import Template

from app.core.config import settings
from app.core.logging import logger


class EmailService:
    """Service for sending emails"""
    
    def __init__(self):
        self.smtp_host = settings.SMTP_HOST
        self.smtp_port = settings.SMTP_PORT
        self.smtp_user = settings.SMTP_USER
        self.smtp_password = settings.SMTP_PASSWORD
        self.from_email = settings.FROM_EMAIL
    
    async def send_email(
        self,
        to: List[str],
        subject: str,
        html_content: str,
        text_content: str = None
    ):
        """Send an email"""
        if not self.smtp_host:
            logger.warning("SMTP not configured, skipping email")
            return
        
        try:
            message = MIMEMultipart('alternative')
            message['Subject'] = subject
            message['From'] = self.from_email
            message['To'] = ', '.join(to)
            
            if text_content:
                message.attach(MIMEText(text_content, 'plain'))
            
            message.attach(MIMEText(html_content, 'html'))
            
            await aiosmtplib.send(
                message,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_user,
                password=self.smtp_password,
                start_tls=True,
            )
            
            logger.info(f"Email sent to {to}: {subject}")
            
        except Exception as e:
            logger.error(f"Failed to send email: {str(e)}")
    
    async def send_welcome_email(self, email: str, name: str):
        """Send welcome email to new users"""
        subject = "Welcome to ForgeScan!"
        
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                          color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
                .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }
                .button { display: inline-block; padding: 12px 24px; background: #667eea; 
                         color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
                .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Welcome to ForgeScan!</h1>
                </div>
                <div class="content">
                    <h2>Hi {{ name }},</h2>
                    <p>Thank you for signing up! We're excited to help you secure your applications.</p>
                    
                    <h3>Get Started:</h3>
                    <ol>
                        <li>Run your first security scan</li>
                        <li>Review the findings</li>
                        <li>Follow remediation steps</li>
                    </ol>
                    
                    <a href="{{ dashboard_url }}" class="button">Go to Dashboard</a>
                    
                    <h3>Resources:</h3>
                    <ul>
                        <li><a href="{{ docs_url }}">Documentation</a></li>
                        <li><a href="{{ api_docs_url }}">API Reference</a></li>
                        <li><a href="{{ support_url }}">Support</a></li>
                    </ul>
                    
                    <p>If you have any questions, just reply to this email!</p>
                    
                    <p>Happy scanning!<br>The ForgeScan Team</p>
                </div>
                <div class="footer">
                    <p>© 2025 ForgeScan. All rights reserved.</p>
                    <p><a href="{{ unsubscribe_url }}">Unsubscribe</a></p>
                </div>
            </div>
        </body>
        </html>
        """
        
        template = Template(html_template)
        html_content = template.render(
            name=name or 'there',
            dashboard_url=f"{settings.FRONTEND_URL}/dashboard",
            docs_url="https://docs.forgescan.io",
            api_docs_url=f"{settings.BACKEND_URL}/docs",
            support_url="mailto:support@forgescan.io",
            unsubscribe_url=f"{settings.FRONTEND_URL}/unsubscribe",
        )
        
        await self.send_email([email], subject, html_content)
    
    async def send_scan_complete_email(
        self,
        email: str,
        scan_target: str,
        findings_summary: Dict[str, Any],
        scan_url: str
    ):
        """Send email when scan completes"""
        critical_count = findings_summary.get('critical_count', 0)
        high_count = findings_summary.get('high_count', 0)
        
        subject = f"Scan Complete: {scan_target}"
        if critical_count > 0:
            subject = f"🚨 {critical_count} Critical Issues - " + subject
        
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: #667eea; color: white; padding: 20px; text-align: center; }
                .content { background: #f9f9f9; padding: 30px; }
                .findings { display: flex; gap: 10px; justify-content: space-around; margin: 20px 0; }
                .finding-box { text-align: center; padding: 15px; border-radius: 8px; }
                .critical { background: #ffebee; color: #c62828; }
                .high { background: #fff3e0; color: #e65100; }
                .medium { background: #e3f2fd; color: #1565c0; }
                .low { background: #e8f5e9; color: #2e7d32; }
                .button { display: inline-block; padding: 12px 24px; background: #667eea; 
                         color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Security Scan Complete</h1>
                </div>
                <div class="content">
                    <h2>{{ target }}</h2>
                    <p>Your security scan has completed. Here's what we found:</p>
                    
                    <div class="findings">
                        <div class="finding-box critical">
                            <h3>{{ critical_count }}</h3>
                            <p>Critical</p>
                        </div>
                        <div class="finding-box high">
                            <h3>{{ high_count }}</h3>
                            <p>High</p>
                        </div>
                        <div class="finding-box medium">
                            <h3>{{ medium_count }}</h3>
                            <p>Medium</p>
                        </div>
                        <div class="finding-box low">
                            <h3>{{ low_count }}</h3>
                            <p>Low</p>
                        </div>
                    </div>
                    
                    {% if critical_count > 0 %}
                    <p style="color: #c62828; font-weight: bold;">
                        ⚠️ {{ critical_count }} critical issue(s) require immediate attention!
                    </p>
                    {% endif %}
                    
                    <a href="{{ scan_url }}" class="button">View Full Report</a>
                    
                    <p style="margin-top: 30px;">
                        <small>Risk Score: {{ risk_score }}/100</small>
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        
        template = Template(html_template)
        html_content = template.render(
            target=scan_target,
            critical_count=critical_count,
            high_count=findings_summary.get('high_count', 0),
            medium_count=findings_summary.get('medium_count', 0),
            low_count=findings_summary.get('low_count', 0),
            risk_score=findings_summary.get('risk_score', 0),
            scan_url=scan_url,
        )
        
        await self.send_email([email], subject, html_content)