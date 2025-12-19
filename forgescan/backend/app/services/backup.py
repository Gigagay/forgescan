# backend/app/services/backup.py
"""
Automated backup and disaster recovery system
Implements 3-2-1 backup rule
"""

import subprocess
from datetime import datetime, timedelta
import boto3
import logging

class BackupService:
    """Automated backup system"""
    
    def __init__(self):
        self.s3 = boto3.client('s3')
        self.backup_bucket = os.environ['BACKUP_S3_BUCKET']
    
    async def backup_database(self):
        """Create encrypted database backup"""
        
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        backup_file = f"/tmp/forgescan_backup_{timestamp}.sql.gz"
        
        # Dump database
        subprocess.run([
            'pg_dump',
            '-h', os.environ['DB_HOST'],
            '-U', os.environ['DB_USER'],
            '-d', os.environ['DB_NAME'],
            '-F', 'c',  # Custom format (compressed)
            '-f', backup_file
        ], check=True)
        
        # Encrypt backup
        encrypted_file = await self._encrypt_file(backup_file)
        
        # Upload to S3
        s3_key = f"database_backups/{timestamp}/backup.sql.gz.encrypted"
        
        self.s3.upload_file(
            encrypted_file,
            self.backup_bucket,
            s3_key,
            ExtraArgs={
                'ServerSideEncryption': 'AES256',
                'StorageClass': 'STANDARD_IA'  # Infrequent access
            }
        )
        
        # Also backup to secondary location (3-2-1 rule)
        await self._backup_to_secondary_location(encrypted_file)
        
        # Record backup
        await self._record_backup(
            backup_type='database',
            s3_key=s3_key,
            size_bytes=os.path.getsize(encrypted_file)
        )
        
        # Cleanup local files
        os.remove(backup_file)
        os.remove(encrypted_file)
        
        logger.info(f"Database backup completed: {s3_key}")
    
    async def backup_file_storage(self):
        """Backup uploaded files and scan results"""
        
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        
        # Tar and compress files
        subprocess.run([
            'tar',
            '-czf',
            f'/tmp/files_backup_{timestamp}.tar.gz',
            '/app/uploads'
        ], check=True)
        
        # Encrypt and upload
        # Similar to database backup...
    
    async def restore_database(self, backup_key: str):
        """Restore database from backup"""
        
        # Download from S3
        backup_file = f"/tmp/restore_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.sql.gz.encrypted"
        
        self.s3.download_file(
            self.backup_bucket,
            backup_key,
            backup_file
        )
        
        # Decrypt
        decrypted_file = await self._decrypt_file(backup_file)
        
        # Restore to database
        subprocess.run([
            'pg_restore',
            '-h', os.environ['DB_HOST'],
            '-U', os.environ['DB_USER'],
            '-d', os.environ['DB_NAME'],
            '-c',  # Clean (drop) database objects before recreating
            decrypted_file
        ], check=True)
        
        logger.info(f"Database restored from: {backup_key}")
    
    async def cleanup_old_backups(self):
        """Delete backups older than retention period"""
        
        retention_days = 90
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        # List old backups
        response = self.s3.list_objects_v2(
            Bucket=self.backup_bucket,
            Prefix='database_backups/'
        )
        
        for obj in response.get('Contents', []):
            if obj['LastModified'].replace(tzinfo=None) < cutoff_date:
                self.s3.delete_object(
                    Bucket=self.backup_bucket,
                    Key=obj['Key']
                )
                logger.info(f"Deleted old backup: {obj['Key']}")
    
    async def _encrypt_file(self, filepath: str) -> str:
        """Encrypt file using GPG"""
        
        encrypted_file = f"{filepath}.encrypted"
        
        subprocess.run([
            'gpg',
            '--symmetric',
            '--cipher-algo', 'AES256',
            '--passphrase', os.environ['BACKUP_ENCRYPTION_KEY'],
            '--batch', '--yes',
            '--output', encrypted_file,
            filepath
        ], check=True)
        
        return encrypted_file
    
    async def test_backup_restoration(self):
        """Regularly test backup restoration"""
        
        # Get most recent backup
        response = self.s3.list_objects_v2(
            Bucket=self.backup_bucket,
            Prefix='database_backups/',
            MaxKeys=1
        )
        
        if not response.get('Contents'):
            raise Exception("No backups found")
        
        latest_backup = response['Contents'][0]['Key']
        
        # Restore to test database
        await self.restore_database_to_test_env(latest_backup)
        
        # Verify integrity
        is_valid = await self._verify_backup_integrity()
        
        if not is_valid:
            await self._alert_backup_failure()

# Celery task for automated backups
@celery_app.task
async def scheduled_backup():
    """Run automated backups"""
    
    backup_service = BackupService()
    
    # Daily database backup
    await backup_service.backup_database()
    
    # Weekly file backup
    if datetime.utcnow().weekday() == 0:  # Monday
        await backup_service.backup_file_storage()
    
    # Monthly backup test
    if datetime.utcnow().day == 1:
        await backup_service.test_backup_restoration()
    
    # Cleanup old backups
    await backup_service.cleanup_old_backups()

# Schedule backups
@celery_app.on_after_configure.connect
def setup_backup_tasks(sender, **kwargs):
    # Daily at 2 AM
    sender.add_periodic_task(
        crontab(hour=2, minute=0),
        scheduled_backup.s(),
        name='daily_backup'
    )