# backend/app/core/secrets_manager.py
"""
Production secrets management with HashiCorp Vault
Alternative: AWS Secrets Manager
"""

import hvac
import boto3
import os
from typing import Dict, Optional
from functools import lru_cache
import logging

logger = logging.getLogger(__name__)


class SecretsManager:
    """
    Unified secrets management interface
    Supports: HashiCorp Vault, AWS Secrets Manager, Environment Variables
    """
    
    def __init__(self):
        self.provider = os.getenv('SECRETS_PROVIDER', 'vault')  # vault, aws, env
        
        if self.provider == 'vault':
            self.client = self._init_vault()
        elif self.provider == 'aws':
            self.client = self._init_aws()
        else:
            self.client = None
    
    def _init_vault(self) -> hvac.Client:
        """Initialize HashiCorp Vault client"""
        
        client = hvac.Client(
            url=os.getenv('VAULT_ADDR', 'http://localhost:8200'),
            token=os.getenv('VAULT_TOKEN')
        )
        
        if not client.is_authenticated():
            raise Exception("Vault authentication failed")
        
        logger.info("Connected to HashiCorp Vault")
        return client
    
    def _init_aws(self):
        """Initialize AWS Secrets Manager client"""
        
        return boto3.client(
            'secretsmanager',
            region_name=os.getenv('AWS_REGION', 'us-east-1')
        )
    
    @lru_cache(maxsize=100)
    def get_secret(self, key: str) -> Optional[str]:
        """
        Get secret by key
        Caches results to avoid repeated API calls
        """
        
        try:
            if self.provider == 'vault':
                return self._get_vault_secret(key)
            elif self.provider == 'aws':
                return self._get_aws_secret(key)
            else:
                return os.getenv(key)
        
        except Exception as e:
            logger.error(f"Failed to retrieve secret {key}: {e}")
            return None
    
    def _get_vault_secret(self, key: str) -> str:
        """Get secret from Vault"""
        
        # Parse key format: "path/to/secret:field"
        if ':' in key:
            path, field = key.rsplit(':', 1)
        else:
            path, field = key, 'value'
        
        secret = self.client.secrets.kv.v2.read_secret_version(
            path=path,
            mount_point='forgescan'
        )
        
        return secret['data']['data'][field]
    
    def _get_aws_secret(self, key: str) -> str:
        """Get secret from AWS Secrets Manager"""
        
        response = self.client.get_secret_value(SecretId=key)
        
        if 'SecretString' in response:
            return response['SecretString']
        else:
            return base64.b64decode(response['SecretBinary'])
    
    def set_secret(self, key: str, value: str) -> bool:
        """Store secret"""
        
        try:
            if self.provider == 'vault':
                path, field = key.rsplit(':', 1) if ':' in key else (key, 'value')
                
                self.client.secrets.kv.v2.create_or_update_secret(
                    path=path,
                    secret={field: value},
                    mount_point='forgescan'
                )
                
                return True
            
            elif self.provider == 'aws':
                self.client.create_secret(
                    Name=key,
                    SecretString=value
                )
                return True
            
            return False
        
        except Exception as e:
            logger.error(f"Failed to set secret {key}: {e}")
            return False
    
    def rotate_secret(self, key: str, new_value: str) -> bool:
        """
        Rotate secret with zero-downtime
        Old value remains accessible for grace period
        """
        
        # Store new value with version suffix
        versioned_key = f"{key}_v{int(time.time())}"
        
        if self.set_secret(versioned_key, new_value):
            # Update primary key to point to new version
            self.set_secret(key, new_value)
            
            logger.info(f"Secret {key} rotated successfully")
            return True
        
        return False


# Singleton instance
secrets_manager = SecretsManager()


# Usage in application
def get_database_url() -> str:
    """Get database URL from secrets manager"""
    return secrets_manager.get_secret('database/postgres:connection_string')


def get_api_key(service: str) -> str:
    """Get third-party API key"""
    return secrets_manager.get_secret(f'api-keys/{service}:key')

