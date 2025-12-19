# backend/app/core/secrets.py
"""
Integrate with HashiCorp Vault or AWS Secrets Manager
NEVER store secrets in .env files in production
"""

import hvac
import os

class SecretsManager:
    """Fetch secrets from Vault"""
    
    def __init__(self):
        self.client = hvac.Client(
            url=os.environ['VAULT_ADDR'],
            token=os.environ['VAULT_TOKEN']
        )
    
    def get_secret(self, path: str) -> dict:
        """Retrieve secret from Vault"""
        secret = self.client.secrets.kv.v2.read_secret_version(
            path=path,
            mount_point='forgescan'
        )
        return secret['data']['data']
    
    def get_db_credentials(self):
        """Get database credentials"""
        return self.get_secret('database/postgres')
    
    def get_api_key(self, service: str):
        """Get third-party API keys"""
        return self.get_secret(f'api-keys/{service}')

# Use in application
secrets = SecretsManager()
DATABASE_URL = secrets.get_db_credentials()['connection_string']
OPENAI_API_KEY = secrets.get_api_key('openai')['key']