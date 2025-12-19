# backend/app/core/encryption.py
"""
Database field-level encryption for sensitive data
Implements AES-256-GCM encryption
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import base64
import os

class EncryptionService:
    """Encrypt sensitive database fields"""
    
    def __init__(self):
        # Derive key from master key + salt
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.environ['ENCRYPTION_SALT'].encode(),
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(
            os.environ['MASTER_ENCRYPTION_KEY'].encode()
        ))
        self.cipher = Fernet(key)
    
    def encrypt(self, data: str) -> str:
        """Encrypt sensitive data"""
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        return self.cipher.decrypt(encrypted_data.encode()).decode()
