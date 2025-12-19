# backend/app/core/input_validation.py
"""
Input validation and sanitization
Prevents injection attacks and malformed data
"""

import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, validator, Field
import bleach
from urllib.parse import urlparse


class SecureBaseModel(BaseModel):
    """Base model with built-in security validations"""
    
    class Config:
        # Prevent extra fields
        extra = 'forbid'
        # Validate on assignment
        validate_assignment = True


class SecureString(str):
    """String with automatic XSS sanitization"""
    
    @classmethod
    def __get_validators__(cls):
        yield cls.validate
    
    @classmethod
    def validate(cls, v: str) -> str:
        """Sanitize HTML/XSS"""
        if not isinstance(v, str):
            raise TypeError('string required')
        
        # Remove all HTML tags and attributes
        clean = bleach.clean(v, tags=[], strip=True)
        
        # Remove null bytes
        clean = clean.replace('\x00', '')
        
        return cls(clean)


class SecureURL(str):
    """URL with validation and sanitization"""
    
    ALLOWED_SCHEMES = ['http', 'https']
    
    @classmethod
    def __get_validators__(cls):
        yield cls.validate
    
    @classmethod
    def validate(cls, v: str) -> str:
        """Validate URL format and scheme"""
        if not isinstance(v, str):
            raise TypeError('string required')
        
        try:
            parsed = urlparse(v)
            
            # Check scheme
            if parsed.scheme not in cls.ALLOWED_SCHEMES:
                raise ValueError(f'Invalid URL scheme. Allowed: {cls.ALLOWED_SCHEMES}')
            
            # Check for localhost/internal IPs (SSRF protection)
            if parsed.hostname:
                if parsed.hostname in ['localhost', '127.0.0.1', '0.0.0.0']:
                    raise ValueError('Internal URLs not allowed')
                
                # Check for private IP ranges
                if parsed.hostname.startswith(('10.', '172.', '192.168.')):
                    raise ValueError('Private IP addresses not allowed')
            
            return cls(v)
        
        except Exception as e:
            raise ValueError(f'Invalid URL: {str(e)}')


class InputValidator:
    """Centralized input validation"""
    
    # Regex patterns for common validations
    PATTERNS = {
        'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
        'phone': re.compile(r'^\+?[1-9]\d{1,14}$'),  # E.164 format
        'alphanumeric': re.compile(r'^[a-zA-Z0-9]+$'),
        'uuid': re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
        'domain': re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$'),
    }
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        return bool(InputValidator.PATTERNS['email'].match(email))
    
    @staticmethod
    def validate_password_strength(password: str) -> tuple[bool, List[str]]:
        """
        Validate password strength
        
        Requirements:
        - At least 12 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character
        - No common passwords
        """
        
        errors = []
        
        if len(password) < 12:
            errors.append("Password must be at least 12 characters")
        
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if not re.search(r'\d', password):
            errors.append("Password must contain at least one digit")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
        
        # Check against common passwords
        common_passwords = [
            'password', 'password123', '123456', 'qwerty', 'admin',
            'letmein', 'welcome', 'monkey', '1234567890'
        ]
        
        if password.lower() in common_passwords:
            errors.append("Password is too common")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent directory traversal"""
        
        # Remove directory separators
        filename = filename.replace('/', '').replace('\\', '')
        
        # Remove null bytes
        filename = filename.replace('\x00', '')
        
        # Remove leading dots
        filename = filename.lstrip('.')
        
        # Allow only alphanumeric, dash, underscore, and dot
        filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
        
        # Limit length
        if len(filename) > 255:
            name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
            filename = name[:250] + ('.' + ext if ext else '')
        
        return filename
    
    @staticmethod
    def validate_json_size(data: Dict, max_size_mb: int = 10) -> bool:
        """Validate JSON payload size"""
        import json
        
        size_bytes = len(json.dumps(data).encode('utf-8'))
        max_bytes = max_size_mb * 1024 * 1024
        
        return size_bytes <= max_bytes


# Usage in Pydantic models
class ScanCreateRequest(SecureBaseModel):
    """Secure scan creation request"""
    
    scanner_type: str = Field(..., regex='^(web|api|sca)$')
    target: SecureURL
    options: Optional[Dict] = Field(default={}, max_items=20)
    
    @validator('options')
    def validate_options_size(cls, v):
        """Ensure options aren't too large"""
        if not InputValidator.validate_json_size(v, max_size_mb=1):
            raise ValueError('Options payload too large')
        return v
