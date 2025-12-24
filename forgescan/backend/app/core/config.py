# backend/app/core/config.py
from typing import List, Optional
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import AnyHttpUrl, validator, ConfigDict

# Locate the .env file relative to the project root
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent  # Goes to forgescan root
ENV_FILE = BASE_DIR / ".env"


class Settings(BaseSettings):
    model_config = ConfigDict(env_file=str(ENV_FILE), extra="ignore")

    
    # Application
    PROJECT_NAME: str = "ForgeScan"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    
    # Security
    SECRET_KEY: str
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    
    # Database
    DATABASE_URL: str
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 10
    
    # Redis
    REDIS_URL: str
    
    # Celery
    CELERY_BROKER_URL: str
    CELERY_RESULT_BACKEND: str
    
    # CORS
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []
    ALLOWED_HOSTS: List[str] = ["*"]
    
    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v):
        if isinstance(v, str):
            return [i.strip() for i in v.split(",")]
        return v
    
    # OAuth2 Providers
    GOOGLE_CLIENT_ID: Optional[str] = None
    GOOGLE_CLIENT_SECRET: Optional[str] = None
    GITHUB_CLIENT_ID: Optional[str] = None
    GITHUB_CLIENT_SECRET: Optional[str] = None
    
    # Email
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    FROM_EMAIL: str = "noreply@forgescan.io"
    
    # Peach Payments
    PEACH_ENTITY_ID: Optional[str] = None
    PEACH_ACCESS_TOKEN: Optional[str] = None
    PEACH_WEBHOOK_SECRET: Optional[str] = None
    PEACH_BASE_URL: str = "https://eu-prod.oppwa.com"  # or https://test.oppwa.com for testing
    PEACH_TEST_MODE: bool = False

    
    # Scanner Configuration
    ZAP_API_KEY: Optional[str] = None
    ZAP_PROXY_URL: str = "http://zap:8080"
    SCAN_TIMEOUT_SECONDS: int = 3600
    MAX_CONCURRENT_SCANS: int = 5
    
    # Storage (Backblaze B2)
    S3_BUCKET: Optional[str] = None
    S3_ACCESS_KEY: Optional[str] = None
    S3_SECRET_KEY: Optional[str] = None
    S3_ENDPOINT: Optional[str] = None
    
    # Monitoring
    SENTRY_DSN: Optional[str] = None
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    
    # URL
    FRONTEND_URL: str = "http://localhost:3000"
    BACKEND_URL: str = "http://localhost:8000"


settings = Settings()
