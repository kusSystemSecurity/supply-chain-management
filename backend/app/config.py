"""Application configuration"""
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings"""

    # Database
    database_url: str = "postgresql://user:password@localhost:5432/securechain"

    # Redis
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"

    # API Keys
    cvedetails_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None

    # Application
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    debug: bool = True

    # Security
    secret_key: str = "your-secret-key-change-in-production"

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
