from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Application
    APP_NAME: str = "ThreatLens"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = True

    # Database
    DATABASE_URL: str = "sqlite:///./threatlens.db"

    # Redis / Celery
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"

    # Security
    SECRET_KEY: str = "CHANGE-THIS-IN-PRODUCTION-USE-A-STRONG-RANDOM-KEY"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Evidence storage
    EVIDENCE_STORE_PATH: str = "./evidence_store"

    # Feature flags
    ENABLE_DYNAMIC_SCANNING: bool = False
    ENABLE_AI_TRIAGE: bool = False


settings = Settings()
