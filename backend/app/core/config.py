import os
from pathlib import Path
from typing import Optional

FALLBACK_SQLITE_URL = "sqlite:///./threat_platform.db"

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
    class Settings(BaseSettings):
        PROJECT_NAME: str = "Cross-Layer Threat Detection & Attribution Platform"
        API_V1_STR: str = "/api/v1"
        SECRET_KEY: str = os.getenv("SECRET_KEY", "change-this-in-production-super-secret-key-12345")

        POSTGRES_SERVER: str = os.getenv("POSTGRES_SERVER", "localhost")
        POSTGRES_PORT: int = int(os.getenv("POSTGRES_PORT", "5432"))
        POSTGRES_USER: str = os.getenv("POSTGRES_USER", "postgres")
        POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "postgres")
        POSTGRES_DB: str = os.getenv("POSTGRES_DB", "threat_platform")

        BACKEND_HOST: str = os.getenv("BACKEND_HOST", "0.0.0.0")
        BACKEND_PORT: int = int(os.getenv("BACKEND_PORT", "8000"))

        DATABASE_URL: Optional[str] = None
        FALLBACK_DATABASE_URL: str = FALLBACK_SQLITE_URL

        @property
        def EFFECTIVE_DATABASE_URL(self) -> str:
            if self.DATABASE_URL:
                return self.DATABASE_URL
            env_url = os.getenv("DATABASE_URL")
            if env_url:
                return env_url
            return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"

        model_config = SettingsConfigDict(
            env_file=(".env", "backend/.env", "../.env"),
            env_file_encoding="utf-8",
            extra="ignore",
        )

except ImportError:
    from pydantic import BaseModel
    class Settings(BaseModel):
        PROJECT_NAME: str = "Cross-Layer Threat Detection & Attribution Platform"
        API_V1_STR: str = "/api/v1"
        SECRET_KEY: str = os.getenv("SECRET_KEY", "change-this-in-production-super-secret-key-12345")

        POSTGRES_SERVER: str = os.getenv("POSTGRES_SERVER", "localhost")
        POSTGRES_PORT: int = int(os.getenv("POSTGRES_PORT", "5432"))
        POSTGRES_USER: str = os.getenv("POSTGRES_USER", "postgres")
        POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "postgres")
        POSTGRES_DB: str = os.getenv("POSTGRES_DB", "threat_platform")

        BACKEND_HOST: str = os.getenv("BACKEND_HOST", "0.0.0.0")
        BACKEND_PORT: int = int(os.getenv("BACKEND_PORT", "8000"))

        DATABASE_URL: Optional[str] = None
        FALLBACK_DATABASE_URL: str = FALLBACK_SQLITE_URL

        @property
        def EFFECTIVE_DATABASE_URL(self) -> str:
            if self.DATABASE_URL:
                return self.DATABASE_URL
            env_url = os.getenv("DATABASE_URL")
            if env_url:
                return env_url
            return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"

settings = Settings()
if not settings.DATABASE_URL:
    settings.DATABASE_URL = settings.EFFECTIVE_DATABASE_URL

