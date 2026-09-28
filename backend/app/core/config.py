"""
Application settings loaded from environment / .env file via Pydantic-Settings.
"""
from typing import List

from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # ── Database ──────────────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+psycopg2://cyberuser:cyberpass@localhost:5432/cyberdb"

    # ── Security ──────────────────────────────────────────────────────────
    JWT_SECRET: str = "dev-secret-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days

    # ── AI / External APIs ────────────────────────────────────────────────
    AI_API_KEY: str = ""

    # ── Embeddings API (OpenAI-compatible) ────────────────────────────────
    # Set EMBEDDINGS_API_KEY to enable; leave empty to disable embedding
    # generation (submissions will be stored with embedding_status="failed").
    EMBEDDINGS_API_KEY: str = ""
    EMBEDDINGS_API_URL: str = "https://api.openai.com/v1/embeddings"
    EMBEDDINGS_MODEL:   str = "text-embedding-ada-002"
    VECTOR_DIM:         int = 1536   # must match the chosen model's output dim

    # ── App ───────────────────────────────────────────────────────────────
    ENVIRONMENT: str = "development"
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000"]

    # ── Sanitization pipeline ─────────────────────────────────────────────
    MAX_SUBMISSION_LENGTH: int = 50_000   # chars; truncated before storage
    REDACT_PII: bool = True               # redact email addresses

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors(cls, value):
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",")]
        return value


settings = Settings()
