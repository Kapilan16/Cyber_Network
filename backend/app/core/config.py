"""
Application settings loaded from environment / .env file via Pydantic-Settings.
"""
from typing import List, Literal

from pydantic import Field, ValidationInfo, field_validator
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
    AI_API_URL: str = "https://api.openai.com/v1/chat/completions"
    AI_MODEL: str = "gpt-4o-mini"
    AI_REQUEST_TIMEOUT_SECONDS: float = Field(default=30.0, gt=0)

    # ── Embeddings API (OpenAI-compatible) ────────────────────────────────
    # Used by the optional OpenAI-compatible provider. Local embeddings are default.
    EMBEDDINGS_API_KEY: str = ""
    EMBEDDINGS_API_URL: str = "https://api.openai.com/v1/embeddings"
    EMBEDDINGS_MODEL:   str = "text-embedding-ada-002"
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    VIRUSTOTAL_MIN_INTERVAL_SECONDS: float = Field(default=15.0, ge=0)
    ABUSEIPDB_MIN_INTERVAL_SECONDS: float = Field(default=86.4, ge=0)
    ENRICHMENT_TIMEOUT_SECONDS: float = Field(default=8.0, gt=0)
    ENRICHMENT_MAX_RETRIES: int = Field(default=2, ge=0, le=5)
    RISK_WEIGHT_RULE_SEVERITY: float = Field(default=0.4, ge=0)
    RISK_WEIGHT_RECURRENCE: float = Field(default=0.3, ge=0)
    RISK_WEIGHT_ENRICHMENT: float = Field(default=0.3, ge=0)
    RISK_RECURRENCE_SIMILARITY_THRESHOLD: float = Field(default=0.85, ge=0, le=1)
    RISK_RECURRENCE_MAX_MATCHES: int = Field(default=5, gt=0)
    RISK_NETWORK_RECURRENCE_MULTIPLIER: float = Field(default=2.0, ge=0)
    EMBEDDING_PROVIDER: Literal[
        "local_sentence_transformers",
        "openai_compatible",
        "feature_hash",
    ] = "local_sentence_transformers"
    LOCAL_EMBEDDING_MODEL: str = "sentence-transformers/all-MiniLM-L6-v2"
    VECTOR_DIM:         Literal[1536] = 1536  # MiniLM's 384 values are zero-padded
    CORRELATION_SIMILARITY_THRESHOLD: float = 0.85
    CORRELATION_WINDOW_DAYS: int = 30
    CAMPAIGN_SCAN_INTERVAL_SECONDS: int = Field(default=300, gt=0)
    WARNING_WINDOW_HOURS: int = Field(default=24, gt=0)
    WARNING_THRESHOLD: int = Field(default=3, gt=0)
    WARNING_SCAN_INTERVAL_SECONDS: int = Field(default=300, gt=0)
    FAISS_REBUILD_INTERVAL_SECONDS: int = Field(default=86_400, gt=0)
    ENVIRONMENT: str = "development"
    CENTRAL_SERVER_URL: str = ""
    CENTRAL_API_KEY: str = ""
    CENTRAL_ADMIN_TOKEN: str = "local-dev-admin-token-change-me"
    CENTRAL_TIMEOUT_SECONDS: float = Field(default=3.0, gt=0)
    CENTRAL_MAX_RETRIES: int = Field(default=2, ge=0, le=5)
    CENTRAL_RETRY_BACKOFF_SECONDS: float = Field(default=0.25, ge=0)
    CENTRAL_CIRCUIT_FAILURE_THRESHOLD: int = Field(default=3, gt=0)
    CENTRAL_CIRCUIT_COOLDOWN_SECONDS: float = Field(default=30.0, gt=0)
    SHARING_INTERNAL_RANGES: List[str] = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ]
    SHARING_INTERNAL_HOSTNAMES: List[str] = []
    SHARING_INTERNAL_USERNAMES: List[str] = []

    # ── App ───────────────────────────────────────────────────────────────
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

    @field_validator(
        "SHARING_INTERNAL_RANGES",
        "SHARING_INTERNAL_HOSTNAMES",
        "SHARING_INTERNAL_USERNAMES",
        mode="before",
    )
    @classmethod
    def parse_sharing_lists(cls, value):
        if isinstance(value, str):
            import json as _json
            # pydantic-settings v2 may hand us a JSON-encoded list if the env
            # var was set with square brackets; fall back to comma-splitting.
            stripped = value.strip()
            if stripped.startswith("["):
                try:
                    parsed = _json.loads(stripped)
                    if isinstance(parsed, list):
                        return [str(i).strip() for i in parsed if str(i).strip()]
                except _json.JSONDecodeError:
                    pass
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("CENTRAL_SERVER_URL")
    @classmethod
    def require_https_outside_development(
        cls,
        value: str,
        info: ValidationInfo,
    ) -> str:
        value = value.strip().rstrip("/")
        if not value:
            return value
        if info.data.get("ENVIRONMENT", "development").lower() not in {
            "development",
            "dev",
            "test",
        } and not value.lower().startswith("https://"):
            raise ValueError("CENTRAL_SERVER_URL must use HTTPS outside development")
        if not value.lower().startswith(("http://", "https://")):
            raise ValueError("CENTRAL_SERVER_URL must be an absolute HTTP(S) URL")
        return value


settings = Settings()
