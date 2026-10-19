"""Configuration for the isolated central registry service."""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator
from typing import Literal


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    CENTRAL_DATABASE_URL: str = (
        "postgresql+psycopg2://centraluser:centralpass@localhost:5433/centraldb"
    )
    CENTRAL_SIGNING_SECRET: str = (
        "local-dev-signing-secret-change-me-before-deployment"
    )
    CENTRAL_ADMIN_TOKEN: str = "local-dev-admin-token-change-me"
    CENTRAL_RATE_LIMIT_REQUESTS: int = Field(default=60, gt=0)
    CENTRAL_RATE_LIMIT_WINDOW_SECONDS: int = Field(default=60, gt=0)
    CENTRAL_VECTOR_DIM: Literal[1536] = 1536
    CENTRAL_ALLOW_READ_WITHOUT_CONTRIBUTION: bool = True
    FAISS_REBUILD_INTERVAL_SECONDS: int = Field(default=86_400, gt=0)
    EMBEDDING_PROVIDER: Literal[
        "local_sentence_transformers",
        "openai_compatible",
        "feature_hash",
    ] = "local_sentence_transformers"
    LOCAL_EMBEDDING_MODEL: str = "sentence-transformers/all-MiniLM-L6-v2"
    EMBEDDINGS_API_KEY: str = ""
    EMBEDDINGS_API_URL: str = "https://api.openai.com/v1/embeddings"
    EMBEDDINGS_MODEL: str = "text-embedding-ada-002"

    @field_validator("CENTRAL_VECTOR_DIM", mode="before")
    @classmethod
    def parse_central_vector_dim(cls, value: object) -> object:
        if isinstance(value, str):
            return int(value)
        return value


settings = Settings()
