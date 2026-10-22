"""SQLAlchemy async engine and session factory (placeholder — wired but unused until models are added)."""
import socket
from urllib.parse import urlparse

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import settings


def _resolve_database_url() -> str:
    """Use SQLite in local dev when PostgreSQL is not running.

    This keeps the app usable in workstations without Docker/Postgres while
    preserving the normal Postgres path when the database is available.
    """
    database_url = settings.DATABASE_URL
    env_name = (settings.ENVIRONMENT or "development").lower()
    if env_name not in {"development", "dev", "test"}:
        return database_url

    try:
        parsed = urlparse(database_url)
    except Exception:
        return database_url

    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"postgresql", "postgresql+psycopg2"} or host not in {"localhost", "127.0.0.1", "::1"}:
        return database_url

    port = parsed.port or 5432
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return database_url
    except OSError:
        return "sqlite:///./dev.db"


engine = create_engine(
    _resolve_database_url(),
    pool_pre_ping=True,
    echo=(settings.ENVIRONMENT == "development"),
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""
    pass


def get_db():
    """FastAPI dependency: yields a database session, always closes on exit."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
