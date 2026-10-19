"""Central registry database and session dependency."""
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import settings

engine = create_engine(settings.CENTRAL_DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Base for central-service ORM models."""


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
