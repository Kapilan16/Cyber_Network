"""
Shared pytest fixtures for all backend tests.

Uses an in-memory SQLite database so tests run without a real Postgres instance.

SQLite compatibility:
- pgvector's Vector type is compiled as TEXT for the SQLite DDL so that
  Base.metadata.create_all() succeeds without the Postgres extension.
- The actual <=> cosine operator is never exercised in SQLite tests;
  run_vector_search() is mocked in test_semantic_search.py.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base, get_db
from app.main import app

# ── pgvector SQLite shim ──────────────────────────────────────────────────────
# Register a custom DDL compiler so that Vector(dim) renders as "TEXT" when
# SQLAlchemy generates CREATE TABLE for SQLite.  This must happen BEFORE the
# first call to Base.metadata.create_all().
try:
    from pgvector.sqlalchemy import Vector  # type: ignore[import]
    from sqlalchemy.ext.compiler import compiles  # type: ignore[import]

    @compiles(Vector, "sqlite")
    def _compile_vector_sqlite(type_, compiler, **kw):  # type: ignore[misc]
        return "TEXT"

except ImportError:  # pragma: no cover
    pass  # pgvector not installed — model already falls back to Text

# ── In-memory SQLite engine (no network needed) ───────────────────────────────
SQLITE_URL = "sqlite:///./test.db"

engine = create_engine(
    SQLITE_URL,
    connect_args={"check_same_thread": False},
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function", autouse=False)
def db_session():
    """Create all tables, yield a session, then drop everything."""
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db_session, monkeypatch):
    """TestClient with the DB dependency overridden to use SQLite."""

    def override_get_db():
        try:
            yield db_session
        finally:
            pass  # session lifecycle managed by db_session fixture

    async def skip_background_correlation(submission_id: int) -> None:
        """Keep integration tests isolated from the configured production DB."""
        return None

    monkeypatch.setattr(
        "app.api.v1.endpoints.submissions.correlate_submission_background",
        skip_background_correlation,
    )
    monkeypatch.setattr(
        "app.api.v1.endpoints.submissions.share_submission_background",
        skip_background_correlation,
    )
    app.state.testing_session_factory = TestingSessionLocal
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
    del app.state.testing_session_factory
