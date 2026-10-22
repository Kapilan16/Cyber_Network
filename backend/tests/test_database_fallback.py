import socket


def test_database_url_falls_back_to_sqlite_when_postgres_unavailable(monkeypatch):
    monkeypatch.setattr(
        "app.core.config.settings.DATABASE_URL",
        "postgresql+psycopg2://cyberuser:cyberpass@localhost:5432/cyberdb",
    )
    monkeypatch.setattr("app.core.config.settings.ENVIRONMENT", "development")

    def raise_connection_refused(*args, **kwargs):
        raise ConnectionRefusedError("connection refused")

    monkeypatch.setattr(socket, "create_connection", raise_connection_refused)

    from app.core.database import _resolve_database_url

    assert _resolve_database_url() == "sqlite:///./dev.db"
