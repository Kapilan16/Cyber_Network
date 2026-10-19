import pytest
from pydantic import ValidationError

from app.config import Settings


def test_central_vector_dim_accepts_compose_environment_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CENTRAL_VECTOR_DIM", "1536")

    assert Settings(_env_file=None).CENTRAL_VECTOR_DIM == 1536


def test_central_vector_dim_rejects_unsupported_dimension(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CENTRAL_VECTOR_DIM", "384")

    with pytest.raises(ValidationError):
        Settings(_env_file=None)
