"""Rule descriptions use the same provider and storage width as submissions."""
import json
from unittest.mock import patch

from app.api.v1.endpoints.rules import _set_description_embedding
from app.models.rule import Rule, Severity


def test_rule_description_embedding_uses_shared_fixed_dimension_provider(db_session):
    vector = [0.125] * 1536
    rule = Rule(
        name="Test semantic rule",
        description="Detects a suspicious remote execution pattern",
        condition_json={"contains": ["remote execution"]},
        severity=Severity.high,
    )

    class EmbeddingClient:
        def embed(self, text):
            assert text == rule.description
            return vector

    with patch(
        "app.api.v1.endpoints.rules.get_embeddings_client",
        return_value=EmbeddingClient(),
    ):
        _set_description_embedding(rule, db_session)

    assert isinstance(rule.description_embedding, str)
    assert json.loads(rule.description_embedding) == vector
    assert len(json.loads(rule.description_embedding)) == 1536


def test_blank_rule_description_clears_embedding(db_session):
    rule = Rule(
        name="Empty semantic rule",
        description="  ",
        condition_json={},
        severity=Severity.low,
        description_embedding=json.dumps([0.1] * 1536),
    )

    with patch("app.api.v1.endpoints.rules.get_embeddings_client") as get_client:
        _set_description_embedding(rule, db_session)

    get_client.assert_not_called()
    assert rule.description_embedding is None
