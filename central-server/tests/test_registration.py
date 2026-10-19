"""Tests for central organization registration and admin-only listing."""
import hashlib

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.dependencies import rate_limiter
from app.main import app
from app.models import Organization, OrganizationStatus, SharedIntel
from app.config import settings
from app.security import verify_api_key_signature


@pytest.fixture()
def client(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'central-test.db'}")
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.state.testing_session_factory = TestingSessionLocal
    rate_limiter.reset()
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    rate_limiter.reset()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    del app.state.testing_session_factory


def test_registration_returns_one_time_signed_key_and_stores_only_hash(client):
    response = client.post(
        "/api/central/orgs/register",
        json={"name": " Example Org ", "contact_email": "security@example.org"},
    )

    assert response.status_code == 201
    result = response.json()
    assert result["name"] == "Example Org"
    api_key = result["api_key"]
    assert api_key.startswith("cnm_")
    assert verify_api_key_signature(api_key)

    with app.state.testing_session_factory() as db:
        organization = db.query(Organization).one()
        assert organization.api_key_hash == hashlib.sha256(
            api_key.encode("utf-8")
        ).hexdigest()
        assert organization.api_key_hash != api_key
        assert organization.contact_email == "security@example.org"


def test_invalid_api_key_signature_is_rejected():
    assert not verify_api_key_signature("cnm_1.invalid.0000000000000000")


def test_registered_bearer_key_authenticates_organization(client):
    registration = client.post(
        "/api/central/orgs/register",
        json={"name": "Authenticated Org"},
    )
    api_key = registration.json()["api_key"]

    response = client.get(
        "/api/central/orgs/me",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert response.status_code == 200
    assert response.json() == {
        "id": 1,
        "name": "Authenticated Org",
        "status": "active",
    }


def test_invalid_or_missing_bearer_key_is_rejected(client):
    assert client.get("/api/central/orgs/me").status_code == 401
    response = client.get(
        "/api/central/orgs/me",
        headers={"Authorization": "Bearer cnm_1.invalid.0000000000000000"},
    )
    assert response.status_code == 401


def test_suspended_organization_cannot_authenticate(client):
    api_key = client.post(
        "/api/central/orgs/register",
        json={"name": "Suspended Org"},
    ).json()["api_key"]
    with app.state.testing_session_factory() as db:
        organization = db.query(Organization).one()
        organization.status = OrganizationStatus.suspended
        db.commit()

    response = client.get(
        "/api/central/orgs/me",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert response.status_code == 403


def test_rate_limit_is_enforced_per_organization(client, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "CENTRAL_RATE_LIMIT_REQUESTS", 2)
    monkeypatch.setattr(settings, "CENTRAL_RATE_LIMIT_WINDOW_SECONDS", 60)
    key_one = client.post(
        "/api/central/orgs/register",
        json={"name": "Org One"},
    ).json()["api_key"]
    key_two = client.post(
        "/api/central/orgs/register",
        json={"name": "Org Two"},
    ).json()["api_key"]
    identity_url = "/api/central/orgs/me"

    def identify(api_key):
        return client.get(
            identity_url,
            headers={"Authorization": f"Bearer {api_key}"},
        )

    assert identify(key_one).status_code == 200
    assert identify(key_one).status_code == 200
    limited = identify(key_one)
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) > 0
    assert identify(key_two).status_code == 200


def test_organization_list_is_admin_only_and_exposes_only_name_and_status(client):
    client.post(
        "/api/central/orgs/register",
        json={"name": "Visible Org", "contact_email": "private@example.org"},
    )

    assert client.get("/api/central/orgs").status_code == 401
    response = client.get(
        "/api/central/orgs",
        headers={"X-Central-Admin-Token": "wrong-token"},
    )
    assert response.status_code == 403

    response = client.get(
        "/api/central/orgs",
        headers={
            "X-Central-Admin-Token": "local-dev-admin-token-change-me",
        },
    )
    assert response.status_code == 200
    assert response.json() == [{"name": "Visible Org", "status": "active"}]


def test_demo_bootstrap_is_admin_only_and_idempotent(client):
    endpoint = "/api/central/admin/demo-organizations"
    assert client.post(endpoint).status_code == 401
    assert client.post(
        endpoint,
        headers={"X-Central-Admin-Token": "wrong-token"},
    ).status_code == 403

    headers = {"X-Central-Admin-Token": "local-dev-admin-token-change-me"}
    first = client.post(endpoint, headers=headers)
    assert first.status_code == 200
    first_orgs = first.json()["organizations"]
    assert [org["name"] for org in first_orgs] == [
        "Demo Network Alpha",
        "Demo Network Beta",
        "Demo Network Gamma",
    ]
    assert all(set(org) == {"id", "name", "api_key"} for org in first_orgs)
    assert all(verify_api_key_signature(org["api_key"]) for org in first_orgs)

    first_keys = {org["id"]: org["api_key"] for org in first_orgs}
    second = client.post(endpoint, headers=headers)
    assert second.status_code == 200
    second_orgs = second.json()["organizations"]
    assert [org["id"] for org in second_orgs] == [org["id"] for org in first_orgs]
    assert len(second_orgs) == 3
    assert all(org["api_key"] != first_keys[org["id"]] for org in second_orgs)
    with app.state.testing_session_factory() as db:
        assert db.query(Organization).count() == 3


def test_health_check(client):
    assert client.get("/api/central/health").json() == {"status": "ok"}


def test_central_vector_width_matches_org_local_storage_contract(client, monkeypatch):
    from app.schemas import SharedIntelPayload, SharedIntelSearchRequest

    monkeypatch.setattr(settings, "CENTRAL_VECTOR_DIM", 1536)
    padded_minilm_vector = [0.1] * 384 + [0.0] * (1536 - 384)
    payload = SharedIntelPayload.model_validate(
        {
            "sanitized_text": "An anonymized embedding fixture",
            "embedding": padded_minilm_vector,
        }
    )
    search = SharedIntelSearchRequest.model_validate(
        {"embedding": padded_minilm_vector, "top_k": 5}
    )
    assert len(payload.embedding) == len(search.embedding) == 1536
    assert settings.CENTRAL_VECTOR_DIM == 1536

    with pytest.raises(ValidationError):
        SharedIntelPayload.model_validate(
            {
                "sanitized_text": "Native MiniLM vector must be padded before upload",
                "embedding": [0.1] * 384,
            }
        )


def test_central_embedding_provider_dispatch_and_fallback(monkeypatch):
    from app.embeddings import EmbeddingsClient

    monkeypatch.setattr(settings, "CENTRAL_VECTOR_DIM", 1536)
    monkeypatch.setattr(settings, "EMBEDDING_PROVIDER", "local_sentence_transformers")

    class Model:
        def encode(self, *_args, **_kwargs):
            return [0.25] * 384

    client = EmbeddingsClient()
    monkeypatch.setattr(client, "_get_sentence_model", lambda: Model())
    vector = client.embed("central semantic text")
    assert len(vector) == 1536
    assert vector[:384] == [0.25] * 384
    assert vector[384:] == [0.0] * (1536 - 384)

    def unavailable_model():
        raise OSError("model unavailable")

    monkeypatch.setattr(client, "_get_sentence_model", unavailable_model)
    fallback = client.embed("central semantic text")
    assert len(fallback) == 1536
    assert fallback == client._feature_hash("central semantic text")

    monkeypatch.setattr(settings, "EMBEDDING_PROVIDER", "feature_hash")
    feature_hash_client = EmbeddingsClient()
    assert feature_hash_client.embed("central semantic text") == fallback


def test_central_embedding_openai_provider_uses_configured_dispatch(monkeypatch):
    from app.embeddings import EmbeddingsClient

    monkeypatch.setattr(settings, "CENTRAL_VECTOR_DIM", 1536)
    monkeypatch.setattr(settings, "EMBEDDING_PROVIDER", "openai_compatible")
    monkeypatch.setattr(settings, "EMBEDDINGS_API_KEY", "test-key")
    client = EmbeddingsClient()
    monkeypatch.setattr(client, "_call_api", lambda _text: [0.5] * 384)

    vector = client.embed("central semantic text")
    assert len(vector) == 1536
    assert vector[:384] == [0.5] * 384
    assert vector[384:] == [0.0] * (1536 - 384)


def test_shared_intel_payload_validation(client, monkeypatch):
    monkeypatch.setattr(settings, "CENTRAL_VECTOR_DIM", 3)
    api_key = client.post(
        "/api/central/orgs/register",
        json={"name": "Payload Org"},
    ).json()["api_key"]
    headers = {"Authorization": f"Bearer {api_key}"}
    valid = {
        "sanitized_text": "Suspicious command activity [HOST_REDACTED]",
        "rule_categories": ["suspicious powershell"],
        "mitre_technique_ids": ["T1059.001"],
        "severity": ["high"],
        "embedding": [0.1, 0.2, 0.3],
    }

    accepted = client.post(
        "/api/central/intel/submit",
        headers=headers,
        json=valid,
    )
    assert accepted.status_code == 201
    assert accepted.json()["duplicate"] is False
    assert "source_org_id" not in accepted.json()

    invalid_technique = {**valid, "mitre_technique_ids": ["internal-value"]}
    assert client.post(
        "/api/central/intel/submit",
        headers=headers,
        json=invalid_technique,
    ).status_code == 422

    invalid_severity = {**valid, "severity": ["secret"]}
    assert client.post(
        "/api/central/intel/submit",
        headers=headers,
        json=invalid_severity,
    ).status_code == 422

    invalid_embedding = {**valid, "embedding": [0.1, 0.2]}
    assert client.post(
        "/api/central/intel/submit",
        headers=headers,
        json=invalid_embedding,
    ).status_code == 422

    payload_with_org_data = {**valid, "source_org_id": 5}
    assert client.post(
        "/api/central/intel/submit",
        headers=headers,
        json=payload_with_org_data,
    ).status_code == 422


def test_shared_intel_deduplicates_per_source_org_without_exposing_org(client):
    body = {
        "sanitized_text": "Repeated anonymized report",
        "rule_categories": ["credential exposure"],
        "mitre_technique_ids": ["T1552.001"],
        "severity": ["high"],
        "embedding": None,
    }
    key_one = client.post(
        "/api/central/orgs/register",
        json={"name": "First Org"},
    ).json()["api_key"]
    key_two = client.post(
        "/api/central/orgs/register",
        json={"name": "Second Org"},
    ).json()["api_key"]

    def submit(api_key):
        return client.post(
            "/api/central/intel/submit",
            headers={"Authorization": f"Bearer {api_key}"},
            json=body,
        )

    first = submit(key_one)
    repeated = submit(key_one)
    other_org = submit(key_two)
    assert first.status_code == repeated.status_code == other_org.status_code == 201
    assert first.json()["duplicate"] is False
    assert repeated.json() == {"id": first.json()["id"], "duplicate": True}
    assert other_org.json()["duplicate"] is False
    assert other_org.json()["id"] != first.json()["id"]

    with app.state.testing_session_factory() as db:
        rows = db.query(SharedIntel).order_by(SharedIntel.id).all()
        assert len(rows) == 2
        assert rows[0].source_org_id != rows[1].source_org_id
        assert rows[0].mitre_technique_ids == ["T1552.001"]
        assert rows[0].rule_categories == ["credential exposure"]


def test_shared_intel_stats_are_admin_only_and_have_no_org_breakdown(client):
    api_key = client.post(
        "/api/central/orgs/register",
        json={"name": "Stats Org"},
    ).json()["api_key"]
    client.post(
        "/api/central/intel/submit",
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "sanitized_text": "Anonymized",
            "rule_categories": [],
            "mitre_technique_ids": ["T1059.001"],
            "severity": ["critical", "high"],
            "embedding": None,
        },
    )

    assert client.get("/api/central/intel/stats").status_code == 401
    response = client.get(
        "/api/central/intel/stats",
        headers={"X-Central-Admin-Token": "local-dev-admin-token-change-me"},
    )
    assert response.status_code == 200
    assert response.json() == {
        "total": 1,
        "by_technique": [{"technique_id": "T1059.001", "count": 1}],
        "by_severity": [
            {"severity": "critical", "count": 1},
            {"severity": "high", "count": 1},
        ],
    }
    assert "source_org_id" not in str(response.json())


def test_network_search_ranks_other_orgs_and_never_returns_org_ids(client, monkeypatch):
    from app.search.faiss_index import get_faiss_index

    monkeypatch.setattr(settings, "CENTRAL_VECTOR_DIM", 3)
    key_searcher = client.post(
        "/api/central/orgs/register",
        json={"name": "Search-only Org"},
    ).json()["api_key"]
    key_first = client.post(
        "/api/central/orgs/register",
        json={"name": "Contributor One"},
    ).json()["api_key"]
    key_second = client.post(
        "/api/central/orgs/register",
        json={"name": "Contributor Two"},
    ).json()["api_key"]
    key_searcher_contributor = client.post(
        "/api/central/orgs/register",
        json={"name": "Search and Contribute Org"},
    ).json()["api_key"]

    def submit(api_key, sanitized_text, embedding):
        return client.post(
            "/api/central/intel/submit",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "sanitized_text": sanitized_text,
                "rule_categories": [],
                "mitre_technique_ids": ["T1059"],
                "severity": ["medium"],
                "embedding": embedding,
            },
        )

    assert submit(key_first, "closest from contributor one", [1, 0, 0]).status_code == 201
    assert submit(key_second, "orthogonal from contributor two", [0, 1, 0]).status_code == 201
    assert submit(key_searcher, "must not return its own intel", [1, 0, 0]).status_code == 201
    assert submit(key_searcher_contributor, "next closest", [0.8, 0.6, 0]).status_code == 201
    assert get_faiss_index().count == 4

    response = client.post(
        "/api/central/intel/search",
        headers={"Authorization": f"Bearer {key_searcher}"},
        json={"embedding": [1, 0, 0], "top_k": 2},
    )
    assert response.status_code == 200
    body = response.json()
    assert [item["sanitized_text"] for item in body["results"]] == [
        "closest from contributor one",
        "next closest",
    ]
    assert body["results"][0]["similarity_score"] == 1.0
    assert body["results"][1]["similarity_score"] == 0.8
    assert body["total_found"] == 2
    assert all("source_org_id" not in item for item in body["results"])
    assert "source_org_id" not in str(body)


def test_cold_faiss_index_uses_sqlite_database_search(client, monkeypatch):
    monkeypatch.setattr(settings, "CENTRAL_VECTOR_DIM", 3)
    searcher = client.post(
        "/api/central/orgs/register",
        json={"name": "Cold Index Searcher"},
    ).json()["api_key"]
    contributor = client.post(
        "/api/central/orgs/register",
        json={"name": "Cold Index Contributor"},
    ).json()["api_key"]
    client.post(
        "/api/central/intel/submit",
        headers={"Authorization": f"Bearer {contributor}"},
        json={
            "sanitized_text": "pgvector fallback intel",
            "rule_categories": [],
            "mitre_technique_ids": [],
            "severity": [],
            "embedding": [1.0, 0.0, 0.0],
        },
    )

    class ColdIndex:
        available = False
        count = 0

    monkeypatch.setattr(
        "app.main.get_faiss_index",
        lambda: ColdIndex(),
    )
    response = client.post(
        "/api/central/intel/search",
        headers={"Authorization": f"Bearer {searcher}"},
        json={"embedding": [1.0, 0.0, 0.0], "top_k": 1},
    )
    assert response.status_code == 200
    assert response.json()["results"][0]["sanitized_text"] == "pgvector fallback intel"


def test_empty_faiss_results_fall_back_to_sqlite_database_search(client, monkeypatch):
    from app.schemas import SharedIntelSearchResponse

    monkeypatch.setattr(settings, "CENTRAL_VECTOR_DIM", 3)
    key_searcher = client.post(
        "/api/central/orgs/register",
        json={"name": "Empty FAISS Searcher"},
    ).json()["api_key"]
    key_contributor = client.post(
        "/api/central/orgs/register",
        json={"name": "Empty FAISS Contributor"},
    ).json()["api_key"]
    client.post(
        "/api/central/intel/submit",
        headers={"Authorization": f"Bearer {key_contributor}"},
        json={
            "sanitized_text": "database fallback intel",
            "rule_categories": [],
            "mitre_technique_ids": [],
            "severity": [],
            "embedding": [1.0, 0.0, 0.0],
        },
    )

    monkeypatch.setattr(
        "app.main._search_shared_intel_faiss",
        lambda *_args: SharedIntelSearchResponse(results=[], total_found=0),
    )
    response = client.post(
        "/api/central/intel/search",
        headers={"Authorization": f"Bearer {key_searcher}"},
        json={"embedding": [1.0, 0.0, 0.0], "top_k": 1},
    )

    assert response.status_code == 200
    assert response.json()["total_found"] == 1
    assert response.json()["results"][0]["sanitized_text"] == "database fallback intel"


def test_read_without_contribution_is_explicitly_configurable(client, monkeypatch):
    monkeypatch.setattr(settings, "CENTRAL_VECTOR_DIM", 3)
    monkeypatch.setattr(settings, "CENTRAL_ALLOW_READ_WITHOUT_CONTRIBUTION", True)
    key = client.post(
        "/api/central/orgs/register",
        json={"name": "Opted Out Reader"},
    ).json()["api_key"]
    headers = {"Authorization": f"Bearer {key}"}

    allowed = client.post(
        "/api/central/intel/search",
        headers=headers,
        json={"embedding": [1, 0, 0], "top_k": 5},
    )
    assert allowed.status_code == 200

    monkeypatch.setattr(settings, "CENTRAL_ALLOW_READ_WITHOUT_CONTRIBUTION", False)
    denied = client.post(
        "/api/central/intel/search",
        headers=headers,
        json={"embedding": [1, 0, 0], "top_k": 5},
    )
    assert denied.status_code == 403
