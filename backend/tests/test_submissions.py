"""
Integration tests for POST/GET /api/submissions endpoints.
"""
import pytest

REGISTER_URL = "/api/auth/register"
LOGIN_URL = "/api/auth/login"
SUBMISSIONS_URL = "/api/submissions"

_ANALYST = {"email": "analyst@test.com", "password": "P@ssw0rd123!"}
_ADMIN = {"email": "admin@test.com", "password": "P@ssw0rd123!", "role": "admin"}


def _register_and_login(client, creds: dict) -> str:
    """Register (if first time) and return a Bearer token."""
    client.post(REGISTER_URL, json=creds)
    if creds.get("role") == "admin":
        from app.api.deps import get_db
        from app.models.user import User, UserRole

        db = next(client.app.dependency_overrides[get_db]())
        user = db.query(User).filter(User.email == creds["email"]).one()
        user.role = UserRole.admin
        db.commit()
    resp = client.post(LOGIN_URL, json={"email": creds["email"], "password": creds["password"]})
    return resp.json()["access_token"]


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── POST /api/submissions ──────────────────────────────────────────────────────

def test_create_submission_clean(client):
    token = _register_and_login(client, _ANALYST)
    resp = client.post(
        SUBMISSIONS_URL,
        json={"raw_text": "Alert: high CPU on host-1", "source_type": "alert"},
        headers=auth_headers(token),
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["sanitization_status"] == "clean"
    assert data["sanitized_text"] == "Alert: high CPU on host-1"
    assert data["raw_text"] == "Alert: high CPU on host-1"
    assert data["sanitization_meta"]["redaction_count"] == 0


def test_create_submission_redacts_aws_key(client):
    token = _register_and_login(client, _ANALYST)
    resp = client.post(
        SUBMISSIONS_URL,
        json={"raw_text": "Key: AKIAIOSFODNN7EXAMPLE used", "source_type": "log"},
        headers=auth_headers(token),
    )
    assert resp.status_code == 201
    data = resp.json()
    assert "AKIAIOSFODNN7EXAMPLE" not in data["sanitized_text"]
    assert "[REDACTED]" in data["sanitized_text"]
    assert data["sanitization_status"] == "redacted"
    assert data["sanitization_meta"]["redaction_count"] >= 1


def test_create_submission_flags_shell(client):
    token = _register_and_login(client, _ANALYST)
    resp = client.post(
        SUBMISSIONS_URL,
        json={"raw_text": "payload $(whoami) found", "source_type": "freeform"},
        headers=auth_headers(token),
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["sanitization_status"] == "flagged"
    assert data["sanitization_meta"]["flag_count"] >= 1


def test_create_submission_requires_auth(client):
    resp = client.post(
        SUBMISSIONS_URL,
        json={"raw_text": "unauthenticated submission"},
    )
    assert resp.status_code == 401


def test_create_submission_empty_text_rejected(client):
    token = _register_and_login(client, _ANALYST)
    resp = client.post(
        SUBMISSIONS_URL,
        json={"raw_text": ""},
        headers=auth_headers(token),
    )
    assert resp.status_code == 422


# ── GET /api/submissions ───────────────────────────────────────────────────────

def test_list_submissions_user_scoped(client):
    token_a = _register_and_login(client, _ANALYST)
    token_b = _register_and_login(client, {"email": "other@test.com", "password": "P@ss123!!"})

    # analyst posts one submission
    client.post(
        SUBMISSIONS_URL,
        json={"raw_text": "analyst submission"},
        headers=auth_headers(token_a),
    )

    # other user posts one submission
    client.post(
        SUBMISSIONS_URL,
        json={"raw_text": "other submission"},
        headers=auth_headers(token_b),
    )

    # analyst should only see their own
    resp = client.get(SUBMISSIONS_URL, headers=auth_headers(token_a))
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["sanitized_text"] == "analyst submission"


def test_admin_sees_all_submissions(client):
    token_analyst = _register_and_login(client, _ANALYST)
    token_admin = _register_and_login(client, _ADMIN)

    client.post(
        SUBMISSIONS_URL,
        json={"raw_text": "submission one"},
        headers=auth_headers(token_analyst),
    )
    client.post(
        SUBMISSIONS_URL,
        json={"raw_text": "submission two"},
        headers=auth_headers(token_admin),
    )

    resp = client.get(SUBMISSIONS_URL, headers=auth_headers(token_admin))
    assert resp.status_code == 200
    assert resp.json()["total"] == 2


def test_list_paginated(client):
    token = _register_and_login(client, _ANALYST)
    for i in range(5):
        client.post(
            SUBMISSIONS_URL,
            json={"raw_text": f"log line {i}"},
            headers=auth_headers(token),
        )
    resp = client.get(SUBMISSIONS_URL + "?page=1&page_size=3", headers=auth_headers(token))
    data = resp.json()
    assert data["total"] == 5
    assert len(data["items"]) == 3


# ── GET /api/submissions/{id} ─────────────────────────────────────────────────

def test_get_submission_by_id(client):
    token = _register_and_login(client, _ANALYST)
    created = client.post(
        SUBMISSIONS_URL,
        json={"raw_text": "specific submission"},
        headers=auth_headers(token),
    ).json()
    sub_id = created["id"]

    resp = client.get(f"{SUBMISSIONS_URL}/{sub_id}", headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["id"] == sub_id


def test_get_submission_other_user_returns_404(client):
    token_a = _register_and_login(client, _ANALYST)
    token_b = _register_and_login(client, {"email": "intruder@test.com", "password": "P@ss123!!"})

    created = client.post(
        SUBMISSIONS_URL,
        json={"raw_text": "private submission"},
        headers=auth_headers(token_a),
    ).json()

    # Other user tries to access analyst's submission → 404 (not 403)
    resp = client.get(f"{SUBMISSIONS_URL}/{created['id']}", headers=auth_headers(token_b))
    assert resp.status_code == 404


def test_get_nonexistent_submission_returns_404(client):
    token = _register_and_login(client, _ANALYST)
    resp = client.get(f"{SUBMISSIONS_URL}/99999", headers=auth_headers(token))
    assert resp.status_code == 404


def test_dashboard_summary_includes_stage_one_aggregates(client):
    token = _register_and_login(client, _ANALYST)
    created = client.post(
        SUBMISSIONS_URL,
        json={"raw_text": "Failed login attempts from 203.0.113.44", "source_type": "alert"},
        headers=auth_headers(token),
    )
    assert created.status_code == 201

    response = client.get("/api/dashboard/summary", headers=auth_headers(token))
    assert response.status_code == 200
    summary = response.json()
    assert summary["submissions_today"] == 1
    assert set(summary["open_findings_by_severity"]) == {"critical", "high", "medium", "low"}
    assert isinstance(summary["top_tactics_this_week"], list)
