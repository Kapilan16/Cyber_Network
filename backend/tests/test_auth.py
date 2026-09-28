"""
Tests for POST /api/auth/register, POST /api/auth/login,
POST /api/auth/refresh, and invalid-credential edge cases.
"""

REGISTER_URL = "/api/auth/register"
LOGIN_URL = "/api/auth/login"
REFRESH_URL = "/api/auth/refresh"
ME_URL = "/api/auth/me"

_USER = {"email": "alice@example.com", "password": "S3cur3P@ss!"}


# ─── Register ────────────────────────────────────────────────────────────────


def test_register_success(client):
    resp = client.post(REGISTER_URL, json=_USER)
    assert resp.status_code == 201
    data = resp.json()
    assert data["email"] == _USER["email"]
    assert data["role"] == "analyst"
    assert "id" in data
    assert "hashed_password" not in data  # never leak hash


def test_register_duplicate_email(client):
    client.post(REGISTER_URL, json=_USER)  # first registration
    resp = client.post(REGISTER_URL, json=_USER)  # duplicate
    assert resp.status_code == 409
    assert "already registered" in resp.json()["detail"].lower()


def test_register_cannot_self_assign_admin_role(client):
    payload = {**_USER, "email": "admin@example.com", "role": "admin"}
    resp = client.post(REGISTER_URL, json=payload)
    assert resp.status_code == 201
    assert resp.json()["role"] == "analyst"


def test_register_invalid_email(client):
    resp = client.post(REGISTER_URL, json={"email": "not-an-email", "password": "pw"})
    assert resp.status_code == 422  # Pydantic validation error


# ─── Login ───────────────────────────────────────────────────────────────────


def test_login_success(client):
    client.post(REGISTER_URL, json=_USER)
    resp = client.post(LOGIN_URL, json=_USER)
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


def test_login_wrong_password(client):
    client.post(REGISTER_URL, json=_USER)
    resp = client.post(
        LOGIN_URL, json={"email": _USER["email"], "password": "WrongPass!"}
    )
    assert resp.status_code == 401
    assert "incorrect" in resp.json()["detail"].lower()


def test_login_unknown_email(client):
    resp = client.post(
        LOGIN_URL, json={"email": "nobody@example.com", "password": "pw"}
    )
    assert resp.status_code == 401


# ─── Refresh ─────────────────────────────────────────────────────────────────


def test_refresh_success(client):
    client.post(REGISTER_URL, json=_USER)
    tokens = client.post(LOGIN_URL, json=_USER).json()
    resp = client.post(REFRESH_URL, json={"refresh_token": tokens["refresh_token"]})
    assert resp.status_code == 200
    new_tokens = resp.json()
    assert "access_token" in new_tokens
    # New access token should be different (different exp)
    # (may be same if issued within same second, just assert it exists)
    assert new_tokens["token_type"] == "bearer"


def test_refresh_with_access_token_rejected(client):
    client.post(REGISTER_URL, json=_USER)
    tokens = client.post(LOGIN_URL, json=_USER).json()
    # Passing the *access* token where a refresh token is expected
    resp = client.post(REFRESH_URL, json={"refresh_token": tokens["access_token"]})
    assert resp.status_code == 401


def test_refresh_invalid_token(client):
    resp = client.post(REFRESH_URL, json={"refresh_token": "this.is.garbage"})
    assert resp.status_code == 401


# ─── Protected route (/me) ────────────────────────────────────────────────────


def test_me_authenticated(client):
    client.post(REGISTER_URL, json=_USER)
    tokens = client.post(LOGIN_URL, json=_USER).json()
    resp = client.get(
        ME_URL, headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert resp.status_code == 200
    assert resp.json()["email"] == _USER["email"]


def test_me_unauthenticated(client):
    resp = client.get(ME_URL)
    assert resp.status_code == 401


def test_me_invalid_token(client):
    resp = client.get(ME_URL, headers={"Authorization": "Bearer bad.token.value"})
    assert resp.status_code == 401
