"""
Tests for the MITRE ATT&CK integration:
  1. Seed-load integrity check
  2. List / filter techniques
  3. Get technique by ID
  4. mitre-summary aggregation correctness
  5. Extended FindingOut now includes mitre_technique field
"""
from __future__ import annotations

import pytest

REGISTER_URL = "/api/auth/register"
LOGIN_URL    = "/api/auth/login"
SUBMISSIONS  = "/api/submissions"
RULES_SEED   = "/api/rules/seed"
MITRE_SEED   = "/api/mitre/techniques/seed"
MITRE_LIST   = "/api/mitre/techniques"

_ANALYST = {"email": "mitre_analyst@test.com", "password": "P@ssw0rd!!1"}
_ADMIN   = {"email": "mitre_admin@test.com",   "password": "P@ssw0rd!!1", "role": "admin"}


def _token(client, creds: dict) -> str:
    client.post(REGISTER_URL, json=creds)
    if creds.get("role") == "admin":
        from app.api.deps import get_db
        from app.models.user import User, UserRole

        db = next(client.app.dependency_overrides[get_db]())
        user = db.query(User).filter(User.email == creds["email"]).one()
        user.role = UserRole.admin
        db.commit()
    r = client.post(LOGIN_URL, json={"email": creds["email"], "password": creds["password"]})
    return r.json()["access_token"]


def _auth(tok: str) -> dict:
    return {"Authorization": f"Bearer {tok}"}


# ── Seed integrity ────────────────────────────────────────────────────────────

def test_mitre_seed_loads_all_techniques(client):
    admin_tok = _token(client, _ADMIN)
    r = client.post(MITRE_SEED, headers=_auth(admin_tok))
    assert r.status_code == 201
    data = r.json()
    assert data["techniques_created"] == data["total_in_file"]
    assert data["total_in_file"] >= 40          # at least 40 techniques in the JSON


def test_mitre_seed_is_idempotent(client):
    admin_tok = _token(client, _ADMIN)
    client.post(MITRE_SEED, headers=_auth(admin_tok))
    r2 = client.post(MITRE_SEED, headers=_auth(admin_tok))
    assert r2.status_code == 201
    assert r2.json()["techniques_created"] == 0


def test_mitre_seed_requires_admin(client):
    analyst_tok = _token(client, _ANALYST)
    r = client.post(MITRE_SEED, headers=_auth(analyst_tok))
    assert r.status_code == 403


# ── List / filter ─────────────────────────────────────────────────────────────

def test_list_techniques_returns_all(client):
    admin_tok = _token(client, _ADMIN)
    client.post(MITRE_SEED, headers=_auth(admin_tok))
    analyst_tok = _token(client, _ANALYST)
    r = client.get(MITRE_LIST, headers=_auth(analyst_tok))
    assert r.status_code == 200
    techniques = r.json()
    assert len(techniques) >= 40
    # Every item must have id, name, tactic
    for t in techniques:
        assert "id" in t and "name" in t and "tactic" in t


def test_list_techniques_filter_by_tactic(client):
    admin_tok = _token(client, _ADMIN)
    client.post(MITRE_SEED, headers=_auth(admin_tok))
    analyst_tok = _token(client, _ANALYST)

    r = client.get(f"{MITRE_LIST}?tactic=Execution", headers=_auth(analyst_tok))
    assert r.status_code == 200
    items = r.json()
    assert len(items) >= 3
    for t in items:
        assert "execution" in t["tactic"].lower()


def test_list_techniques_keyword_search(client):
    admin_tok = _token(client, _ADMIN)
    client.post(MITRE_SEED, headers=_auth(admin_tok))
    analyst_tok = _token(client, _ANALYST)

    r = client.get(f"{MITRE_LIST}?q=PowerShell", headers=_auth(analyst_tok))
    assert r.status_code == 200
    items = r.json()
    assert any("powershell" in t["name"].lower() for t in items)


def test_list_techniques_requires_auth(client):
    r = client.get(MITRE_LIST)
    assert r.status_code == 401


# ── Get by ID ─────────────────────────────────────────────────────────────────

def test_get_technique_by_id(client):
    admin_tok = _token(client, _ADMIN)
    client.post(MITRE_SEED, headers=_auth(admin_tok))
    analyst_tok = _token(client, _ANALYST)

    r = client.get(f"{MITRE_LIST}/T1059.001", headers=_auth(analyst_tok))
    assert r.status_code == 200
    tech = r.json()
    assert tech["id"] == "T1059.001"
    assert "PowerShell" in tech["name"]
    assert tech["tactic"] == "Execution"


def test_get_technique_not_found(client):
    admin_tok = _token(client, _ADMIN)
    client.post(MITRE_SEED, headers=_auth(admin_tok))
    analyst_tok = _token(client, _ANALYST)
    r = client.get(f"{MITRE_LIST}/T9999", headers=_auth(analyst_tok))
    assert r.status_code == 404


# ── mitre-summary ─────────────────────────────────────────────────────────────

def test_mitre_summary_correctness(client):
    """
    Submit text that triggers the PowerShell rule (linked to T1059.001, tactic: Execution).
    After evaluate, mitre-summary must include Execution in its tactics breakdown.
    """
    admin_tok   = _token(client, _ADMIN)
    analyst_tok = _token(client, _ANALYST)

    # Seed both datasets
    client.post(RULES_SEED,  headers=_auth(admin_tok))
    client.post(MITRE_SEED,  headers=_auth(admin_tok))

    # Submission that should trigger PowerShell encoded-command rule
    sub = client.post(
        SUBMISSIONS,
        json={"raw_text": "Process launched: powershell -EncodedCommand VABCDE", "source_type": "alert"},
        headers=_auth(analyst_tok),
    )
    sub_id = sub.json()["id"]

    # Evaluate
    ev = client.post(f"{SUBMISSIONS}/{sub_id}/evaluate", headers=_auth(analyst_tok))
    assert ev.json()["findings_created"] >= 1

    # Fetch summary
    r = client.get(f"/api/mitre/submissions/{sub_id}/mitre-summary", headers=_auth(analyst_tok))
    assert r.status_code == 200
    summary = r.json()

    assert summary["submission_id"] == sub_id
    assert summary["total_findings"] >= 1
    tactic_names = [t["tactic"] for t in summary["tactics"]]
    assert "Execution" in tactic_names


def test_mitre_summary_clean_submission(client):
    """A clean submission with no findings → empty tactics list."""
    admin_tok   = _token(client, _ADMIN)
    analyst_tok = _token(client, _ANALYST)
    client.post(RULES_SEED, headers=_auth(admin_tok))
    client.post(MITRE_SEED, headers=_auth(admin_tok))

    sub = client.post(
        SUBMISSIONS,
        json={"raw_text": "User logged in successfully at 09:00 UTC.", "source_type": "log"},
        headers=_auth(analyst_tok),
    )
    sub_id = sub.json()["id"]
    client.post(f"{SUBMISSIONS}/{sub_id}/evaluate", headers=_auth(analyst_tok))

    r = client.get(f"/api/mitre/submissions/{sub_id}/mitre-summary", headers=_auth(analyst_tok))
    assert r.status_code == 200
    summary = r.json()
    assert summary["total_findings"] == 0
    assert summary["tactics"] == []


def test_mitre_summary_requires_auth(client):
    r = client.get("/api/mitre/submissions/1/mitre-summary")
    assert r.status_code == 401


def test_mitre_summary_scoped_to_owner(client):
    """Another user cannot see a different user's submission summary."""
    admin_tok   = _token(client, _ADMIN)
    analyst_tok = _token(client, _ANALYST)
    other_tok   = _token(client, {"email": "mitre_other@test.com", "password": "P@ssOther!!"})
    client.post(RULES_SEED, headers=_auth(admin_tok))

    sub = client.post(
        SUBMISSIONS,
        json={"raw_text": "test data"},
        headers=_auth(analyst_tok),
    )
    sub_id = sub.json()["id"]

    r = client.get(f"/api/mitre/submissions/{sub_id}/mitre-summary", headers=_auth(other_tok))
    assert r.status_code == 404


# ── FindingOut includes mitre_technique ───────────────────────────────────────

def test_findings_endpoint_includes_mitre_technique(client):
    """GET /api/submissions/{id}/findings should return mitre_technique per finding."""
    admin_tok   = _token(client, _ADMIN)
    analyst_tok = _token(client, _ANALYST)
    client.post(RULES_SEED, headers=_auth(admin_tok))
    client.post(MITRE_SEED, headers=_auth(admin_tok))

    sub = client.post(
        SUBMISSIONS,
        json={"raw_text": "mimikatz tool found; LSASS dump detected on host", "source_type": "alert"},
        headers=_auth(analyst_tok),
    )
    sub_id = sub.json()["id"]
    client.post(f"{SUBMISSIONS}/{sub_id}/evaluate", headers=_auth(analyst_tok))

    findings = client.get(f"{SUBMISSIONS}/{sub_id}/findings", headers=_auth(analyst_tok)).json()
    assert len(findings) >= 1

    # At least one finding should have mitre_technique populated
    mitre_linked = [f for f in findings if f.get("mitre_technique") is not None]
    assert len(mitre_linked) >= 1

    for f in mitre_linked:
        mt = f["mitre_technique"]
        assert "id" in mt
        assert "name" in mt
        assert "tactic" in mt
