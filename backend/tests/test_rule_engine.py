"""
Unit + integration tests for the rule engine.

Part 1 — pure DSL evaluator (no DB)
  Tests every operator: contains, not_contains, regex, not_regex,
  equals, starts_with, ends_with, and, or, any, all, not, nested.

Part 2 — end-to-end API
  submit → sanitize → evaluate → findings
"""
from __future__ import annotations

import pytest
from app.rules.evaluator import evaluate_rule

# ═══════════════════════════════════════════════════════════════════════════════
# Part 1 — DSL evaluator unit tests (pure functions, zero DB)
# ═══════════════════════════════════════════════════════════════════════════════

CTX = {
    "sanitized_text": (
        "Alert: unusual PowerShell activity. "
        "Command: powershell.exe -EncodedCommand ABCD1234. "
        "Source IP: 192.168.1.45. "
        "MD5: d41d8cd98f00b204e9800998ecf8427e. "
        "Contact admin@corp.example for details."
    ),
    "raw_text": "raw content here",
    "source_type": "alert",
}

# ── contains ──────────────────────────────────────────────────────────────────

def test_contains_match():
    cond = {"op": "contains", "value": "PowerShell"}
    matched, snippet = evaluate_rule(cond, CTX)
    assert matched is True
    assert "PowerShell" in snippet or "powershell" in snippet.lower()


def test_contains_no_match():
    cond = {"op": "contains", "value": "mimikatz"}
    matched, snippet = evaluate_rule(cond, CTX)
    assert matched is False
    assert snippet == ""


def test_contains_case_insensitive():
    cond = {"op": "contains", "value": "POWERSHELL"}
    matched, _ = evaluate_rule(cond, CTX)
    assert matched is True  # case-insensitive by default


# ── not_contains ──────────────────────────────────────────────────────────────

def test_not_contains_match():
    """'mimikatz' is absent → not_contains should return True."""
    cond = {"op": "not_contains", "value": "mimikatz"}
    matched, snippet = evaluate_rule(cond, CTX)
    assert matched is True
    assert snippet == ""


def test_not_contains_no_match():
    """'PowerShell' IS present → not_contains should return False."""
    cond = {"op": "not_contains", "value": "PowerShell"}
    matched, _ = evaluate_rule(cond, CTX)
    assert matched is False


# ── regex ─────────────────────────────────────────────────────────────────────

def test_regex_match_ipv4():
    cond = {"op": "regex", "pattern": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"}
    matched, snippet = evaluate_rule(cond, CTX)
    assert matched is True
    assert "192.168.1.45" in snippet


def test_regex_match_md5():
    cond = {"op": "regex", "pattern": r"\b[0-9a-f]{32}\b"}
    matched, snippet = evaluate_rule(cond, CTX)
    assert matched is True
    assert "d41d8cd98f00b204e9800998ecf8427e" in snippet


def test_regex_no_match():
    cond = {"op": "regex", "pattern": r"\bAKIA[A-Z0-9]{16}\b"}
    matched, snippet = evaluate_rule(cond, CTX)
    assert matched is False
    assert snippet == ""


def test_regex_invalid_pattern_safe():
    """An invalid regex must not raise — it should return (False, '')."""
    cond = {"op": "regex", "pattern": r"[invalid("}
    matched, snippet = evaluate_rule(cond, CTX)
    assert matched is False
    assert snippet == ""


# ── not_regex ─────────────────────────────────────────────────────────────────

def test_not_regex_match():
    """AWS key pattern is absent → not_regex returns True."""
    cond = {"op": "not_regex", "pattern": r"\bAKIA[A-Z0-9]{16}\b"}
    matched, _ = evaluate_rule(cond, CTX)
    assert matched is True


def test_not_regex_no_match():
    """IPv4 IS present → not_regex returns False."""
    cond = {"op": "not_regex", "pattern": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"}
    matched, _ = evaluate_rule(cond, CTX)
    assert matched is False


# ── equals ────────────────────────────────────────────────────────────────────

def test_equals_match():
    cond = {"op": "equals", "field": "source_type", "value": "alert"}
    matched, snippet = evaluate_rule(cond, CTX)
    assert matched is True


def test_equals_no_match():
    cond = {"op": "equals", "field": "source_type", "value": "report"}
    matched, _ = evaluate_rule(cond, CTX)
    assert matched is False


# ── starts_with / ends_with ───────────────────────────────────────────────────

def test_starts_with_match():
    cond = {"op": "starts_with", "value": "Alert:"}
    matched, snippet = evaluate_rule(cond, CTX)
    assert matched is True
    assert snippet.startswith("Alert:")


def test_starts_with_no_match():
    cond = {"op": "starts_with", "value": "WARNING"}
    matched, _ = evaluate_rule(cond, CTX)
    assert matched is False


def test_ends_with_match():
    cond = {"op": "ends_with", "value": "for details."}
    matched, _ = evaluate_rule(cond, CTX)
    assert matched is True


# ── and / all ─────────────────────────────────────────────────────────────────

def test_and_both_match():
    cond = {
        "and": [
            {"op": "contains", "value": "PowerShell"},
            {"op": "regex",    "pattern": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"},
        ]
    }
    matched, snippet = evaluate_rule(cond, CTX)
    assert matched is True
    assert snippet != ""


def test_and_one_fails():
    cond = {
        "and": [
            {"op": "contains", "value": "PowerShell"},
            {"op": "contains", "value": "mimikatz"},   # not present
        ]
    }
    matched, snippet = evaluate_rule(cond, CTX)
    assert matched is False
    assert snippet == ""


def test_all_alias_for_and():
    cond = {
        "all": [
            {"op": "contains", "value": "PowerShell"},
            {"op": "contains", "value": "EncodedCommand"},
        ]
    }
    matched, _ = evaluate_rule(cond, CTX)
    assert matched is True


# ── or / any ──────────────────────────────────────────────────────────────────

def test_or_first_matches():
    cond = {
        "or": [
            {"op": "contains", "value": "PowerShell"},
            {"op": "contains", "value": "mimikatz"},
        ]
    }
    matched, snippet = evaluate_rule(cond, CTX)
    assert matched is True
    assert "powershell" in snippet.lower()


def test_or_second_matches():
    cond = {
        "or": [
            {"op": "contains", "value": "mimikatz"},
            {"op": "contains", "value": "EncodedCommand"},
        ]
    }
    matched, snippet = evaluate_rule(cond, CTX)
    assert matched is True
    assert "EncodedCommand" in snippet or "encodedcommand" in snippet.lower()


def test_any_none_match():
    cond = {
        "any": [
            {"op": "contains", "value": "mimikatz"},
            {"op": "contains", "value": "cobalt strike"},
        ]
    }
    matched, snippet = evaluate_rule(cond, CTX)
    assert matched is False
    assert snippet == ""


# ── not ───────────────────────────────────────────────────────────────────────

def test_not_negates_match():
    cond = {"not": {"op": "contains", "value": "mimikatz"}}
    matched, _ = evaluate_rule(cond, CTX)
    assert matched is True  # mimikatz absent, so not(False) = True


def test_not_negates_present_value():
    cond = {"not": {"op": "contains", "value": "PowerShell"}}
    matched, _ = evaluate_rule(cond, CTX)
    assert matched is False  # PowerShell present, so not(True) = False


# ── nested compound ───────────────────────────────────────────────────────────

def test_nested_and_inside_or():
    """(contains mimikatz OR (contains PowerShell AND contains EncodedCommand))"""
    cond = {
        "or": [
            {"op": "contains", "value": "mimikatz"},
            {
                "and": [
                    {"op": "contains", "value": "PowerShell"},
                    {"op": "contains", "value": "EncodedCommand"},
                ]
            },
        ]
    }
    matched, snippet = evaluate_rule(cond, CTX)
    assert matched is True
    assert snippet != ""


def test_unknown_op_returns_false():
    """Unknown operators must return False safely — never raise."""
    cond = {"op": "explode", "value": "anything"}
    matched, snippet = evaluate_rule(cond, CTX)
    assert matched is False
    assert snippet == ""


# ═══════════════════════════════════════════════════════════════════════════════
# Part 2 — End-to-end API tests (submit → sanitize → evaluate → findings)
# ═══════════════════════════════════════════════════════════════════════════════

REGISTER_URL   = "/api/auth/register"
LOGIN_URL      = "/api/auth/login"
SUBMISSIONS    = "/api/submissions"
RULES_SEED     = "/api/rules/seed"
RULES_LIST     = "/api/rules"

_ANALYST = {"email": "rultest_analyst@test.com", "password": "P@ssw0rd!!"}
_ADMIN   = {"email": "rultest_admin@test.com",   "password": "P@ssw0rd!!", "role": "admin"}


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


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_seed_and_list_rules(client):
    admin_tok = _token(client, _ADMIN)

    r = client.post(RULES_SEED, headers=_auth(admin_tok))
    assert r.status_code == 201
    data = r.json()
    assert data["rules_created"] == 15
    assert data["total_seed_rules"] == 15

    # Idempotent second call
    r2 = client.post(RULES_SEED, headers=_auth(admin_tok))
    assert r2.json()["rules_created"] == 0

    # List rules
    r3 = client.get(RULES_LIST, headers=_auth(admin_tok))
    assert r3.status_code == 200
    assert len(r3.json()) == 15


def test_analyst_cannot_manage_rules(client):
    analyst_tok = _token(client, _ANALYST)
    headers = _auth(analyst_tok)
    rule_body = {"name": "Unauthorized", "condition_json": {"op": "contains", "value": "x"}}

    assert client.post(RULES_LIST, json=rule_body, headers=headers).status_code == 403
    assert client.put(f"{RULES_LIST}/1", json={"name": "Unauthorized"}, headers=headers).status_code == 403
    assert client.delete(f"{RULES_LIST}/1", headers=headers).status_code == 403


def test_evaluate_submission_finds_powershell_rule(client):
    """Submit a PowerShell-laced alert, seed rules, evaluate → finding created."""
    analyst_tok = _token(client, _ANALYST)
    admin_tok   = _token(client, _ADMIN)

    # Seed rules
    client.post(RULES_SEED, headers=_auth(admin_tok))

    # Create a submission that should trigger the PowerShell encoded-command rule
    text = (
        "Alert: Suspicious process spawned. "
        "Parent: winword.exe → Child: powershell -EncodedCommand VABCDEFGHIJ. "
        "Severity: High."
    )
    sub = client.post(SUBMISSIONS, json={"raw_text": text, "source_type": "alert"}, headers=_auth(analyst_tok))
    assert sub.status_code == 201
    sub_id = sub.json()["id"]

    # Evaluate
    ev = client.post(f"{SUBMISSIONS}/{sub_id}/evaluate", headers=_auth(analyst_tok))
    assert ev.status_code == 200
    data = ev.json()
    assert data["rules_evaluated"] == 15
    assert data["findings_created"] >= 1

    # Verify at least the PowerShell rule triggered
    rule_names = [f["rule_name"] for f in data["findings"]]
    assert any("PowerShell" in n or "powershell" in n.lower() for n in rule_names)


def test_submission_intake_evaluates_rules_and_lists_severity_counts(client):
    analyst_tok = _token(client, _ANALYST)
    admin_tok = _token(client, _ADMIN)
    client.post(RULES_SEED, headers=_auth(admin_tok))

    submitted = client.post(
        SUBMISSIONS,
        json={"raw_text": "mimikatz detected; lsass dump from 10.0.0.8", "source_type": "alert"},
        headers=_auth(analyst_tok),
    )
    assert submitted.status_code == 201
    submission_id = submitted.json()["id"]

    findings = client.get(f"{SUBMISSIONS}/{submission_id}/findings", headers=_auth(analyst_tok))
    assert findings.status_code == 200
    assert findings.json()

    listing = client.get(SUBMISSIONS, headers=_auth(analyst_tok)).json()
    row = next(item for item in listing["items"] if item["id"] == submission_id)
    assert sum(row["findings_by_severity"].values()) == len(findings.json())


def test_evaluate_submission_ipv4_ioc(client):
    """A submission with an IPv4 address triggers the IOC: IPv4 Address rule."""
    analyst_tok = _token(client, _ANALYST)
    admin_tok   = _token(client, _ADMIN)
    client.post(RULES_SEED, headers=_auth(admin_tok))

    sub = client.post(
        SUBMISSIONS,
        json={"raw_text": "Connection from 10.0.0.1 detected on port 443.", "source_type": "log"},
        headers=_auth(analyst_tok),
    )
    sub_id = sub.json()["id"]
    ev = client.post(f"{SUBMISSIONS}/{sub_id}/evaluate", headers=_auth(analyst_tok))
    assert ev.status_code == 200
    rule_names = [f["rule_name"] for f in ev.json()["findings"]]
    assert any("IPv4" in n for n in rule_names)


def test_evaluate_clean_submission_no_findings(client):
    """A benign submission produces zero findings."""
    analyst_tok = _token(client, _ANALYST)
    admin_tok   = _token(client, _ADMIN)
    client.post(RULES_SEED, headers=_auth(admin_tok))

    sub = client.post(
        SUBMISSIONS,
        json={"raw_text": "User logged in successfully at 09:00 UTC.", "source_type": "log"},
        headers=_auth(analyst_tok),
    )
    sub_id = sub.json()["id"]
    ev = client.post(f"{SUBMISSIONS}/{sub_id}/evaluate", headers=_auth(analyst_tok))
    assert ev.status_code == 200
    assert ev.json()["findings_created"] == 0


def test_get_findings_endpoint(client):
    """GET /api/submissions/{id}/findings returns the persisted findings."""
    analyst_tok = _token(client, _ANALYST)
    admin_tok   = _token(client, _ADMIN)
    client.post(RULES_SEED, headers=_auth(admin_tok))

    sub = client.post(
        SUBMISSIONS,
        json={"raw_text": "mimikatz detected on host-5, lsass dump found.", "source_type": "alert"},
        headers=_auth(analyst_tok),
    )
    sub_id = sub.json()["id"]
    client.post(f"{SUBMISSIONS}/{sub_id}/evaluate", headers=_auth(analyst_tok))

    r = client.get(f"{SUBMISSIONS}/{sub_id}/findings", headers=_auth(analyst_tok))
    assert r.status_code == 200
    findings = r.json()
    assert len(findings) >= 1
    # Each finding must have required fields
    for f in findings:
        assert "rule_name" in f
        assert "severity" in f
        assert "submission_id" in f


def test_evaluate_requires_auth(client):
    r = client.post("/api/submissions/1/evaluate")
    assert r.status_code == 401


def test_evaluate_nonexistent_submission(client):
    analyst_tok = _token(client, _ANALYST)
    r = client.post("/api/submissions/99999/evaluate", headers=_auth(analyst_tok))
    assert r.status_code == 404


def test_evaluate_is_idempotent(client):
    """Calling evaluate twice should not double findings."""
    analyst_tok = _token(client, _ANALYST)
    admin_tok   = _token(client, _ADMIN)
    client.post(RULES_SEED, headers=_auth(admin_tok))

    sub = client.post(
        SUBMISSIONS,
        json={"raw_text": "AutoOpen macro triggered in Document_Open", "source_type": "report"},
        headers=_auth(analyst_tok),
    )
    sub_id = sub.json()["id"]

    ev1 = client.post(f"{SUBMISSIONS}/{sub_id}/evaluate", headers=_auth(analyst_tok))
    ev2 = client.post(f"{SUBMISSIONS}/{sub_id}/evaluate", headers=_auth(analyst_tok))

    assert ev1.json()["findings_created"] == ev2.json()["findings_created"]
