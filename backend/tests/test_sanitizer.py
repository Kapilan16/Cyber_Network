"""
Unit tests for the sanitization pipeline.

The sanitizer performs pure text transformation only — it never executes,
evaluates, or interprets any content.  These tests verify that:

  1.  Control characters are stripped
  2.  Encoding is normalised (bytes → UTF-8, NFC)
  3.  Whitespace is normalised (CRLF, trailing spaces, excess blank lines)
  4.  Content is truncated at MAX_SUBMISSION_LENGTH
  5.  AWS access key IDs are redacted
  6.  Private-key PEM headers are redacted
  7.  Generic API-key assignments are redacted
  8.  Email addresses are redacted when redact_pii=True
  9.  Email addresses are preserved when redact_pii=False
  10. Shell command patterns are flagged (content kept, status = flagged)
  11. Script eval patterns are flagged
  12. Clean text produces status=clean with zero redactions/flags
"""
import pytest

from app.models.raw_submission import SanitizationStatus
from app.sanitization.sanitizer import sanitize


# ─── 1. Control-character stripping ──────────────────────────────────────────

def test_strips_null_bytes():
    raw = "normal\x00text\x00with\x00nulls"
    result = sanitize(raw)
    assert "\x00" not in result.sanitized_text
    assert "normaltext" in result.sanitized_text.replace("withnulls", "withnulls")


def test_strips_escape_and_bell():
    """ESC (0x1B), BEL (0x07), BS (0x08) must be removed; tab/LF kept."""
    raw = "line1\x1b[31mred\x07\x08\nline2\t indented"
    result = sanitize(raw)
    assert "\x1b" not in result.sanitized_text
    assert "\x07" not in result.sanitized_text
    assert "\x08" not in result.sanitized_text
    assert "\n" in result.sanitized_text     # LF preserved
    assert "\t" in result.sanitized_text     # tab preserved


def test_strips_c1_control_range():
    """C1 block (0x80-0x9F) should be stripped."""
    raw = "start\x80\x9fend"
    result = sanitize(raw)
    assert "\x80" not in result.sanitized_text
    assert "\x9f" not in result.sanitized_text
    assert "startend" in result.sanitized_text


# ─── 2. Encoding / Unicode normalisation ─────────────────────────────────────

def test_decodes_bytes_utf8():
    raw_bytes = "héllo wörld".encode("utf-8")
    result = sanitize(raw_bytes)
    assert "héllo" in result.sanitized_text
    assert "wörld" in result.sanitized_text


def test_handles_invalid_utf8_bytes():
    """Invalid byte sequences are replaced, not raised."""
    raw_bytes = b"good\xff\xfebad"
    result = sanitize(raw_bytes)
    assert "good" in result.sanitized_text
    assert "bad" in result.sanitized_text


def test_nfc_normalization():
    """Decomposed 'é' (e + combining accent) should normalise to composed 'é'."""
    decomposed = "e\u0301"   # 'e' + combining acute accent  (NFC → é)
    result = sanitize(decomposed)
    # After NFC the string should be the single composed character
    assert result.sanitized_text.strip() == "\xe9"  # é


# ─── 3. Whitespace normalisation ─────────────────────────────────────────────

def test_normalises_crlf():
    raw = "line1\r\nline2\r\nline3"
    result = sanitize(raw)
    assert "\r" not in result.sanitized_text
    assert result.sanitized_text == "line1\nline2\nline3"


def test_collapses_excess_blank_lines():
    raw = "para1\n\n\n\n\npara2"
    result = sanitize(raw)
    assert "\n\n\n" not in result.sanitized_text
    assert "para1" in result.sanitized_text
    assert "para2" in result.sanitized_text


def test_strips_trailing_whitespace_per_line():
    raw = "line1   \nline2\t  \nline3"
    result = sanitize(raw)
    for line in result.sanitized_text.splitlines():
        assert line == line.rstrip(), f"trailing whitespace on: {line!r}"


# ─── 4. Truncation ───────────────────────────────────────────────────────────

def test_truncation_at_max_length():
    raw = "A" * 200
    result = sanitize(raw, max_length=100)
    assert result.was_truncated is True
    assert "[TRUNCATED" in result.sanitized_text
    # Actual text portion before truncation marker should be ≤ max_length
    body = result.sanitized_text.split("\n")[0]
    assert len(body) <= 100


def test_no_truncation_within_limit():
    raw = "short text"
    result = sanitize(raw, max_length=1000)
    assert result.was_truncated is False
    assert "short text" in result.sanitized_text


# ─── 5. AWS access key redaction ─────────────────────────────────────────────

def test_redacts_aws_access_key_id():
    raw = "Key: AKIAIOSFODNN7EXAMPLE is the access key"
    result = sanitize(raw)
    assert "AKIAIOSFODNN7EXAMPLE" not in result.sanitized_text
    assert "[REDACTED]" in result.sanitized_text
    assert result.redaction_count >= 1
    assert result.status in (SanitizationStatus.redacted, SanitizationStatus.flagged)


def test_redacts_asia_key_variant():
    # ASIA prefix (4 chars) + exactly 16 uppercase alphanumeric chars = 20-char AWS temp key
    raw = "Temporary key: ASIAIOSFODNN7EXAMPLE for session"
    result = sanitize(raw)
    assert "ASIAIOSFODNN7EXAMPLE" not in result.sanitized_text
    assert "[REDACTED]" in result.sanitized_text



# ─── 6. Private-key PEM header redaction ─────────────────────────────────────

def test_redacts_rsa_private_key_header():
    raw = "Config:\n-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
    result = sanitize(raw)
    # Original PEM header text must not survive verbatim
    assert "BEGIN RSA PRIVATE KEY-----\nMIIE" not in result.sanitized_text
    assert "[PRIVATE_KEY_REDACTED]" in result.sanitized_text
    assert result.redaction_count >= 1


def test_redacts_openssh_private_key_header():
    raw = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNz...\n-----END OPENSSH PRIVATE KEY-----"
    result = sanitize(raw)
    assert "[PRIVATE_KEY_REDACTED]" in result.sanitized_text


# ─── 7. Generic API-key / token redaction ────────────────────────────────────

def test_redacts_api_key_assignment():
    raw = "api_key=abcdef1234567890abcdef1234567890"
    result = sanitize(raw)
    assert "abcdef1234567890abcdef1234567890" not in result.sanitized_text
    assert "[REDACTED]" in result.sanitized_text
    assert result.redaction_count >= 1


def test_redacts_bearer_token():
    # Use a plain alphanumeric token (no dots) to match GENERIC_API_KEY pattern reliably
    raw = "Authorization: Bearer abcdefghij1234567890ABCDEF"
    result = sanitize(raw)
    assert "abcdefghij1234567890ABCDEF" not in result.sanitized_text
    assert "[REDACTED]" in result.sanitized_text


# ─── 8. Email redaction (PII) ────────────────────────────────────────────────

def test_redacts_email_when_pii_enabled():
    raw = "Contact analyst john.doe@example.com for details."
    result = sanitize(raw, redact_pii=True)
    assert "john.doe@example.com" not in result.sanitized_text
    assert "[EMAIL_REDACTED]" in result.sanitized_text
    assert result.redaction_count >= 1


def test_preserves_email_when_pii_disabled():
    raw = "Contact analyst john.doe@example.com for details."
    result = sanitize(raw, redact_pii=False)
    assert "john.doe@example.com" in result.sanitized_text
    assert "[EMAIL_REDACTED]" not in result.sanitized_text


# ─── 9. Multiple redactions ───────────────────────────────────────────────────

def test_multiple_secrets_all_redacted():
    raw = (
        "api_key=secretvalue12345678901234\n"
        "Contact: admin@corp.example.com\n"
        "Key: AKIAIOSFODNN7EXAMPLE access\n"
    )
    result = sanitize(raw, redact_pii=True)
    assert "secretvalue12345678901234" not in result.sanitized_text
    assert "admin@corp.example.com" not in result.sanitized_text
    assert "AKIAIOSFODNN7EXAMPLE" not in result.sanitized_text
    assert result.redaction_count >= 3


# ─── 10. Shell pattern detection ─────────────────────────────────────────────

def test_flags_shell_command_substitution():
    """$(whoami) is suspicious — must be flagged, content kept as inert text."""
    raw = "Server info: $(whoami) running on host"
    result = sanitize(raw)
    assert result.flag_count >= 1
    assert result.status == SanitizationStatus.flagged
    # Content is kept — pipeline does NOT strip or execute it
    assert "$(whoami)" in result.sanitized_text
    assert any("shell_substitution" in w for w in result.warnings)


def test_flags_dangerous_rm_rf():
    raw = "cleanup script: rm -rf /tmp/data"
    result = sanitize(raw)
    assert result.flag_count >= 1
    assert result.status == SanitizationStatus.flagged
    assert any("shell_redirect" in w for w in result.warnings)


# ─── 11. Script eval detection ────────────────────────────────────────────────

def test_flags_eval_call():
    raw = "The log contains: eval(user_input) at line 42"
    result = sanitize(raw)
    assert result.flag_count >= 1
    assert result.status == SanitizationStatus.flagged
    assert any("script_eval" in w for w in result.warnings)
    # Content must NOT be executed — it's kept as literal text
    assert "eval(user_input)" in result.sanitized_text


def test_flags_os_module_access():
    raw = "Malicious payload detected: import os; os.system('id')"
    result = sanitize(raw)
    assert result.flag_count >= 1
    assert any("os_module_access" in w for w in result.warnings)


# ─── 12. Clean input ─────────────────────────────────────────────────────────

def test_clean_text_produces_clean_status():
    raw = (
        "ALERT: Unusual login attempt from IP 192.168.1.45\n"
        "Severity: Medium\n"
        "Timestamp: 2026-09-27T08:00:00Z\n"
        "Action: Investigate"
    )
    result = sanitize(raw, redact_pii=False)
    assert result.status == SanitizationStatus.clean
    assert result.redaction_count == 0
    assert result.flag_count == 0
    assert result.warnings == []
    assert "192.168.1.45" in result.sanitized_text
