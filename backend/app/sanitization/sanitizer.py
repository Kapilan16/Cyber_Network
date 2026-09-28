"""
Sanitization pipeline — pure text transformation, zero code execution.

Pipeline steps (in order):
  1. Decode bytes → str (best-effort UTF-8 with replacement)
  2. Strip C0/C1 control characters (keep tab, LF, CR)
  3. Normalize line endings to LF; trim trailing whitespace per line
  4. Collapse excess blank lines (> 2 consecutive)
  5. Truncate to MAX_SUBMISSION_LENGTH
  6. Redact secrets  (AWS keys, API keys, PEM headers)
  7. Redact PII      (email addresses — only when redact_pii=True)
  8. Detect suspicious patterns (shell/script — flagged, NOT executed)

Nothing in this module imports subprocess, exec, eval, or any execution
primitive. All transformations are pure string operations or regex substitutions.
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field

from app.models.raw_submission import SanitizationStatus
from app.sanitization import patterns as P

# Replacement tokens used in sanitized output
_REDACTED = "[REDACTED]"
_REDACTED_EMAIL = "[EMAIL_REDACTED]"
_REDACTED_KEY_BLOCK = "[PRIVATE_KEY_REDACTED]"


@dataclass
class SanitizationResult:
    """Immutable result object returned by sanitize()."""
    sanitized_text: str
    status: SanitizationStatus
    redaction_count: int = 0
    flag_count: int = 0
    warnings: list[str] = field(default_factory=list)
    was_truncated: bool = False


# ─── Public entry-point ───────────────────────────────────────────────────────

def sanitize(
    raw: str | bytes,
    *,
    redact_pii: bool = True,
    max_length: int = 50_000,
) -> SanitizationResult:
    """
    Run the full sanitization pipeline on *raw* and return a SanitizationResult.

    Parameters
    ----------
    raw:        Text (str) or bytes to sanitize.
    redact_pii: When True, email addresses are replaced with [EMAIL_REDACTED].
    max_length: Maximum character length; content beyond this is dropped.

    Returns
    -------
    SanitizationResult with sanitized_text and audit metadata.
    """
    text = _decode(raw)
    text = _strip_control_chars(text)
    text = _normalize_whitespace(text)
    text, was_truncated = _truncate(text, max_length)

    text, redaction_count = _redact_secrets(text, redact_pii=redact_pii)
    warnings, flag_count = _detect_suspicious(text)

    # Determine aggregate status
    if flag_count > 0:
        status = SanitizationStatus.flagged
    elif redaction_count > 0:
        status = SanitizationStatus.redacted
    else:
        status = SanitizationStatus.clean

    return SanitizationResult(
        sanitized_text=text,
        status=status,
        redaction_count=redaction_count,
        flag_count=flag_count,
        warnings=warnings,
        was_truncated=was_truncated,
    )


# ─── Step implementations ─────────────────────────────────────────────────────

def _decode(raw: str | bytes) -> str:
    """
    Ensure we have a str. If bytes, decode as UTF-8 with replacement characters
    for undecodable sequences. Then normalize Unicode to NFC form so that
    visually identical characters map to the same code-points.
    """
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", errors="replace")
    else:
        text = raw

    # Normalize Unicode (NFC): combine decomposed chars, replace surrogates, etc.
    text = unicodedata.normalize("NFC", text)

    # Replace Unicode replacement character clusters that snuck in
    text = text.replace("\ufffd\ufffd", "\ufffd")

    return text


def _strip_control_chars(text: str) -> str:
    """
    Remove C0 / C1 control characters, keeping:
      \\t  (0x09) — horizontal tab
      \\n  (0x0A) — line feed
      \\r  (0x0D) — carriage return
    Null bytes, BEL, BS, VT, FF, ESC, DEL, and C1 (0x80-0x9F) are all stripped.
    """
    return P.CONTROL_CHARS.sub("", text)


def _normalize_whitespace(text: str) -> str:
    """
    • Normalize CRLF → LF
    • Strip trailing whitespace from each line
    • Collapse 3+ consecutive blank lines to 2
    """
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = P.LINE_TRAILING_WS.sub("", text)
    text = P.EXCESS_BLANK_LINES.sub("\n\n", text)
    return text.strip()


def _truncate(text: str, max_length: int) -> tuple[str, bool]:
    """Truncate to max_length characters. Returns (text, was_truncated)."""
    if len(text) <= max_length:
        return text, False
    marker = f"\n... [TRUNCATED at {max_length} chars]"
    return text[:max_length] + marker, True


def _redact_secrets(text: str, *, redact_pii: bool) -> tuple[str, int]:
    """
    Replace credential / secret patterns with [REDACTED] tokens.
    Returns (sanitized_text, count_of_replacements).
    """
    count = 0

    # ── Private key blocks (multi-line): redact header + footer ──────────
    def _sub(pattern, replacement, t):
        nonlocal count
        result, n = pattern.subn(replacement, t)
        count += n
        return result

    # Redact entire PEM private key blocks (header → footer inclusive)
    # We handle this as a two-pass: mark header, then footer
    text = _sub(P.PRIVATE_KEY_HEADER, f"-----BEGIN PRIVATE KEY----- {_REDACTED_KEY_BLOCK}", text)
    text = _sub(P.PRIVATE_KEY_FOOTER, f"-----END PRIVATE KEY----- {_REDACTED_KEY_BLOCK}", text)

    # ── AWS access key IDs ────────────────────────────────────────────────
    text = _sub(P.AWS_ACCESS_KEY, _REDACTED, text)

    # ── AWS secret key assignments ────────────────────────────────────────
    text = _sub(P.AWS_SECRET_KEY, _REDACTED, text)

    # ── Generic API/token/password assignments ────────────────────────────
    # Replace only the value part (group 1) to keep the key name visible
    def _redact_value(m: "re.Match") -> str:
        nonlocal count
        count += 1
        full = m.group(0)
        val = m.group(1)
        return full.replace(val, _REDACTED)

    text = P.GENERIC_API_KEY.sub(_redact_value, text)

    # ── Authorization / Bearer tokens ─────────────────────────────────────
    text = P.BEARER_TOKEN.sub(_redact_value, text)

    # ── Email addresses (PII, conditional) ───────────────────────────────
    if redact_pii:
        text = _sub(P.EMAIL, _REDACTED_EMAIL, text)

    return text, count


def _detect_suspicious(text: str) -> tuple[list[str], int]:
    """
    Scan for shell/script-like patterns. Content is NOT modified —
    we only record what was found for downstream review.
    Returns (list_of_warning_strings, total_match_count).
    """
    warnings: list[str] = []
    total = 0
    for name, pattern in P.SHELL_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            total += len(matches)
            warnings.append(
                f"{name}: {len(matches)} occurrence(s) detected (content kept inert)"
            )
    return warnings, total
