"""Strict second-pass sanitization for optional external intelligence sharing."""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Sequence
from typing import Any

from app.core.config import settings
from app.models.mitre_technique import MitreTechnique
from app.models.organization import Organization
from app.models.raw_submission import RawSubmission
from app.models.rule import Finding
from app.sanitization.sanitizer import sanitize

_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_IP_ADDRESS = re.compile(
    r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])|"
    r"(?<![\w:])(?:[0-9A-F]{0,4}:){2,7}[0-9A-F]{0,4}(?![\w:])",
    re.IGNORECASE,
)
_HASH = re.compile(
    r"(?<![0-9A-F])(?:[0-9A-F]{32}|[0-9A-F]{40}|[0-9A-F]{64})(?![0-9A-F])",
    re.IGNORECASE,
)
_URL = re.compile(r"\b(?:https?://|ftp://)\S+", re.IGNORECASE)
_DOMAIN = re.compile(
    r"(?<![@\w-])(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"
    r"(?:[A-Z]{2,63}|local|internal|corp|lan|home|test)\b",
    re.IGNORECASE,
)
_HOST_ASSIGNMENT = re.compile(
    r"(?i)\b(?:host(?:name)?|computer(?:name)?|server)\s*[=:]\s*"
    r"[A-Z0-9_.-]+"
)
_USER_ASSIGNMENT = re.compile(
    r"(?i)\b(?:user(?:name)?|account|login)\s*[=:]\s*"
    r"(?:[A-Z0-9_.-]+\\)?[A-Z0-9_.-]+"
)
_DOMAIN_USER = re.compile(r"\b[A-Z0-9_.-]+\\[A-Z0-9_.-]+\b", re.IGNORECASE)
_USERNAME_TOKEN = re.compile(r"(?<![\w.-])@[A-Z0-9_.-]{2,}(?![\w.-])", re.IGNORECASE)
_PERSON_NAME = re.compile(
    r"\b[A-Z][a-z]{1,30}(?:[-'][A-Z]?[a-z]{1,30})?"
    r"(?:\s+[A-Z][a-z]{1,30}(?:[-'][A-Z]?[a-z]{1,30})?){1,2}\b"
)
_MITRE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


class SharingOptInRequiredError(PermissionError):
    """Raised when a caller attempts payload construction while opted out."""


def _as_enum_value(value: Any) -> str:
    return str(getattr(value, "value", value))


def _ip_in_networks(value: str, networks: Sequence[ipaddress._BaseNetwork]) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(address.version == network.version and address in network for network in networks)


def _is_denied_hostname(value: str, internal_hostnames: Sequence[str]) -> bool:
    normalized = value.rstrip(".").lower()
    return any(
        normalized == hostname.rstrip(".").lower()
        or normalized.endswith("." + hostname.rstrip(".").lower())
        for hostname in internal_hostnames
        if hostname.strip()
    )


def _redact_text(
    text: str,
    *,
    org_name: str,
    internal_ranges: Sequence[str],
    internal_hostnames: Sequence[str],
    internal_usernames: Sequence[str],
    allowlisted_iocs: frozenset[str],
) -> str:
    deny_networks = [ipaddress.ip_network(value, strict=False) for value in internal_ranges]
    redacted = sanitize(text, redact_pii=True).sanitized_text
    allowed_values = frozenset(value.strip().lower() for value in allowlisted_iocs)
    protected_iocs: dict[str, str] = {}

    def protect(match: re.Match[str]) -> str:
        value = match.group(0)
        normalized = value.lower()
        if normalized not in allowed_values:
            return value
        if _ip_in_networks(value, deny_networks) or _is_denied_hostname(
            value,
            internal_hostnames,
        ):
            return value
        embedded_ips = _IP_ADDRESS.findall(value)
        if any(_ip_in_networks(address, deny_networks) for address in embedded_ips):
            return value
        embedded_domains = _DOMAIN.findall(value)
        if any(
            _is_denied_hostname(domain, internal_hostnames)
            for domain in embedded_domains
        ):
            return value
        marker = f"__SHARING_ALLOWED_IOC_{len(protected_iocs)}__"
        protected_iocs[marker] = value
        return marker

    # Protect only explicit allow-list entries; private addresses and internal
    # hostnames remain denied even if accidentally present in the allow-list.
    for pattern in (_URL, _IP_ADDRESS, _HASH, _DOMAIN):
        redacted = pattern.sub(protect, redacted)

    for value in (org_name, *internal_hostnames, *internal_usernames):
        value = value.strip()
        if value:
            redacted = re.sub(re.escape(value), "[ORG_DATA_REDACTED]", redacted, flags=re.IGNORECASE)

    redacted = _EMAIL.sub("[USER_REDACTED]", redacted)
    redacted = _HOST_ASSIGNMENT.sub("[HOST_REDACTED]", redacted)
    redacted = _USER_ASSIGNMENT.sub("[USER_REDACTED]", redacted)
    redacted = _DOMAIN_USER.sub("[USER_REDACTED]", redacted)
    redacted = _USERNAME_TOKEN.sub("[USER_REDACTED]", redacted)
    redacted = _PERSON_NAME.sub("[PERSON_REDACTED]", redacted)

    def redact_ip(match: re.Match[str]) -> str:
        candidate = match.group(0)
        if candidate in allowlisted_iocs and not _ip_in_networks(candidate, deny_networks):
            return candidate
        if _ip_in_networks(candidate, deny_networks):
            return "[INTERNAL_IP_REDACTED]"
        return "[IOC_REDACTED]"

    redacted = _IP_ADDRESS.sub(redact_ip, redacted)

    def redact_hash(match: re.Match[str]) -> str:
        candidate = match.group(0)
        return candidate if candidate.lower() in allowed_values else "[IOC_REDACTED]"

    redacted = _HASH.sub(redact_hash, redacted)

    def is_denied_url(value: str) -> bool:
        embedded_ips = _IP_ADDRESS.findall(value)
        if any(_ip_in_networks(address, deny_networks) for address in embedded_ips):
            return True
        embedded_domains = _DOMAIN.findall(value)
        return any(
            _is_denied_hostname(domain, internal_hostnames)
            for domain in embedded_domains
        )

    redacted = _URL.sub(
        lambda match: (
            match.group(0)
            if match.group(0).lower() in allowed_values
            and not is_denied_url(match.group(0))
            else "[IOC_REDACTED]"
        ),
        redacted,
    )
    redacted = _DOMAIN.sub(
        lambda match: (
            match.group(0)
            if match.group(0).lower() in allowed_values
            and not _is_denied_hostname(match.group(0), internal_hostnames)
            else "[HOST_REDACTED]"
        ),
        redacted,
    )

    # A second pass catches credentials introduced or exposed by previous text shapes.
    redacted = sanitize(redacted, redact_pii=True).sanitized_text
    for marker, value in protected_iocs.items():
        redacted = redacted.replace(marker, value)
    return redacted


def _extract_embedding(value: Any) -> list[float] | None:
    if value is None:
        return None
    if hasattr(value, "tolist"):
        value = value.tolist()
    if isinstance(value, str):
        import json

        value = json.loads(value)
    if not isinstance(value, (list, tuple)):
        raise ValueError("Submission embedding must be a numeric vector")
    try:
        return [float(item) for item in value]
    except (TypeError, ValueError) as exc:
        raise ValueError("Submission embedding must contain only numeric values") from exc


def _rule_category(finding: Finding) -> str | None:
    rule = finding.rule
    name = getattr(rule, "name", None) if rule is not None else None
    if not name or ":" not in name:
        return None
    category = name.split(":", 1)[0].strip()
    if not category or not re.fullmatch(r"[A-Za-z][A-Za-z0-9 &/_-]{0,79}", category):
        return None
    return category.lower().replace("&", "and")


def build_shared_intel_payload(
    organization: Organization,
    submission: RawSubmission,
    findings: Iterable[Finding],
    techniques: Iterable[MitreTechnique | str],
    *,
    internal_ranges: Sequence[str] | None = None,
    internal_hostnames: Sequence[str] | None = None,
    internal_usernames: Sequence[str] | None = None,
    allowlisted_iocs: Iterable[str] = (),
) -> dict[str, Any]:
    """Build the strict external schema only after verifying explicit org opt-in.

    Returns only sanitized text, rule categories, ATT&CK IDs, severity values,
    and the optional embedding. Org/user/submission identifiers never enter the
    returned payload; authenticated transport provides org attribution.
    """
    if organization.share_with_network is not True:
        raise SharingOptInRequiredError(
            "Organization must explicitly opt in before building shared payloads"
        )

    source_text = submission.sanitized_text or sanitize(
        submission.raw_text,
        redact_pii=True,
    ).sanitized_text
    payload_text = _redact_text(
        source_text,
        org_name=organization.name,
        internal_ranges=(
            list(internal_ranges)
            if internal_ranges is not None
            else settings.SHARING_INTERNAL_RANGES
        ),
        internal_hostnames=(
            list(internal_hostnames)
            if internal_hostnames is not None
            else settings.SHARING_INTERNAL_HOSTNAMES
        ),
        internal_usernames=(
            list(internal_usernames)
            if internal_usernames is not None
            else settings.SHARING_INTERNAL_USERNAMES
        ),
        allowlisted_iocs=frozenset(allowlisted_iocs),
    )

    findings = tuple(findings)
    categories = sorted(
        {category for finding in findings if (category := _rule_category(finding))}
    )
    severities = sorted({_as_enum_value(finding.severity) for finding in findings})
    technique_ids = {
        technique
        for finding in findings
        if finding.rule is not None
        and (technique := getattr(finding.rule, "mitre_technique_id", None))
    }
    for technique in techniques:
        technique_id = technique if isinstance(technique, str) else technique.id
        if _MITRE_ID.fullmatch(technique_id):
            technique_ids.add(technique_id.upper())

    return {
        "sanitized_text": payload_text,
        "rule_categories": categories,
        "mitre_technique_ids": sorted(technique_ids),
        "severity": severities,
        "embedding": _extract_embedding(submission.embedding),
    }
