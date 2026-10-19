"""IOC extraction patterns shared with the built-in seed rules."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

IPV4_PATTERN = (
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
MD5_PATTERN = r"\b[0-9a-fA-F]{32}\b"
SHA1_PATTERN = r"\b[0-9a-fA-F]{40}\b"
SHA256_PATTERN = r"\b[0-9a-fA-F]{64}\b"
DOMAIN_PATTERN = (
    r"(?<![\w.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}\.?(?![\w.-])"
)

_IPV4_RE = re.compile(IPV4_PATTERN)
_IPV6_RE = re.compile(r"(?<![\w:])[0-9a-fA-F:]{2,39}(?![\w:])")
_DOMAIN_RE = re.compile(DOMAIN_PATTERN)
_MD5_RE = re.compile(MD5_PATTERN)
_SHA1_RE = re.compile(SHA1_PATTERN)
_SHA256_RE = re.compile(SHA256_PATTERN)
_NON_PUBLIC_DOMAIN_SUFFIXES = {
    "internal",
    "local",
    "localhost",
    "test",
    "invalid",
}


@dataclass(frozen=True)
class ExtractedIOC:
    ioc_type: str
    ioc_value: str
    externally_queryable: bool = True


def extract_iocs(text: str) -> list[ExtractedIOC]:
    """Extract unique IPs, domains, and MD5/SHA1/SHA256 hashes."""
    extracted: dict[tuple[str, str], ExtractedIOC] = {}

    for match in _IPV4_RE.finditer(text):
        value = match.group(0)
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        extracted[("ip", value)] = ExtractedIOC(
            "ip",
            value,
            externally_queryable=address.is_global,
        )

    for match in _IPV6_RE.finditer(text):
        value = match.group(0)
        if ":" not in value:
            continue
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        extracted[("ip", str(address).lower())] = ExtractedIOC(
            "ip",
            str(address).lower(),
            externally_queryable=address.is_global,
        )

    for match in _DOMAIN_RE.finditer(text):
        value = match.group(0).rstrip(".").lower()
        if value:
            extracted[("domain", value)] = ExtractedIOC(
                "domain",
                value,
                externally_queryable=(
                    value.rsplit(".", 1)[-1] not in _NON_PUBLIC_DOMAIN_SUFFIXES
                ),
            )

    for pattern in (_MD5_RE, _SHA1_RE, _SHA256_RE):
        for match in pattern.finditer(text):
            value = match.group(0).lower()
            extracted[("hash", value)] = ExtractedIOC("hash", value)

    return sorted(
        extracted.values(),
        key=lambda ioc: (ioc.ioc_type, ioc.ioc_value),
    )
