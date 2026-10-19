"""Tests for the opt-in-gated outbound intelligence payload."""
from types import SimpleNamespace

import pytest

from app.models.organization import Organization
from app.models.rule import Severity
from app.sharing.payload import (
    SharingOptInRequiredError,
    build_shared_intel_payload,
)


@pytest.mark.parametrize(
    ("source", "expected_tokens"),
    [
        (
            "Org=Northwind Security hostname=dc01.northwind.local",
            ("Northwind Security", "dc01.northwind.local"),
        ),
        (
            "Employee Alice Smith username=asmith DOMAIN\\jdoe alice@example.org",
            ("Alice Smith", "asmith", "jdoe", "alice@example.org"),
        ),
        (
            "internal 10.24.8.3 and custom range 198.51.100.19",
            ("10.24.8.3", "198.51.100.19"),
        ),
        (
            "IOC 203.0.113.7 hash "
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef "
            "at https://malware.example/path",
            (
                "203.0.113.7",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "https://malware.example/path",
            ),
        ),
    ],
)
def test_second_pass_redacts_org_user_host_and_ioc_patterns(source, expected_tokens):
    organization = Organization(
        id=7,
        name="Northwind Security",
        share_with_network=True,
    )
    submission = SimpleNamespace(
        raw_text=source,
        sanitized_text=source,
        embedding=[0.1, 0.2],
    )

    payload = build_shared_intel_payload(
        organization,
        submission,
        findings=[],
        techniques=[],
        internal_ranges=["10.0.0.0/8", "198.51.100.0/24"],
        internal_hostnames=["northwind.local"],
        internal_usernames=["asmith", "jdoe"],
    )
    body = payload["sanitized_text"]

    for token in expected_tokens:
        assert token.lower() not in body.lower()
    assert "REDACTED" in body


def test_only_allowlisted_public_iocs_are_preserved():
    organization = Organization(
        id=7,
        name="Northwind Security",
        share_with_network=True,
    )
    submission = SimpleNamespace(
        raw_text="",
        sanitized_text="External 203.0.113.7, internal 10.0.0.8",
        embedding=[0.1],
    )

    payload = build_shared_intel_payload(
        organization,
        submission,
        findings=[],
        techniques=[],
        internal_ranges=["10.0.0.0/8"],
        allowlisted_iocs=["203.0.113.7", "10.0.0.8"],
    )

    assert "203.0.113.7" in payload["sanitized_text"]
    assert "10.0.0.8" not in payload["sanitized_text"]


def test_payload_contains_only_approved_fields_and_no_rule_text():
    organization = Organization(
        id=7,
        name="Northwind Security",
        share_with_network=True,
    )
    submission = SimpleNamespace(
        raw_text="",
        sanitized_text="Suspicious encoded command",
        embedding=[0.25, 0.75],
        user_id=91,
        id=402,
    )
    finding = SimpleNamespace(
        severity=Severity.high,
        rule=SimpleNamespace(
            name="Suspicious PowerShell: Proprietary detector implementation",
            description="Internal confidential description",
            mitre_technique_id="T1059.001",
        ),
    )

    payload = build_shared_intel_payload(
        organization,
        submission,
        findings=[finding],
        techniques=["T1059.001"],
    )

    assert set(payload) == {
        "sanitized_text",
        "rule_categories",
        "mitre_technique_ids",
        "severity",
        "embedding",
    }
    assert payload["rule_categories"] == ["suspicious powershell"]
    assert payload["mitre_technique_ids"] == ["T1059.001"]
    assert payload["severity"] == ["high"]
    assert payload["embedding"] == [0.25, 0.75]
    assert "Proprietary" not in str(payload)
    assert "Northwind" not in str(payload)
    assert "user_id" not in str(payload)
    assert "402" not in str(payload)


def test_opt_out_organization_never_builds_a_payload():
    organization = Organization(
        id=7,
        name="Northwind Security",
        share_with_network=False,
    )

    class UnreadableSubmission:
        @property
        def raw_text(self):
            raise AssertionError("submission must not be accessed while opted out")

    with pytest.raises(SharingOptInRequiredError):
        build_shared_intel_payload(
            organization,
            UnreadableSubmission(),
            findings=[],
            techniques=[],
        )


def test_default_organization_sharing_setting_is_opted_out():
    organization = Organization(name="Default Organization")
    assert Organization.__table__.c.share_with_network.default.arg is False
    assert organization.share_with_network is None


def test_uninitialized_opt_in_state_fails_closed():
    organization = Organization(name="Default Organization")
    with pytest.raises(SharingOptInRequiredError):
        build_shared_intel_payload(
            organization,
            SimpleNamespace(),
            findings=[],
            techniques=[],
        )
