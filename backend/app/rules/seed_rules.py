"""
Seed data — 15 illustrative detection rules.

These are example detection patterns for an analyst-facing SOC platform.
They match text phrases that *describe* or *report on* suspicious activity,
as an analyst would write them in alert text, log excerpts, or threat reports.
They are purely illustrative — not attack payloads.
"""
from __future__ import annotations

from app.enrichment.iocs import IPV4_PATTERN, MD5_PATTERN, SHA256_PATTERN

SEED_RULES: list[dict] = [
    # ── Credential exposure ────────────────────────────────────────────────
    {
        "name": "Credential Exposure: Plaintext Password Mention",
        "description": "Submission text contains phrases consistent with a plaintext password being reported.",
        "severity": "high",
        "mitre_technique_id": "T1552.001",
        "condition_json": {
            "any": [
                {"op": "contains", "value": "password is"},
                {"op": "contains", "value": "my password"},
                {"op": "contains", "value": "cleartext password"},
                {"op": "contains", "value": "password in plaintext"},
            ]
        },
    },
    {
        "name": "Credential Exposure: AWS Access Key Pattern",
        "description": "Submission contains an AWS-style access key ID prefix (AKIA/ASIA).",
        "severity": "critical",
        "mitre_technique_id": "T1552.005",
        "condition_json": {
            "op": "regex",
            "pattern": r"\b(AKIA|ASIA|AROA)[A-Z0-9]{16}\b",
        },
    },
    {
        "name": "Credential Exposure: Private Key Header Reference",
        "description": "Text references a PEM private key begin-header, suggesting key material was present.",
        "severity": "critical",
        "mitre_technique_id": "T1552.004",
        "condition_json": {
            "op": "contains",
            "value": "BEGIN PRIVATE KEY",
        },
    },

    # ── PowerShell / command execution ────────────────────────────────────
    {
        "name": "Suspicious PowerShell: Encoded Command",
        "description": "Text mentions PowerShell encoded-command flags commonly used to obfuscate execution.",
        "severity": "high",
        "mitre_technique_id": "T1059.001",
        "condition_json": {
            "any": [
                {"op": "contains", "value": "-EncodedCommand"},
                {"op": "contains", "value": "-enc "},
                {"op": "contains", "value": "powershell -e "},
                {"op": "regex",    "pattern": r"powershell\s+-[eE][nN][cC]"},
            ]
        },
    },
    {
        "name": "Suspicious PowerShell: Invoke-Expression Mention",
        "description": "Text references IEX or Invoke-Expression, common in obfuscated script reporting.",
        "severity": "high",
        "mitre_technique_id": "T1059.001",
        "condition_json": {
            "any": [
                {"op": "contains", "value": "Invoke-Expression"},
                {"op": "contains", "value": "IEX("},
                {"op": "regex",    "pattern": r"\bIEX\s*\("},
            ]
        },
    },

    # ── Phishing language ─────────────────────────────────────────────────
    {
        "name": "Phishing Language: Account Verification Request",
        "description": "Text contains phishing-characteristic account-verification language.",
        "severity": "medium",
        "mitre_technique_id": "T1566.002",
        "condition_json": {
            "any": [
                {"op": "contains", "value": "verify your account"},
                {"op": "contains", "value": "confirm your account"},
                {"op": "contains", "value": "validate your credentials"},
                {"op": "contains", "value": "account will be suspended"},
            ]
        },
    },
    {
        "name": "Phishing Language: Urgency Indicators",
        "description": "Text uses urgency language typical of social-engineering lures.",
        "severity": "medium",
        "mitre_technique_id": "T1566",
        "condition_json": {
            "any": [
                {"op": "contains", "value": "urgent action required"},
                {"op": "contains", "value": "immediate action"},
                {"op": "contains", "value": "your account has been compromised"},
                {"op": "contains", "value": "act now to secure"},
            ]
        },
    },

    # ── IOC patterns ──────────────────────────────────────────────────────
    {
        "name": "IOC: IPv4 Address",
        "description": "Submission contains one or more IPv4 address strings (potential network IOC).",
        "severity": "low",
        "mitre_technique_id": None,
        "condition_json": {
            "op": "regex",
            "pattern": IPV4_PATTERN,
        },
    },
    {
        "name": "IOC: MD5 Hash",
        "description": "Submission contains a 32-character hexadecimal string (potential MD5 file hash).",
        "severity": "low",
        "mitre_technique_id": None,
        "condition_json": {
            "op": "regex",
            "pattern": MD5_PATTERN,
        },
    },
    {
        "name": "IOC: SHA-256 Hash",
        "description": "Submission contains a 64-character hexadecimal string (potential SHA-256 file hash).",
        "severity": "low",
        "mitre_technique_id": None,
        "condition_json": {
            "op": "regex",
            "pattern": SHA256_PATTERN,
        },
    },

    # ── Malware / tooling mentions ─────────────────────────────────────────
    {
        "name": "Malware Tooling: Mimikatz / Pass-the-Hash",
        "description": "Text references mimikatz or pass-the-hash credential-theft technique.",
        "severity": "critical",
        "mitre_technique_id": "T1003.001",
        "condition_json": {
            "any": [
                {"op": "contains", "value": "mimikatz"},
                {"op": "contains", "value": "pass the hash"},
                {"op": "contains", "value": "pass-the-hash"},
                {"op": "contains", "value": "pth attack"},
            ]
        },
    },
    {
        "name": "Malware Tooling: Cobalt Strike / Beacon",
        "description": "Text mentions Cobalt Strike or beacon C2 framework activity.",
        "severity": "critical",
        "mitre_technique_id": "T1219",
        "condition_json": {
            "any": [
                {"op": "contains", "value": "cobalt strike"},
                {
                    "and": [
                        {"op": "contains", "value": "beacon"},
                        {"op": "contains", "value": "c2"},
                    ]
                },
                {"op": "contains", "value": "cs beacon"},
            ]
        },
    },

    # ── Credential dumping ────────────────────────────────────────────────
    {
        "name": "Credential Dumping: LSASS Reference",
        "description": "Text mentions LSASS process or SAM database in a dump/extraction context.",
        "severity": "critical",
        "mitre_technique_id": "T1003.001",
        "condition_json": {
            "any": [
                {
                    "and": [
                        {"op": "contains", "value": "lsass"},
                        {"op": "contains", "value": "dump"},
                    ]
                },
                {"op": "contains", "value": "SAM database"},
                {"op": "contains", "value": "credential dump"},
                {"op": "contains", "value": "ntds.dit"},
            ]
        },
    },

    # ── Lateral movement ──────────────────────────────────────────────────
    {
        "name": "Lateral Movement: PsExec / Admin Share",
        "description": "Text references PsExec or admin shares used for lateral movement.",
        "severity": "high",
        "mitre_technique_id": "T1021.002",
        "condition_json": {
            "any": [
                {"op": "contains", "value": "psexec"},
                {"op": "regex",    "pattern": r"\\\\[A-Za-z0-9_\-\.]+\\(admin|c|ipc)\$"},
                {"op": "contains", "value": "net use \\\\"},
            ]
        },
    },

    # ── Macro / Office weaponization ──────────────────────────────────────
    {
        "name": "Malicious Macro: Office AutoOpen Keywords",
        "description": "Text reports on VBA macro keywords associated with malicious Office documents.",
        "severity": "high",
        "mitre_technique_id": "T1137.001",
        "condition_json": {
            "any": [
                {"op": "contains", "value": "AutoOpen"},
                {"op": "contains", "value": "Document_Open"},
                {"op": "regex",    "pattern": r"\bShell\s*\("},
                {"op": "contains", "value": "Workbook_Open"},
            ]
        },
    },
]
