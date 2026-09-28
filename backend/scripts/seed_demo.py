#!/usr/bin/env python
"""
seed_demo.py — one-shot demo data loader for Cyber Network Stage 1.

Creates:
  • admin@cybernetwork.demo  / Admin@Demo2025!   (role=admin)
  • analyst@cybernetwork.demo / Analyst@Demo2025! (role=analyst)
  • 15 seed detection rules (via SEED_RULES)
  • 50 MITRE ATT&CK techniques
  • 20 sample submissions covering diverse security scenarios
    → each is sanitized, evaluated, and embedding attempted

Usage (from the backend/ directory):
    python scripts/seed_demo.py
Or with a custom DATABASE_URL:
    DATABASE_URL=postgresql+psycopg2://... python scripts/seed_demo.py
"""
from __future__ import annotations

import os
import sys
import logging

# ── Make sure 'app' is importable when run from backend/ ────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.core.database import Base
from app.core.security import hash_password
from app.models.user import User, UserRole
from app.models.rule import Rule, Finding
from app.models.raw_submission import RawSubmission, SourceType, EmbeddingStatus
from app.models.mitre_technique import MitreTechnique
from app.sanitization.sanitizer import sanitize
from app.rules.evaluator import evaluate_rule
from app.rules.seed_rules import SEED_RULES

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
log = logging.getLogger("seed_demo")

# ── Connection ────────────────────────────────────────────────────────────────

DATABASE_URL = os.environ.get("DATABASE_URL", settings.DATABASE_URL)

engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)

# ── Demo users ────────────────────────────────────────────────────────────────

DEMO_USERS = [
    {
        "email": "admin@cybernetwork.demo",
        "password": "Admin@Demo2025!",
        "role": UserRole.admin,
    },
    {
        "email": "analyst@cybernetwork.demo",
        "password": "Analyst@Demo2025!",
        "role": UserRole.analyst,
    },
]

# ── Sample submissions ────────────────────────────────────────────────────────

SAMPLE_SUBMISSIONS = [
    {
        "raw_text": (
            "CRITICAL ALERT: Brute-force login detected. User 'admin' had 47 failed "
            "login attempts from IP 203.0.113.42 within 5 minutes. Account temporarily locked."
        ),
        "source_type": SourceType.alert,
    },
    {
        "raw_text": (
            "PowerShell encoded command executed on WORKSTATION-04:\n"
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand "
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
        ),
        "source_type": SourceType.alert,
    },
    {
        "raw_text": (
            "Phishing email intercepted:\n"
            "Subject: URGENT - Your account will be suspended. Verify your credentials immediately.\n"
            "Sender: security-noreply@micros0ft-update.net\n"
            "Body: Click here to verify your account and avoid suspension: http://malicious-link.net/verify"
        ),
        "source_type": SourceType.report,
    },
    {
        "raw_text": (
            "Threat intelligence report — APT29 campaign indicators:\n"
            "C2 server IPs observed: 198.51.100.77, 198.51.100.88, 203.0.113.9\n"
            "Associated domains: cdn-update.onmicrosoft-live.com, secure-login.update-portal.net\n"
            "Technique: Spear-phishing with macro-enabled Office documents"
        ),
        "source_type": SourceType.report,
    },
    {
        "raw_text": (
            "2024-01-15 03:22:11 WARN sshd[4821]: Failed password for root from 45.89.172.33 "
            "port 54123 ssh2\n"
            "2024-01-15 03:22:13 WARN sshd[4821]: Failed password for root from 45.89.172.33 "
            "port 54123 ssh2\n"
            "2024-01-15 03:22:15 WARN sshd[4821]: Failed password for root from 45.89.172.33 "
            "port 54123 ssh2"
        ),
        "source_type": SourceType.log,
    },
    {
        "raw_text": (
            "Registry persistence mechanism detected:\n"
            "Key: HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
            "Value: 'WindowsUpdate' = 'C:\\Users\\Public\\svchost32.exe -hide'\n"
            "Process created by: explorer.exe (PID 1204)"
        ),
        "source_type": SourceType.alert,
    },
    {
        "raw_text": (
            "Data exfiltration alert: Large outbound transfer detected.\n"
            "Source: FINANCE-SRV-01 (10.0.1.50)\n"
            "Destination: 185.220.101.42:443 (Tor exit node)\n"
            "Volume: 2.3 GB transferred in 8 minutes\n"
            "User context: svc_backup (service account)"
        ),
        "source_type": SourceType.alert,
    },
    {
        "raw_text": (
            "Lateral movement detected: Pass-the-Hash attack pattern observed.\n"
            "Source host: WORKSTATION-07 (10.0.2.7)\n"
            "Target host: DOMAIN-CTRL-01 (10.0.0.5)\n"
            "NTLM hash re-use detected via Mimikatz signature in memory"
        ),
        "source_type": SourceType.alert,
    },
    {
        "raw_text": (
            "Malware detection — CrowdStrike Falcon:\n"
            "File: C:\\Temp\\invoice_q4.pdf.exe\n"
            "SHA256: 8f14e45fceea167a5a36dedd4bea2543b66b0e4bb0ba6b7a1c6c9e3a4bde8f9\n"
            "Classification: Trojan.GenericKD.64281234\n"
            "Action taken: Quarantined"
        ),
        "source_type": SourceType.alert,
    },
    {
        "raw_text": (
            "Credential dumping activity detected on DOMAIN-CTRL-01:\n"
            "Process: lsass.exe accessed by rundll32.exe\n"
            "Parent: cmd.exe spawned by: mshta.exe\n"
            "Command observed: sekurlsa::logonpasswords (Mimikatz pattern)"
        ),
        "source_type": SourceType.alert,
    },
    {
        "raw_text": (
            "Suspicious scheduled task created:\n"
            "Task name: \\Microsoft\\Windows\\UpdateOrchestrator\\Reboot_AC\n"
            "Action: C:\\Windows\\Temp\\updater.bat\n"
            "Trigger: At system startup\n"
            "Created by: NT AUTHORITY\\SYSTEM via cmd.exe"
        ),
        "source_type": SourceType.log,
    },
    {
        "raw_text": (
            "Network scan detected from internal host:\n"
            "Source: 10.0.5.133 (WORKSTATION-12)\n"
            "Scan type: SYN stealth scan (nmap -sS signature)\n"
            "Targets: 10.0.0.0/24 — 256 hosts scanned in 30 seconds\n"
            "Ports probed: 22, 80, 443, 3389, 8080, 8443"
        ),
        "source_type": SourceType.alert,
    },
    {
        "raw_text": (
            "Analyst notes — suspicious email campaign analysis:\n"
            "Campaign theme: HR policy update requiring urgent acknowledgment\n"
            "Attachment: HR_Policy_Update_2024.docm (macro-enabled Word document)\n"
            "Macro drops: VBScript loader → PowerShell → Cobalt Strike beacon\n"
            "Attribution: Medium confidence — TA505 TTPs"
        ),
        "source_type": SourceType.report,
    },
    {
        "raw_text": (
            "Web application firewall alert:\n"
            "Rule triggered: SQL Injection attempt\n"
            "Source IP: 91.195.240.7\n"
            "Request: GET /api/users?id=1' OR '1'='1'--\n"
            "Status: Blocked (HTTP 403)"
        ),
        "source_type": SourceType.alert,
    },
    {
        "raw_text": (
            "Cloud storage misconfiguration detected:\n"
            "Resource: S3 bucket 'company-backups-2024' \n"
            "Issue: Public read access enabled\n"
            "Contents exposed: 847 files including database dumps, configuration files\n"
            "Discovery method: Certificate Transparency log monitoring"
        ),
        "source_type": SourceType.report,
    },
    {
        "raw_text": (
            "2024-01-16 08:45:23 ERROR kernel: audit: type=1400 audit(1705387523.441:892): "
            "apparmor=DENIED operation=exec profile=unconfined name=/usr/bin/nmap "
            "pid=28431 comm=bash requested_mask=x denied_mask=x\n"
            "2024-01-16 08:45:30 ERROR kernel: DROP IN=eth0 OUT= MAC=ff:ff:ff:ff "
            "SRC=10.0.5.133 DST=10.0.0.1 PROTO=TCP DPT=22"
        ),
        "source_type": SourceType.log,
    },
    {
        "raw_text": (
            "Insider threat indicator — DLP alert:\n"
            "User: jdoe@company.com\n"
            "Action: Mass file download from SharePoint\n"
            "Files downloaded: 1,247 documents (3.8 GB) in 15 minutes\n"
            "Context: User submitted resignation 3 days prior\n"
            "Destination: Personal Dropbox account"
        ),
        "source_type": SourceType.alert,
    },
    {
        "raw_text": (
            "Vulnerability scan results — external perimeter:\n"
            "Critical findings: CVE-2021-44228 (Log4Shell) — Apache Tomcat 9.0.41 on WEB-SRV-03\n"
            "High findings: CVE-2022-22965 (Spring4Shell) — Spring Framework 5.3.15\n"
            "Recommendation: Emergency patch within 24 hours\n"
            "CVSS score: 10.0 (Critical)"
        ),
        "source_type": SourceType.report,
    },
    {
        "raw_text": (
            "Command-and-control beaconing detected:\n"
            "Host: WORKSTATION-09 (10.0.3.9)\n"
            "Outbound connections to: 185.220.100.241 every 60 seconds\n"
            "Protocol: HTTPS (TLS 1.2) to port 443\n"
            "JA3 fingerprint matches Cobalt Strike default profile\n"
            "Process: svchost.exe (unusual parent: excel.exe)"
        ),
        "source_type": SourceType.alert,
    },
    {
        "raw_text": (
            "Security awareness: Normal activity log for baseline reference.\n"
            "User jsmith@company.com authenticated from office IP 10.0.0.45 at 09:15 AM.\n"
            "Accessed standard business applications: Outlook, SharePoint, Jira.\n"
            "No anomalies detected. Session duration: 8h 32m."
        ),
        "source_type": SourceType.log,
    },
]


# ── MITRE seed helper (minimal, reuses seed from API) ────────────────────────

def _seed_mitre(session) -> None:
    """Load MITRE techniques if table is empty."""
    if session.query(MitreTechnique).count() > 0:
        log.info("MITRE techniques already seeded — skipping.")
        return

    import json, pathlib
    data_path = (
        pathlib.Path(__file__).parent.parent / "app" / "data" / "mitre_techniques.json"
    )
    if not data_path.exists():
        log.warning("mitre_techniques.json not found — skipping MITRE seed.")
        return

    techniques = json.loads(data_path.read_text(encoding="utf-8"))
    for t in techniques:
        session.add(MitreTechnique(
            id=t["id"],
            name=t["name"],
            tactic=t["tactic"],
            description=t.get("description", ""),
        ))
    session.commit()
    log.info("Seeded %d MITRE techniques.", len(techniques))


def _seed_rules(session) -> None:
    """Load seed rules if not already present."""
    created = 0
    for rule_data in SEED_RULES:
        if session.query(Rule).filter(Rule.name == rule_data["name"]).first():
            continue
        session.add(Rule(
            name=rule_data["name"],
            description=rule_data.get("description"),
            condition_json=rule_data["condition_json"],
            severity=rule_data["severity"],
            mitre_technique_id=rule_data.get("mitre_technique_id"),
            is_active=True,
        ))
        created += 1
    session.commit()
    log.info("Seeded %d/%d detection rules.", created, len(SEED_RULES))


def _get_or_create_user(session, email: str, password: str, role: UserRole) -> User:
    user = session.query(User).filter(User.email == email).first()
    if user:
        log.info("User already exists: %s", email)
        return user

    user = User(
        email=email,
        hashed_password=hash_password(password),
        role=role,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    log.info("Created user: %s (role=%s)", email, role.value)
    return user


def _seed_submissions(session, analyst_user: User) -> None:
    """Create sample submissions for the analyst demo user."""
    existing = session.query(RawSubmission).filter(
        RawSubmission.user_id == analyst_user.id
    ).count()
    if existing:
        log.info("Sample submissions already seeded (%d found) — skipping.", existing)
        return

    rules = session.query(Rule).filter(Rule.is_active == True).all()  # noqa: E712
    if not rules:
        log.warning("No active rules found — findings will be empty.")

    # Try embeddings
    try:
        from app.embeddings.client import get_embeddings_client
        emb_client = get_embeddings_client()
    except Exception:
        emb_client = None

    created_count = 0
    for sample in SAMPLE_SUBMISSIONS:
        result = sanitize(
            sample["raw_text"],
            redact_pii=settings.REDACT_PII,
            max_length=settings.MAX_SUBMISSION_LENGTH,
        )
        sub = RawSubmission(
            user_id=analyst_user.id,
            raw_text=sample["raw_text"],
            source_type=sample["source_type"],
            sanitized_text=result.sanitized_text,
            sanitization_status=result.status,
            embedding_status=EmbeddingStatus.pending,
        )
        session.add(sub)
        session.commit()
        session.refresh(sub)

        # Evaluate rules → findings
        context = {
            "sanitized_text": sub.sanitized_text or "",
            "raw_text": sub.raw_text or "",
            "source_type": sub.source_type.value,
        }
        for rule in rules:
            matched, snippet = evaluate_rule(rule.condition_json, context)
            if matched:
                session.add(Finding(
                    submission_id=sub.id,
                    rule_id=rule.id,
                    matched_snippet=snippet[:500] if snippet else None,
                    severity=rule.severity,
                ))
        session.commit()

        # Embed (non-blocking)
        if emb_client and sub.sanitized_text:
            try:
                vec = emb_client.embed(sub.sanitized_text)
                sub.embedding = vec
                sub.embedding_status = (
                    EmbeddingStatus.complete if vec else EmbeddingStatus.failed
                )
                session.commit()
            except Exception:
                sub.embedding_status = EmbeddingStatus.failed
                session.commit()

        created_count += 1

    log.info("Created %d sample submissions.", created_count)


def main() -> None:
    log.info("=== Cyber Network Demo Seed ===")
    log.info("Database: %s", DATABASE_URL.split("@")[-1] if "@" in DATABASE_URL else DATABASE_URL)

    with Session() as session:
        # 1. Ensure tables exist (no-op if already migrated)
        try:
            Base.metadata.create_all(bind=engine, checkfirst=True)
        except Exception as e:
            log.warning("create_all skipped (likely already migrated): %s", e)

        # 2. MITRE techniques
        _seed_mitre(session)

        # 3. Detection rules
        _seed_rules(session)

        # 4. Users
        admin  = _get_or_create_user(session, **{k: v for k, v in DEMO_USERS[0].items()})
        analyst = _get_or_create_user(session, **{k: v for k, v in DEMO_USERS[1].items()})

        # 5. Sample submissions (analyst account)
        _seed_submissions(session, analyst)

        log.info("=== Seed complete ===")
        log.info("  Admin:   admin@cybernetwork.demo / Admin@Demo2025!")
        log.info("  Analyst: analyst@cybernetwork.demo / Analyst@Demo2025!")


if __name__ == "__main__":
    main()
