#!/usr/bin/env python
"""
seed_demo.py — repeatable local and central-network demo data loader.

Creates:
  • admin@cybernetwork.demo  / Admin@Demo2025!   (role=admin)
  • analyst@cybernetwork.demo / Analyst@Demo2025! (role=analyst)
  • 15 seed detection rules (via SEED_RULES)
  • 50 MITRE ATT&CK techniques
  • 20 sample submissions covering diverse security scenarios
    → each is sanitized, evaluated, and embedding attempted
  • Three demo network organizations, with two submissions per org.
    Opted-in orgs pass sanitized findings through the outbound payload builder
    and submit them to central; a separate demo org verifies network search.

Usage (from the backend/ directory):
    python scripts/seed_demo.py
Or with a custom DATABASE_URL:
    DATABASE_URL=postgresql+psycopg2://... python scripts/seed_demo.py
"""
from __future__ import annotations

import json
import os
import sys
import logging
from datetime import datetime, timedelta, timezone

# ── Make sure 'app' is importable when run from backend/ ────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker
import httpx

from app.core.config import settings
from app.core.database import Base
from app.core.security import hash_password
from app.models.organization import Organization
from app.models.user import User, UserRole
from app.models.rule import Rule, Finding
from app.models.raw_submission import (
    EmbeddingStatus,
    NetworkSyncStatus,
    RawSubmission,
    SourceType,
)
from app.models.memory import CorrelationLink
from app.models.mitre_technique import MitreTechnique
from app.correlation.campaigns import scan_recurring_memory_nodes
from app.correlation.engine import correlate_submission
from app.sanitization.sanitizer import sanitize
from app.rules.evaluator import evaluate_rule
from app.rules.seed_rules import SEED_RULES
from app.sharing.payload import build_shared_intel_payload
from app.central_client import CentralClient

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
    from app.embeddings.client import get_embeddings_client

    embedding_client = get_embeddings_client()
    for rule_data in SEED_RULES:
        existing = session.query(Rule).filter(Rule.name == rule_data["name"]).first()
        if existing:
            if existing.description and existing.description_embedding is None:
                vector = embedding_client.embed(existing.description)
                existing.description_embedding = (
                    json.dumps(vector)
                    if vector is not None and session.bind.dialect.name == "sqlite"
                    else vector
                )
            continue
        rule = Rule(
            name=rule_data["name"],
            description=rule_data.get("description"),
            condition_json=rule_data["condition_json"],
            severity=rule_data["severity"],
            mitre_technique_id=rule_data.get("mitre_technique_id"),
            is_active=True,
        )
        if rule.description:
            vector = embedding_client.embed(rule.description)
            rule.description_embedding = (
                json.dumps(vector)
                if vector is not None and session.bind.dialect.name == "sqlite"
                else vector
            )
        session.add(rule)
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


CAMPAIGN_SUBMISSIONS = [
    {
        "key": "powershell-1",
        "days_ago": 21,
        "raw_text": (
            "SOC investigation: workstation PS-104 launched PowerShell with "
            "the -EncodedCommand flag; execution was blocked and isolated."
        ),
        "rule_name": "Suspicious PowerShell: Encoded Command",
    },
    {
        "key": "phishing-1",
        "days_ago": 20,
        "raw_text": (
            "Mail gateway report: suspicious message asked the recipient to "
            "verify your account through an external sign-in page."
        ),
        "rule_name": "Phishing Language: Account Verification Request",
    },
    {
        "key": "powershell-2",
        "days_ago": 10,
        "raw_text": (
            "Endpoint alert: a second workstation attempted a PowerShell "
            "-EncodedCommand launch; the command was contained."
        ),
        "rule_name": "Suspicious PowerShell: Encoded Command",
    },
    {
        "key": "phishing-2",
        "days_ago": 9,
        "raw_text": (
            "Analyst report: another lure instructed a user to verify your "
            "account after warning that access would be suspended."
        ),
        "rule_name": "Phishing Language: Account Verification Request",
    },
    {
        "key": "powershell-3",
        "days_ago": 2,
        "raw_text": (
            "EDR alert: repeat PowerShell -EncodedCommand activity detected "
            "on a neighboring host; process was terminated."
        ),
        "rule_name": "Suspicious PowerShell: Encoded Command",
    },
    {
        "key": "phishing-3",
        "days_ago": 1,
        "raw_text": (
            "Mail investigation: a related campaign again requested users "
            "verify your account using an untrusted web form."
        ),
        "rule_name": "Phishing Language: Account Verification Request",
    },
]


def _seed_campaign_submissions(
    session,
    analyst_user: User,
    *,
    now: datetime | None = None,
    embedding_client=None,
) -> int:
    """Create repeatable, historically spaced demo activity and its memory links."""
    from app.embeddings.client import get_embeddings_client

    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=timezone.utc)
    client = embedding_client if embedding_client is not None else get_embeddings_client()
    rules_by_name = {
        rule.name: rule
        for rule in session.query(Rule).filter(Rule.is_active.is_(True)).all()
    }
    created = 0

    for sample in sorted(CAMPAIGN_SUBMISSIONS, key=lambda item: item["days_ago"], reverse=True):
        raw_text = f"[stage2-campaign:{sample['key']}] {sample['raw_text']}"
        submission = (
            session.query(RawSubmission)
            .filter(
                RawSubmission.user_id == analyst_user.id,
                RawSubmission.raw_text == raw_text,
            )
            .one_or_none()
        )
        event_time = current_time - timedelta(days=sample["days_ago"])
        if submission is None:
            result = sanitize(
                raw_text,
                redact_pii=settings.REDACT_PII,
                max_length=settings.MAX_SUBMISSION_LENGTH,
            )
            submission = RawSubmission(
                user_id=analyst_user.id,
                raw_text=raw_text,
                source_type=SourceType.alert,
                submitted_at=event_time,
                sanitized_text=result.sanitized_text,
                sanitization_status=result.status,
                embedding_status=EmbeddingStatus.pending,
            )
            session.add(submission)
            session.flush()

            context = {
                "sanitized_text": submission.sanitized_text or "",
                "raw_text": submission.raw_text,
                "source_type": submission.source_type.value,
            }
            for rule in rules_by_name.values():
                matched, snippet = evaluate_rule(rule.condition_json, context)
                if matched:
                    session.add(
                        Finding(
                            submission_id=submission.id,
                            rule_id=rule.id,
                            matched_snippet=snippet[:500] if snippet else None,
                            severity=rule.severity,
                            created_at=event_time,
                        )
                    )

            if client is not None and submission.sanitized_text:
                vector = client.embed(submission.sanitized_text)
                if vector is not None:
                    submission.embedding = (
                        json.dumps(vector)
                        if session.bind.dialect.name == "sqlite"
                        else vector
                    )
                    submission.embedding_status = EmbeddingStatus.complete
                else:
                    submission.embedding_status = EmbeddingStatus.failed

            session.flush()
            created += 1

        has_links = (
            session.query(CorrelationLink.id)
            .filter(CorrelationLink.submission_id == submission.id)
            .first()
            is not None
        )
        if not has_links:
            findings = (
                session.query(Finding)
                .filter(Finding.submission_id == submission.id)
                .all()
            )
            correlate_submission(submission, findings, session)
        session.commit()

    scan_recurring_memory_nodes(session, now=current_time)
    session.commit()
    log.info("Seeded %d recurring-pattern submissions.", created)
    return created


def _seed_central_network_demo(session) -> None:
    """Seed three isolated demo identities and verify cross-org search."""
    if not settings.CENTRAL_SERVER_URL:
        log.info("Central network URL is not configured; skipping network demo seed.")
        return
    if not settings.CENTRAL_ADMIN_TOKEN:
        raise RuntimeError(
            "CENTRAL_ADMIN_TOKEN is required to bootstrap the central network demo"
        )

    response = httpx.post(
        f"{settings.CENTRAL_SERVER_URL.rstrip('/')}/api/central/admin/demo-organizations",
        headers={"X-Central-Admin-Token": settings.CENTRAL_ADMIN_TOKEN},
        timeout=15.0,
    )
    response.raise_for_status()
    central_orgs = response.json()["organizations"]
    if len(central_orgs) != 3:
        raise RuntimeError("Central demo bootstrap did not return three organizations")

    sharing_by_name = {
        "Demo Network Alpha": True,
        "Demo Network Beta": True,
        "Demo Network Gamma": False,
    }
    embedding_client = None
    from app.embeddings.client import get_embeddings_client

    embedding_client = get_embeddings_client()
    registered: dict[str, dict] = {}
    for central_org in central_orgs:
        name = central_org["name"]
        registered[name] = central_org
        local_org = (
            session.query(Organization)
            .filter(Organization.name == name)
            .first()
        )
        if local_org is None:
            local_org = Organization(name=name)
            session.add(local_org)
            session.flush()
        local_org.share_with_network = sharing_by_name[name]

        slug = name.rsplit(" ", 1)[-1].lower()
        email = f"demo-{slug}@cybernetwork.demo"
        demo_user = session.query(User).filter(User.email == email).first()
        if demo_user is None:
            demo_user = User(
                org_id=local_org.id,
                email=email,
                hashed_password=hash_password("Analyst@Demo2025!"),
                role=UserRole.analyst,
            )
            session.add(demo_user)
            session.flush()
        else:
            demo_user.org_id = local_org.id

        admin_email = f"network-{slug}-admin@cybernetwork.demo"
        demo_admin = session.query(User).filter(User.email == admin_email).first()
        if demo_admin is None:
            demo_admin = User(
                org_id=local_org.id,
                email=admin_email,
                hashed_password=hash_password("Admin@Demo2025!"),
                role=UserRole.admin,
            )
            session.add(demo_admin)
            session.flush()
        else:
            demo_admin.org_id = local_org.id
            demo_admin.role = UserRole.admin

        for sample in (CAMPAIGN_SUBMISSIONS[0], CAMPAIGN_SUBMISSIONS[1]):
            raw_text = (
                f"Organization: {name}. Hostname={slug}-db.internal "
                f"Username=analyst.{slug} Private IP=10.24.6.8. "
                f"{sample['raw_text']}"
            )
            submission = (
                session.query(RawSubmission)
                .filter(
                    RawSubmission.user_id == demo_user.id,
                    RawSubmission.raw_text == raw_text,
                )
                .one_or_none()
            )
            if submission is None:
                result = sanitize(
                    raw_text,
                    redact_pii=settings.REDACT_PII,
                    max_length=settings.MAX_SUBMISSION_LENGTH,
                )
                event_time = datetime.now(timezone.utc) - timedelta(
                    days=(len(registered) - 1) * 2
                )
                submission = RawSubmission(
                    user_id=demo_user.id,
                    raw_text=raw_text,
                    source_type=SourceType.alert,
                    submitted_at=event_time,
                    sanitized_text=result.sanitized_text,
                    sanitization_status=result.status,
                    embedding_status=EmbeddingStatus.pending,
                )
                session.add(submission)
                session.flush()

                context = {
                    "sanitized_text": submission.sanitized_text or "",
                    "raw_text": submission.raw_text,
                    "source_type": submission.source_type.value,
                }
                matched_rule = False
                for rule in session.query(Rule).filter(Rule.is_active.is_(True)).all():
                    matched, snippet = evaluate_rule(rule.condition_json, context)
                    if matched:
                        session.add(
                            Finding(
                                submission_id=submission.id,
                                rule_id=rule.id,
                                matched_snippet=snippet[:500] if snippet else None,
                                severity=rule.severity,
                                created_at=event_time,
                            )
                        )
                        matched_rule = matched_rule or rule.name == sample["rule_name"]
                if not matched_rule:
                    raise RuntimeError(
                        f"Demo sample failed to match its expected rule: {sample['rule_name']}"
                    )
                vector = embedding_client.embed(submission.sanitized_text or "")
                if vector is None:
                    raise RuntimeError(
                        f"Could not create a demo embedding for {name} submission"
                    )
                if len(vector) != settings.VECTOR_DIM:
                    raise RuntimeError(
                        "Demo embedding dimension does not match VECTOR_DIM"
                    )
                submission.embedding = (
                    json.dumps(vector)
                    if session.bind.dialect.name == "sqlite"
                    else vector
                )
                submission.embedding_status = EmbeddingStatus.complete
                session.flush()

            if local_org.share_with_network:
                findings = (
                    session.query(Finding)
                    .filter(Finding.submission_id == submission.id)
                    .all()
                )
                if not findings:
                    raise RuntimeError(
                        f"Opted-in demo submission {submission.id} has no findings"
                    )
                technique_ids = {
                    finding.rule.mitre_technique_id
                    for finding in findings
                    if finding.rule is not None and finding.rule.mitre_technique_id
                }
                techniques = (
                    session.query(MitreTechnique)
                    .filter(MitreTechnique.id.in_(technique_ids))
                    .all()
                    if technique_ids
                    else []
                )
                payload = build_shared_intel_payload(
                    local_org,
                    submission,
                    findings,
                    techniques,
                )
                with CentralClient(
                    base_url=settings.CENTRAL_SERVER_URL,
                    api_key=central_org["api_key"],
                ) as central:
                    result = central.submit_intel(payload)
                submission.network_sync_status = (
                    NetworkSyncStatus.duplicate
                    if result.get("duplicate", False)
                    else NetworkSyncStatus.shared
                )
                submission.network_sync_error = None
                submission.network_synced_at = datetime.now(timezone.utc)
            else:
                submission.network_sync_status = NetworkSyncStatus.not_shared
            session.commit()

    # Use the opted-out Beta identity as a reader and confirm its search returns
    # Alpha's anonymized contribution, with no source identity in the response.
    alpha = registered["Demo Network Alpha"]
    beta = registered["Demo Network Beta"]
    alpha_user = session.query(User).filter(User.email == "demo-alpha@cybernetwork.demo").one()
    query_submission = (
        session.query(RawSubmission)
        .filter(
            RawSubmission.user_id == alpha_user.id,
            RawSubmission.raw_text.contains("PowerShell"),
        )
        .order_by(RawSubmission.id)
        .first()
    )
    if query_submission is None or query_submission.embedding is None:
        raise RuntimeError("Alpha demo embedding is missing; network smoke search cannot run")
    query_vector = query_submission.embedding
    if isinstance(query_vector, str):
        query_vector = json.loads(query_vector)
    with CentralClient(
        base_url=settings.CENTRAL_SERVER_URL,
        api_key=beta["api_key"],
    ) as central:
        search = central.search_intel([float(value) for value in query_vector], top_k=10)
    if not search.get("results"):
        raise RuntimeError("Beta's central network search returned no Alpha demo results")
    if any("source_org_id" in result for result in search["results"]):
        raise RuntimeError("Central search exposed an organization identifier")
    for result in search["results"]:
        text = result["sanitized_text"].lower()
        if any(
            identifying_value in text
            for identifying_value in (
                "demo network alpha",
                "alpha-db.internal",
                "analyst.alpha",
                "10.24.6.8",
            )
        ):
            raise RuntimeError(
                "Central search returned organization-identifying text or an internal IOC"
            )
    log.info(
        "Central network demo ready: 3 registered orgs; opted-in sharing and "
        "cross-org search verified (%d results).",
        len(search["results"]),
    )


def main() -> None:
    log.info("=== Cyber Network Demo Seed ===")
    log.info("Database: %s", DATABASE_URL.split("@")[-1] if "@" in DATABASE_URL else DATABASE_URL)

    with Session() as session:
        # 1. Support standalone seeding without rerunning metadata DDL on an
        #    Alembic-managed database (notably PostgreSQL enum types).
        try:
            if not inspect(engine).has_table("alembic_version"):
                Base.metadata.create_all(bind=engine, checkfirst=True)
            else:
                log.info("Alembic-managed schema detected — skipping create_all.")
        except Exception as e:
            log.exception("Unable to ensure demo seed schema exists.")
            raise

        # 2. MITRE techniques
        _seed_mitre(session)

        # 3. Detection rules
        _seed_rules(session)

        # 4. Users
        admin  = _get_or_create_user(session, **{k: v for k, v in DEMO_USERS[0].items()})
        analyst = _get_or_create_user(session, **{k: v for k, v in DEMO_USERS[1].items()})

        # 5. Sample submissions (analyst account)
        _seed_submissions(session, analyst)

        # 6. Related, historically spaced findings for immediate campaign demos
        _seed_campaign_submissions(session, analyst)

        # 7. Separate central organizations and their anonymized network data
        _seed_central_network_demo(session)

        log.info("=== Seed complete ===")
        log.info("  Admin:   admin@cybernetwork.demo / Admin@Demo2025!")
        log.info("  Analyst: analyst@cybernetwork.demo / Analyst@Demo2025!")


if __name__ == "__main__":
    main()
