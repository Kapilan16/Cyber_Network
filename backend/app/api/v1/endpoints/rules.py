"""
Rule engine API endpoints.

POST /api/submissions/{id}/evaluate  — run all active rules, persist Findings
GET  /api/submissions/{id}/findings  — list findings for a submission
GET  /api/rules                      — list all rules (admin only)
POST /api/rules                      — create a rule (admin only)
POST /api/rules/seed                 — load seed rules (admin only, idempotent)
PUT  /api/rules/{rule_id}            — update a rule (admin only)
DELETE /api/rules/{rule_id}          — delete a rule (admin only)
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_admin, get_current_user
from app.core.database import get_db
from app.models.mitre_technique import MitreTechnique
from app.models.raw_submission import RawSubmission
from app.models.rule import Finding, Rule, Severity
from app.models.user import User, UserRole
from app.rules.evaluator import evaluate_rule
from app.rules.seed_rules import SEED_RULES

router = APIRouter()


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class RuleOut(BaseModel):
    id: int
    name: str
    description: Optional[str]
    severity: Severity
    mitre_technique_id: Optional[str]
    is_active: bool
    condition_json: dict

    model_config = {"from_attributes": True}


class MitreTechniqueRef(BaseModel):
    id: str
    name: str
    tactic: str


class FindingOut(BaseModel):
    id: int
    submission_id: int
    rule_id: int
    rule_name: str
    matched_snippet: Optional[str]
    severity: Severity
    created_at: str
    mitre_technique: Optional[MitreTechniqueRef] = None

    model_config = {"from_attributes": True}


class EvaluateResponse(BaseModel):
    submission_id: int
    rules_evaluated: int
    findings_created: int
    findings: List[FindingOut]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _check_submission_access(sub: RawSubmission | None, current_user: User) -> RawSubmission:
    """Return the submission or raise 404 (never 403 — avoids existence leaks)."""
    if sub is None:
        raise HTTPException(status_code=404, detail="Submission not found")
    if current_user.role != UserRole.admin and sub.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Submission not found")
    return sub


def _finding_out(f: Finding, db: "Session | None" = None) -> FindingOut:
    mitre_ref: MitreTechniqueRef | None = None
    rule: Rule | None = f.rule
    if rule and rule.mitre_technique_id and db is not None:
        tech: MitreTechnique | None = (
            db.query(MitreTechnique)
            .filter(MitreTechnique.id == rule.mitre_technique_id)
            .first()
        )
        if tech:
            mitre_ref = MitreTechniqueRef(id=tech.id, name=tech.name, tactic=tech.tactic)

    return FindingOut(
        id=f.id,
        submission_id=f.submission_id,
        rule_id=f.rule_id,
        rule_name=rule.name if rule else "",
        matched_snippet=f.matched_snippet,
        severity=f.severity,
        created_at=f.created_at.isoformat(),
        mitre_technique=mitre_ref,
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post(
    "/submissions/{submission_id}/evaluate",
    response_model=EvaluateResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate all active rules against a submission",
    tags=["rules"],
)
def evaluate_submission(
    submission_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EvaluateResponse:
    """
    Runs every active Rule against the submission's sanitized_text.
    Persists a Finding for each rule that matches (idempotent — existing
    findings for the same submission+rule pair are replaced).
    """
    sub = db.query(RawSubmission).filter(RawSubmission.id == submission_id).first()
    _check_submission_access(sub, current_user)

    if not sub.sanitized_text:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Submission has no sanitized_text to evaluate.",
        )

    active_rules: list[Rule] = (
        db.query(Rule).filter(Rule.is_active == True).all()  # noqa: E712
    )

    # Build evaluation context
    context = {
        "sanitized_text": sub.sanitized_text or "",
        "raw_text": sub.raw_text or "",
        "source_type": sub.source_type.value if sub.source_type else "",
    }

    # Delete stale findings for this submission so re-evaluation is idempotent
    db.query(Finding).filter(Finding.submission_id == submission_id).delete()

    new_findings: list[Finding] = []
    for rule in active_rules:
        try:
            matched, snippet = evaluate_rule(rule.condition_json, context)
        except Exception:
            # Defensive: a malformed condition_json must never crash the pipeline
            matched, snippet = False, ""

        if matched:
            finding = Finding(
                submission_id=submission_id,
                rule_id=rule.id,
                matched_snippet=snippet[:500] if snippet else None,
                severity=rule.severity,
            )
            db.add(finding)
            new_findings.append(finding)

    db.commit()
    for f in new_findings:
        db.refresh(f)

    return EvaluateResponse(
        submission_id=submission_id,
        rules_evaluated=len(active_rules),
        findings_created=len(new_findings),
        findings=[_finding_out(f, db) for f in new_findings],
    )


@router.get(
    "/submissions/{submission_id}/findings",
    response_model=List[FindingOut],
    summary="List findings for a submission",
    tags=["rules"],
)
def get_findings(
    submission_id: int,
    severity: Optional[Severity] = Query(None, description="Filter by severity"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> List[FindingOut]:
    sub = db.query(RawSubmission).filter(RawSubmission.id == submission_id).first()
    _check_submission_access(sub, current_user)

    q = db.query(Finding).filter(Finding.submission_id == submission_id)
    if severity:
        q = q.filter(Finding.severity == severity)
    findings = q.order_by(Finding.created_at.desc()).all()
    return [_finding_out(f, db) for f in findings]


@router.get(
    "/rules",
    response_model=List[RuleOut],
    summary="List all detection rules (admin only)",
    tags=["rules"],
)
def list_rules(
    active_only: bool = Query(False),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_admin),
) -> List[RuleOut]:
    q = db.query(Rule)
    if active_only:
        q = q.filter(Rule.is_active == True)  # noqa: E712
    return q.order_by(Rule.id).all()


@router.post(
    "/rules/seed",
    status_code=status.HTTP_201_CREATED,
    summary="Load seed detection rules (admin only, idempotent)",
    tags=["rules"],
)
def seed_rules(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_admin),
) -> dict:
    """
    Inserts the built-in seed rules if they don't already exist (matched by name).
    Safe to call multiple times.
    """
    created = 0
    for rule_data in SEED_RULES:
        exists = db.query(Rule).filter(Rule.name == rule_data["name"]).first()
        if exists:
            continue
        rule = Rule(
            name=rule_data["name"],
            description=rule_data.get("description"),
            condition_json=rule_data["condition_json"],
            severity=rule_data["severity"],
            mitre_technique_id=rule_data.get("mitre_technique_id"),
            is_active=True,
        )
        db.add(rule)
        created += 1
    db.commit()
    return {"rules_created": created, "total_seed_rules": len(SEED_RULES)}


# ── Rule CRUD (admin only) ────────────────────────────────────────────────────

class RuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    condition_json: dict
    severity: Severity = Severity.medium
    mitre_technique_id: Optional[str] = None
    is_active: bool = True


class RuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    condition_json: Optional[dict] = None
    severity: Optional[Severity] = None
    mitre_technique_id: Optional[str] = None
    is_active: Optional[bool] = None


@router.post(
    "/rules",
    response_model=RuleOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a detection rule (admin only)",
    tags=["rules"],
)
def create_rule(
    body: RuleCreate,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_admin),
) -> RuleOut:
    """Create a new detection rule."""
    if db.query(Rule).filter(Rule.name == body.name).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Rule with name '{body.name}' already exists.",
        )
    rule = Rule(
        name=body.name,
        description=body.description,
        condition_json=body.condition_json,
        severity=body.severity,
        mitre_technique_id=body.mitre_technique_id,
        is_active=body.is_active,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


@router.put(
    "/rules/{rule_id}",
    response_model=RuleOut,
    summary="Update a detection rule (admin only)",
    tags=["rules"],
)
def update_rule(
    rule_id: int,
    body: RuleUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_admin),
) -> RuleOut:
    """Partially update an existing rule. Only provided fields are changed."""
    rule = db.query(Rule).filter(Rule.id == rule_id).first()
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    updates = body.model_dump(exclude_unset=True)
    for field, value in updates.items():
        setattr(rule, field, value)
    db.commit()
    db.refresh(rule)
    return rule


@router.delete(
    "/rules/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Delete a detection rule (admin only)",
    tags=["rules"],
)
def delete_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_admin),
) -> Response:
    """Permanently delete a rule and all its associated findings."""
    rule = db.query(Rule).filter(Rule.id == rule_id).first()
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(rule)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)

