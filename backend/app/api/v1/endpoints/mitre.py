"""
MITRE ATT&CK endpoints.

GET  /api/mitre/techniques          — list/search techniques (tactic filter, keyword)
GET  /api/mitre/techniques/{id}     — get single technique
POST /api/mitre/techniques/seed     — load seed data from JSON (admin only, idempotent)
GET  /api/submissions/{id}/mitre-summary — tactic/technique breakdown for a submission
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_admin, get_current_user
from app.core.database import get_db
from app.models.mitre_technique import MitreTechnique
from app.models.raw_submission import RawSubmission
from app.models.rule import Finding, Rule
from app.models.user import User, UserRole

router = APIRouter(prefix="/mitre", tags=["mitre"])

_DATA_FILE = Path(__file__).parent.parent.parent.parent / "app" / "data" / "mitre_techniques.json"


# ── Schemas ───────────────────────────────────────────────────────────────────

class TechniqueOut(BaseModel):
    id: str
    name: str
    tactic: str
    description: Optional[str]

    model_config = {"from_attributes": True}


class TacticBreakdown(BaseModel):
    tactic: str
    finding_count: int
    technique_ids: List[str]


class MitreSummary(BaseModel):
    submission_id: int
    total_findings: int
    mapped_findings: int       # findings that have a linked technique
    tactics: List[TacticBreakdown]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _check_submission_access(
    submission_id: int, db: Session, current_user: User
) -> RawSubmission:
    sub = db.query(RawSubmission).filter(RawSubmission.id == submission_id).first()
    if sub is None:
        raise HTTPException(status_code=404, detail="Submission not found")
    if current_user.role != UserRole.admin and sub.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Submission not found")
    return sub


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post(
    "/techniques/seed",
    status_code=status.HTTP_201_CREATED,
    summary="Seed MITRE techniques from local JSON (admin only, idempotent)",
)
def seed_mitre_techniques(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_admin),
) -> dict:
    """Loads mitre_techniques.json and inserts missing rows. Safe to call repeatedly."""
    data_path = Path(__file__).resolve().parent.parent.parent.parent / "data" / "mitre_techniques.json"
    with open(data_path, encoding="utf-8") as fh:
        techniques = json.load(fh)

    created = 0
    for tech in techniques:
        exists = db.query(MitreTechnique).filter(MitreTechnique.id == tech["id"]).first()
        if exists:
            continue
        db.add(
            MitreTechnique(
                id=tech["id"],
                name=tech["name"],
                tactic=tech["tactic"],
                description=tech.get("description"),
            )
        )
        created += 1

    db.commit()
    return {"techniques_created": created, "total_in_file": len(techniques)}


@router.get(
    "/techniques",
    response_model=List[TechniqueOut],
    summary="List MITRE techniques (optional tactic or keyword filter)",
)
def list_techniques(
    tactic: Optional[str] = Query(None, description="Filter by tactic name (case-insensitive)"),
    q: Optional[str] = Query(None, description="Keyword search across id/name/description"),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> List[TechniqueOut]:
    query = db.query(MitreTechnique)
    if tactic:
        query = query.filter(MitreTechnique.tactic.ilike(f"%{tactic}%"))
    if q:
        like = f"%{q}%"
        query = query.filter(
            MitreTechnique.id.ilike(like)
            | MitreTechnique.name.ilike(like)
            | MitreTechnique.description.ilike(like)
        )
    return query.order_by(MitreTechnique.tactic, MitreTechnique.id).all()


@router.get(
    "/techniques/{technique_id}",
    response_model=TechniqueOut,
    summary="Get a single MITRE technique by ID",
)
def get_technique(
    technique_id: str,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> TechniqueOut:
    tech = db.query(MitreTechnique).filter(MitreTechnique.id == technique_id).first()
    if not tech:
        raise HTTPException(status_code=404, detail=f"Technique {technique_id!r} not found")
    return tech


@router.get(
    "/submissions/{submission_id}/mitre-summary",
    response_model=MitreSummary,
    summary="MITRE tactic/technique breakdown for a submission's findings",
    tags=["mitre", "rules"],
)
def mitre_summary(
    submission_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MitreSummary:
    """
    Aggregates findings for a submission into a tactic breakdown.
    Findings without a linked MITRE technique are counted in total_findings
    but excluded from the tactic breakdown.
    """
    _check_submission_access(submission_id, db, current_user)

    findings: list[Finding] = (
        db.query(Finding).filter(Finding.submission_id == submission_id).all()
    )

    total = len(findings)
    tactic_map: dict[str, list[str]] = {}   # tactic → list of technique IDs

    for f in findings:
        rule: Rule | None = f.rule
        if not rule or not rule.mitre_technique_id:
            continue
        tech = db.query(MitreTechnique).filter(
            MitreTechnique.id == rule.mitre_technique_id
        ).first()
        if not tech:
            continue
        tactic_map.setdefault(tech.tactic, []).append(tech.id)

    mapped = sum(len(ids) for ids in tactic_map.values())
    tactics = [
        TacticBreakdown(
            tactic=tactic,
            finding_count=len(ids),
            technique_ids=sorted(set(ids)),
        )
        for tactic, ids in sorted(tactic_map.items())
    ]

    return MitreSummary(
        submission_id=submission_id,
        total_findings=total,
        mapped_findings=mapped,
        tactics=tactics,
    )
