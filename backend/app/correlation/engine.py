"""Persist technique, rule, and embedding-based submission correlations."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload
from starlette.concurrency import run_in_threadpool

from app.core.config import settings
from app.models.memory import (
    CorrelationLink,
    LinkReason,
    MemoryNode,
    MemoryNodeStatus,
    SignatureType,
)
from app.models.raw_submission import RawSubmission
from app.models.rule import Finding

logger = logging.getLogger(__name__)


def _is_after(candidate: datetime, current: datetime) -> bool:
    if candidate.tzinfo is None:
        candidate = candidate.replace(tzinfo=timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return candidate > current


def find_similar_submissions(
    db: Session,
    submission: RawSubmission,
    *,
    similarity_threshold: float,
    window_days: int,
) -> list[tuple[RawSubmission, float]]:
    """Return prior submissions meeting the cosine similarity and time bounds."""
    if submission.embedding is None or submission.id is None:
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
    distance = RawSubmission.embedding.cosine_distance(submission.embedding)
    rows = db.execute(
        select(RawSubmission, (1 - distance).label("similarity"))
        .where(
            RawSubmission.id != submission.id,
            RawSubmission.embedding.is_not(None),
            RawSubmission.submitted_at >= cutoff,
            distance <= (1 - similarity_threshold),
        )
        .order_by(distance.asc())
    ).all()
    return [(row[0], float(row[1])) for row in rows]


def _find_or_create_node(
    db: Session,
    *,
    signature_type: SignatureType,
    signature_key: str,
    observed_at: datetime,
) -> MemoryNode:
    node = (
        db.query(MemoryNode)
        .filter(
            MemoryNode.signature_type == signature_type,
            MemoryNode.signature_key == signature_key,
        )
        .one_or_none()
    )
    if node is not None:
        node.occurrence_count += 1
        node.status = MemoryNodeStatus.active
        if _is_after(observed_at, node.last_seen):
            node.last_seen = observed_at
        return node

    node = MemoryNode(
        signature_type=signature_type,
        signature_key=signature_key,
        first_seen=observed_at,
        last_seen=observed_at,
        occurrence_count=1,
    )
    try:
        with db.begin_nested():
            db.add(node)
            db.flush()
    except IntegrityError:
        # Another background worker may have inserted the same signature.
        node = (
            db.query(MemoryNode)
            .filter(
                MemoryNode.signature_type == signature_type,
                MemoryNode.signature_key == signature_key,
            )
            .one()
        )
        node.occurrence_count += 1
        node.status = MemoryNodeStatus.active
        if _is_after(observed_at, node.last_seen):
            node.last_seen = observed_at
    return node


def _link(
    db: Session,
    *,
    node: MemoryNode,
    submission: RawSubmission,
    finding: Finding | None,
    reason: LinkReason,
    similarity_score: float | None = None,
) -> CorrelationLink:
    link = CorrelationLink(
        memory_node=node,
        submission=submission,
        finding=finding,
        linked_at=submission.submitted_at or datetime.now(timezone.utc),
        link_reason=reason,
        similarity_score=similarity_score,
    )
    db.add(link)
    return link


def _existing_embedding_cluster(
    db: Session,
    matched_submissions: Sequence[tuple[RawSubmission, float]],
) -> MemoryNode | None:
    matched_ids = [matched.id for matched, _ in matched_submissions]
    if not matched_ids:
        return None
    return (
        db.query(MemoryNode)
        .join(CorrelationLink, CorrelationLink.memory_node_id == MemoryNode.id)
        .filter(
            MemoryNode.signature_type == SignatureType.embedding_cluster,
            CorrelationLink.submission_id.in_(matched_ids),
            CorrelationLink.link_reason == LinkReason.embedding_similarity,
        )
        .order_by(MemoryNode.id)
        .first()
    )


def correlate_submission(
    submission: RawSubmission,
    findings: Sequence[Finding],
    db: Session,
) -> list[CorrelationLink]:
    """Create links for a submission's MITRE techniques, rules, and neighbors.

    The caller owns the transaction and must commit or roll it back.
    """
    observed_at = submission.submitted_at or datetime.now(timezone.utc)
    links: list[CorrelationLink] = []

    for finding in findings:
        rule = finding.rule
        technique_id = rule.mitre_technique_id if rule is not None else None
        if technique_id:
            node = _find_or_create_node(
                db,
                signature_type=SignatureType.mitre_technique,
                signature_key=technique_id,
                observed_at=observed_at,
            )
            links.append(
                _link(
                    db,
                    node=node,
                    submission=submission,
                    finding=finding,
                    reason=LinkReason.shared_technique,
                )
            )

        node = _find_or_create_node(
            db,
            signature_type=SignatureType.rule,
            signature_key=str(finding.rule_id),
            observed_at=observed_at,
        )
        links.append(
            _link(
                db,
                node=node,
                submission=submission,
                finding=finding,
                reason=LinkReason.shared_rule,
            )
        )

    if submission.embedding is not None and submission.id is not None:
        matches = find_similar_submissions(
            db,
            submission,
            similarity_threshold=settings.CORRELATION_SIMILARITY_THRESHOLD,
            window_days=settings.CORRELATION_WINDOW_DAYS,
        )
        matches = [
            (matched, score)
            for matched, score in matches
            if matched.id != submission.id
            and score >= settings.CORRELATION_SIMILARITY_THRESHOLD
        ]
        if matches:
            nearest, score = max(matches, key=lambda match: match[1])
            node = _existing_embedding_cluster(db, matches)
            if node is None:
                node = _find_or_create_node(
                    db,
                    signature_type=SignatureType.embedding_cluster,
                    signature_key=f"submission-{nearest.id}",
                    observed_at=observed_at,
                )
            else:
                node.occurrence_count += 1
                node.status = MemoryNodeStatus.active
                if _is_after(observed_at, node.last_seen):
                    node.last_seen = observed_at
            links.append(
                _link(
                    db,
                    node=node,
                    submission=submission,
                    finding=None,
                    reason=LinkReason.embedding_similarity,
                    similarity_score=score,
                )
            )

    db.flush()
    logger.info(
        "Created %d correlation links for submission %s",
        len(links),
        submission.id,
    )
    return links


def _correlate_submission_in_session(submission_id: int) -> None:
    from app.core.database import SessionLocal

    db = SessionLocal()
    try:
        submission = (
            db.query(RawSubmission)
            .filter(RawSubmission.id == submission_id)
            .one_or_none()
        )
        if submission is None:
            logger.error(
                "Cannot correlate missing submission %s",
                submission_id,
            )
            return
        findings = (
            db.query(Finding)
            .options(joinedload(Finding.rule))
            .filter(Finding.submission_id == submission_id)
            .all()
        )
        correlate_submission(submission, findings, db)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Correlation failed for submission %s", submission_id)
        raise
    finally:
        db.close()


async def correlate_submission_background(submission_id: int) -> None:
    """Run correlation asynchronously using its own short-lived DB session."""
    await run_in_threadpool(_correlate_submission_in_session, submission_id)
