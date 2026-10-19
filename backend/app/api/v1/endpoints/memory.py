"""Read endpoints for long-term memory nodes and their submission links."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session, joinedload

from app.api.deps import get_current_user
from app.correlation.campaigns import build_campaign_summary
from app.core.database import get_db
from app.models.memory import (
    CorrelationLink,
    LinkReason,
    MemoryNode,
    MemoryNodeStatus,
    SignatureType,
)
from app.models.raw_submission import RawSubmission, SanitizationStatus, SourceType
from app.models.rule import Severity
from app.models.user import User, UserRole

router = APIRouter(prefix="/memory", tags=["memory"])


class MemoryNodeOut(BaseModel):
    id: int
    signature_type: SignatureType
    signature_key: str
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int
    status: MemoryNodeStatus
    is_recurring: bool
    recurrence_window_days: int
    recurrence_threshold: int
    summary: str | None

    model_config = {"from_attributes": True}


class PaginatedMemoryNodes(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[MemoryNodeOut]


class LinkedSubmissionOut(BaseModel):
    id: int
    source_type: SourceType
    submitted_at: datetime
    sanitization_status: SanitizationStatus
    sanitized_text: str | None

    model_config = {"from_attributes": True}


class LinkedFindingOut(BaseModel):
    id: int
    rule_id: int
    severity: Severity
    matched_snippet: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class CorrelationLinkOut(BaseModel):
    id: int
    memory_node_id: int
    submission_id: int
    finding_id: int | None
    linked_at: datetime
    link_reason: LinkReason
    similarity_score: float | None
    submission: LinkedSubmissionOut
    finding: LinkedFindingOut | None

    model_config = {"from_attributes": True}


class MemoryNodeDetail(MemoryNodeOut):
    links: List[CorrelationLinkOut]


class MemoryCampaignOut(BaseModel):
    id: int
    signature_type: SignatureType
    signature_key: str
    last_seen: datetime
    occurrence_count: int
    recurrence_window_days: int
    recurrence_threshold: int
    summary: str


class PaginatedMemoryTimeline(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[CorrelationLinkOut]


@router.get(
    "/campaigns",
    response_model=List[MemoryCampaignOut],
    summary="List recurring memory-node campaigns",
)
def list_memory_campaigns(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> List[MemoryCampaignOut]:
    query = db.query(MemoryNode).filter(MemoryNode.is_recurring.is_(True))
    if current_user.role != UserRole.admin:
        visible_nodes = (
            db.query(CorrelationLink.memory_node_id)
            .join(RawSubmission, CorrelationLink.submission_id == RawSubmission.id)
            .filter(RawSubmission.user_id == current_user.id)
        )
        query = query.filter(MemoryNode.id.in_(visible_nodes))
    nodes = query.order_by(MemoryNode.last_seen.desc(), MemoryNode.id).all()
    if not nodes:
        return []

    now = datetime.now(timezone.utc)
    oldest_cutoff = min(
        now - timedelta(days=max(1, node.recurrence_window_days))
        for node in nodes
    )
    link_query = (
        db.query(CorrelationLink.memory_node_id, CorrelationLink.linked_at)
        .join(RawSubmission, CorrelationLink.submission_id == RawSubmission.id)
        .filter(
            CorrelationLink.memory_node_id.in_([node.id for node in nodes]),
            CorrelationLink.linked_at >= oldest_cutoff,
            CorrelationLink.linked_at <= now,
        )
    )
    if current_user.role != UserRole.admin:
        link_query = link_query.filter(RawSubmission.user_id == current_user.id)
    recent_links: dict[int, list[datetime]] = {}
    for node_id, linked_at in link_query.all():
        if linked_at.tzinfo is None:
            linked_at = linked_at.replace(tzinfo=timezone.utc)
        recent_links.setdefault(node_id, []).append(linked_at)

    campaigns = []
    for node in nodes:
        occurrence_count = sum(
            linked_at
            >= now - timedelta(days=max(1, node.recurrence_window_days))
            for linked_at in recent_links.get(node.id, [])
        )
        campaigns.append(
            MemoryCampaignOut(
            id=node.id,
            signature_type=node.signature_type,
            signature_key=node.signature_key,
            last_seen=node.last_seen,
            occurrence_count=occurrence_count,
            recurrence_window_days=node.recurrence_window_days,
            recurrence_threshold=node.recurrence_threshold,
            summary=build_campaign_summary(node, occurrence_count),
            )
        )
    return campaigns


@router.get(
    "/nodes",
    response_model=PaginatedMemoryNodes,
    summary="List long-term memory nodes",
)
def list_memory_nodes(
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(20, ge=1, le=100, description="Results per page"),
    signature_type: SignatureType | None = Query(None),
    node_status: MemoryNodeStatus | None = Query(None, alias="status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PaginatedMemoryNodes:
    query = db.query(MemoryNode)
    if current_user.role != UserRole.admin:
        visible_nodes = (
            db.query(CorrelationLink.memory_node_id)
            .join(RawSubmission, CorrelationLink.submission_id == RawSubmission.id)
            .filter(RawSubmission.user_id == current_user.id)
        )
        query = query.filter(MemoryNode.id.in_(visible_nodes))
    if signature_type is not None:
        query = query.filter(MemoryNode.signature_type == signature_type)
    if node_status is not None:
        query = query.filter(MemoryNode.status == node_status)

    total = query.count()
    items = (
        query.order_by(
            MemoryNode.is_recurring.desc(),
            MemoryNode.last_seen.desc(),
            MemoryNode.id,
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return PaginatedMemoryNodes(total=total, page=page, page_size=page_size, items=items)


@router.get(
    "/nodes/{node_id}",
    response_model=MemoryNodeDetail,
    summary="Get a memory node and its linked submissions/findings",
)
def get_memory_node(
    node_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MemoryNodeDetail:
    node = db.query(MemoryNode).filter(MemoryNode.id == node_id).first()
    if node is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Memory node not found")

    links_query = (
        db.query(CorrelationLink)
        .join(RawSubmission, CorrelationLink.submission_id == RawSubmission.id)
        .options(
            joinedload(CorrelationLink.submission),
            joinedload(CorrelationLink.finding),
        )
        .filter(CorrelationLink.memory_node_id == node_id)
    )
    if current_user.role != UserRole.admin:
        links_query = links_query.filter(RawSubmission.user_id == current_user.id)
    links = links_query.order_by(CorrelationLink.linked_at.desc(), CorrelationLink.id).all()

    if current_user.role != UserRole.admin and not links:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Memory node not found")

    return MemoryNodeDetail(
        **MemoryNodeOut.model_validate(node).model_dump(),
        links=links,
    )


@router.get(
    "/nodes/{node_id}/timeline",
    response_model=PaginatedMemoryTimeline,
    summary="Get a chronological page of linked submissions and findings",
)
def get_memory_node_timeline(
    node_id: int,
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(20, ge=1, le=100, description="Timeline events per page"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PaginatedMemoryTimeline:
    node = db.query(MemoryNode.id).filter(MemoryNode.id == node_id).first()
    if node is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Memory node not found")

    query = (
        db.query(CorrelationLink)
        .join(RawSubmission, CorrelationLink.submission_id == RawSubmission.id)
        .options(
            joinedload(CorrelationLink.submission),
            joinedload(CorrelationLink.finding),
        )
        .filter(CorrelationLink.memory_node_id == node_id)
    )
    if current_user.role != UserRole.admin:
        query = query.filter(RawSubmission.user_id == current_user.id)

    total = query.count()
    items = (
        query.order_by(CorrelationLink.linked_at.asc(), CorrelationLink.id.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    if current_user.role != UserRole.admin and total == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Memory node not found")

    return PaginatedMemoryTimeline(
        total=total,
        page=page,
        page_size=page_size,
        items=items,
    )
