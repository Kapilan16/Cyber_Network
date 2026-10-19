"""Recurring-pattern detection and campaign summary helpers."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models.memory import CorrelationLink, MemoryNode, MemoryNodeStatus

logger = logging.getLogger(__name__)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def scan_recurring_memory_nodes(
    db: Session,
    *,
    now: datetime | None = None,
) -> dict[str, int]:
    """Refresh active-node recurrence flags and mark inactive nodes dormant."""
    current_time = _utc(now or datetime.now(timezone.utc))
    nodes = (
        db.query(MemoryNode)
        .filter(MemoryNode.status == MemoryNodeStatus.active)
        .all()
    )
    if not nodes:
        return {"scanned": 0, "recurring": 0, "dormant": 0}

    oldest_cutoff = min(
        current_time - timedelta(days=max(1, node.recurrence_window_days))
        for node in nodes
    )
    links = (
        db.query(CorrelationLink.memory_node_id, CorrelationLink.linked_at)
        .filter(
            CorrelationLink.memory_node_id.in_([node.id for node in nodes]),
            CorrelationLink.linked_at >= oldest_cutoff,
            CorrelationLink.linked_at <= current_time,
        )
        .all()
    )
    links_by_node: dict[int, list[datetime]] = {}
    for node_id, linked_at in links:
        links_by_node.setdefault(node_id, []).append(_utc(linked_at))

    recurring_count = 0
    dormant_count = 0
    for node in nodes:
        cutoff = current_time - timedelta(days=max(1, node.recurrence_window_days))
        recent_count = sum(
            linked_at >= cutoff
            for linked_at in links_by_node.get(node.id, [])
        )
        is_stale = _utc(node.last_seen) < cutoff and recent_count == 0

        if is_stale:
            node.status = MemoryNodeStatus.dormant
            node.is_recurring = False
            dormant_count += 1
        else:
            node.is_recurring = recent_count >= max(1, node.recurrence_threshold)
            recurring_count += int(node.is_recurring)

    db.flush()
    logger.info(
        "Scanned %d memory nodes: %d recurring, %d newly dormant",
        len(nodes),
        recurring_count,
        dormant_count,
    )
    return {
        "scanned": len(nodes),
        "recurring": recurring_count,
        "dormant": dormant_count,
    }


def scan_recurring_memory_nodes_background() -> dict[str, int]:
    """Run a recurrence scan using an independent database session."""
    from app.core.database import SessionLocal

    db = SessionLocal()
    try:
        result = scan_recurring_memory_nodes(db)
        db.commit()
        return result
    except Exception:
        db.rollback()
        logger.exception("Recurring memory-node scan failed")
        raise
    finally:
        db.close()


def build_campaign_summary(node: MemoryNode, occurrence_count: int) -> str:
    """Create a concise human-readable description of a recurring signature."""
    subject = {
        "mitre_technique": f"Technique {node.signature_key}",
        "rule": f"Rule {node.signature_key}",
        "embedding_cluster": f"Embedding cluster {node.signature_key}",
    }[node.signature_type.value]
    unit = "time" if occurrence_count == 1 else "times"
    return (
        f"{subject} observed {occurrence_count} {unit} "
        f"in {node.recurrence_window_days} days"
    )
