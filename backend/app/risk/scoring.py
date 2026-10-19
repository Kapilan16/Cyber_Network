"""Pure, deterministic risk score calculation.

Each input component is mapped to a 0-100 signal, multiplied by its configured
weight, and divided by the sum of weights. Weights therefore need not add up
to one. Band boundaries are low 0-24, medium 25-49, high 50-74, critical 75-100.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from app.models.risk_score import RiskBand

SEVERITY_SIGNAL = {
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 100,
}


@dataclass(frozen=True)
class RiskCalculation:
    score: int
    band: RiskBand
    components: dict[str, int | float]


def calculate_risk_score(
    severities: Iterable[str],
    local_recurrence_count: int,
    worst_reputation_score: int | None,
    *,
    network_recurrence_count: int = 0,
    weights: dict[str, float] | None = None,
    max_recurrence_matches: int = 5,
    network_recurrence_multiplier: float = 2.0,
) -> RiskCalculation:
    """Calculate a normalized weighted score from documented 0-100 signals."""
    selected_weights = weights or {
        "rule_severity": 0.4,
        "recurrence": 0.3,
        "enrichment": 0.3,
    }
    required = {"rule_severity", "recurrence", "enrichment"}
    if set(selected_weights) != required:
        raise ValueError(f"weights must have exactly these keys: {sorted(required)}")
    if any(value < 0 for value in selected_weights.values()):
        raise ValueError("risk weights cannot be negative")
    weight_total = sum(selected_weights.values())
    if weight_total <= 0:
        raise ValueError("at least one risk weight must be positive")
    if max_recurrence_matches <= 0:
        raise ValueError("max_recurrence_matches must be positive")

    severity_signal = max(
        (SEVERITY_SIGNAL.get(_severity_value(value), 0) for value in severities),
        default=0,
    )
    bounded_local_count = max(0, local_recurrence_count)
    bounded_network_count = max(0, network_recurrence_count)
    recurrence_signal = min(
        100.0,
        100.0
        * min(
            max_recurrence_matches,
            bounded_local_count
            + bounded_network_count * network_recurrence_multiplier,
        )
        / max_recurrence_matches,
    )
    reputation_signal = (
        min(100, max(0, int(worst_reputation_score)))
        if worst_reputation_score is not None
        else 0
    )
    components = {
        "rule_severity_signal": severity_signal,
        "local_recurrence_count": bounded_local_count,
        "network_recurrence_count": bounded_network_count,
        "recurrence_signal": round(recurrence_signal, 2),
        "enrichment_signal": reputation_signal,
        "rule_severity_contribution": round(
            severity_signal * selected_weights["rule_severity"] / weight_total,
            2,
        ),
        "recurrence_contribution": round(
            recurrence_signal * selected_weights["recurrence"] / weight_total,
            2,
        ),
        "enrichment_contribution": round(
            reputation_signal * selected_weights["enrichment"] / weight_total,
            2,
        ),
    }
    score = round(
        components["rule_severity_contribution"]
        + components["recurrence_contribution"]
        + components["enrichment_contribution"]
    )
    score = min(100, max(0, score))
    if score >= 75:
        band = RiskBand.critical
    elif score >= 50:
        band = RiskBand.high
    elif score >= 25:
        band = RiskBand.medium
    else:
        band = RiskBand.low
    return RiskCalculation(score=score, band=band, components=components)


def _severity_value(severity: object) -> str:
    return str(getattr(severity, "value", severity)).lower()
