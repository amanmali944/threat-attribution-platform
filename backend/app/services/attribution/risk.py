"""Explainable risk scoring (Phase 7, contract section 8), per incident and per entity.

    score = 100 x (1 - prod_i (1 - confidence_i x weight_i x 2^(-age_i / half_life)))

* ``confidence_i`` - the Fused Alert's calibrated confidence;
* ``weight_i`` - 0.5 + 0.1 x criticality of what the alert touched (criticality 1..5 -> 0.6..1.0,
  so a criticality-5 asset counts in full, as in the contract example);
* ``age_i`` - seconds from the alert's last activity to ``computed_at``; half-life 24 h by default.

Every contribution is kept (``contributors``), sorted by size, so the UI can say why. A score of
0 has no contributors; a non-zero score always has at least one.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from app.services.attribution.correlation import EMPTY_INVENTORY, AssetInventory, _profile
from app.services.detection import contract as C
from app.services.detection.labeling import to_us
from app.services.detection.resolve import EnrichedEvent, entity_id

DEFAULT_HALF_LIFE_SECONDS = 86_400
LEVELS = ((75.0, "critical"), (50.0, "high"), (25.0, "medium"), (0.0, "low"))


def level(score: float) -> str:
    return next(name for floor, name in LEVELS if score >= floor)


def weight(criticality: int) -> float:
    if not 1 <= int(criticality) <= 5:
        raise ValueError("criticality must be in 1..5")
    return round(0.5 + 0.1 * int(criticality), 6)


def alert_criticality(alert: Mapping[str, Any], events: Mapping[str, EnrichedEvent],
                      assets: AssetInventory = EMPTY_INVENTORY) -> int:
    """Highest criticality among the company hosts an alert's entity and events touch (default 1)."""
    host_crit = {entity_id("host", assets.tenant_id, h): c for h, c in assets.criticality.items()}
    node = _profile(0, alert, events, assets)
    touched = node.actors | node.targets | {alert["entity_id"]}
    return max([host_crit[t] for t in touched if t in host_crit] or [1])


def score(contributions: Iterable[Mapping[str, Any]], computed_at: str,
          half_life_seconds: int = DEFAULT_HALF_LIFE_SECONDS) -> Dict[str, Any]:
    """Combine contributions ``{source_id, kind, reason, confidence, criticality, last_seen}``."""
    now = to_us(computed_at)
    remaining = 1.0
    contributors: List[Dict[str, Any]] = []
    for item in contributions:
        age = max(0, (now - to_us(item["last_seen"])) // 1_000_000)
        w = weight(item.get("criticality", 1))
        decayed = float(item["confidence"]) * w * 2 ** (-age / half_life_seconds)
        if decayed <= 0:
            continue
        remaining *= 1.0 - min(decayed, 1.0)
        contributors.append({"source_id": item["source_id"], "kind": item.get("kind", "fused_alert"),
                             "reason": item.get("reason", ""), "confidence": round(float(item["confidence"]), 6),
                             "weight": w, "age_seconds": int(age), "decayed_contribution": round(decayed, 6)})
    value = round(100.0 * (1.0 - remaining), 2)
    contributors.sort(key=lambda c: (-c["decayed_contribution"], c["source_id"]))
    return {"score": value, "level": level(value), "computed_at": computed_at,
            "half_life_seconds": half_life_seconds, "contributors": contributors}


def _reason(alert: Mapping[str, Any]) -> str:
    rules = [e["rule_id"] for e in alert.get("evidence", []) if e.get("rule_id")]
    return (f"{alert.get('technique', 'unknown')} on {alert.get('entity_type', 'entity')}"
            + (f" ({', '.join(rules)})" if rules else " (fusion)"))


def _contribution(alert: Mapping[str, Any], criticality: int) -> Dict[str, Any]:
    return {"source_id": alert["fused_alert_id"], "kind": "fused_alert", "reason": _reason(alert),
            "confidence": alert["confidence"], "criticality": criticality, "last_seen": alert["window_end"]}


def incident_risk(incident: Mapping[str, Any], fused_alerts: Sequence[Mapping[str, Any]],
                  criticality: Mapping[str, int], computed_at: str,
                  half_life_seconds: int = DEFAULT_HALF_LIFE_SECONDS) -> Dict[str, Any]:
    """Risk Score (contract section 8) of one incident; ``criticality`` maps fused_alert_id -> 1..5."""
    members = set(incident["fused_alert_ids"])
    result = score((_contribution(a, criticality.get(a["fused_alert_id"], 1)) for a in fused_alerts
                    if a["fused_alert_id"] in members), computed_at, half_life_seconds)
    return {"schema_version": C.SCHEMA_VERSION, "tenant_id": incident.get("tenant_id"), "subject_type": "incident",
            "subject_id": incident["incident_id"]} | result


def entity_risk(entity: str, fused_alerts: Sequence[Mapping[str, Any]], criticality: Mapping[str, int],
                computed_at: str, tenant_id: Optional[str] = None,
                half_life_seconds: int = DEFAULT_HALF_LIFE_SECONDS) -> Dict[str, Any]:
    """Risk Score of one entity from the Fused Alerts raised on it."""
    result = score((_contribution(a, criticality.get(a["fused_alert_id"], 1)) for a in fused_alerts
                    if a["entity_id"] == entity), computed_at, half_life_seconds)
    return {"schema_version": C.SCHEMA_VERSION, "tenant_id": tenant_id, "subject_type": "entity",
            "subject_id": entity} | result
