"""Alert Envelope (contract section 4): one shape for every detector.

`build_alert` turns a feature vector plus a detector decision into an envelope;
`validate_alert` checks an envelope against the contract and returns a list of problems.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Mapping, Optional, Sequence

from app.services.detection import contract as C

DETECTORS = ("rules", "isolation_forest", "sequence")
TECHNIQUES = (
    "reconnaissance",
    "initial_access",
    "credential_access",
    "privilege_escalation",
    "lateral_movement",
    "collection",
    "exfiltration",
    "persistence",
    "execution",
    "discovery",
    "unknown",  # anomaly detectors that do not know which technique they saw
)
SEVERITIES = ("info", "low", "medium", "high", "critical")
REQUIRED_FIELDS = (
    "schema_version", "alert_id", "tenant_id", "detector", "detector_version", "rule_id", "title",
    "description", "technique", "technique_id", "severity", "entity_id", "event_ids", "observed_at",
    "window_start", "window_end", "score", "confidence", "evidence",
)


def alert_id(detector: str, rule_id: str, entity_id: str, window_start: str) -> str:
    """Deterministic: the same detector, rule, entity and window always give the same ID."""
    short = {"rules": "rules", "isolation_forest": "iforest", "sequence": "seq"}.get(detector, detector)
    digest = hashlib.sha256(f"{detector}|{rule_id}|{entity_id}|{window_start}".encode("utf-8")).hexdigest()[:12]
    return f"alt-{short}-{digest}"


def build_alert(
    *,
    vector: Mapping[str, Any],
    detector: str,
    detector_version: str,
    rule_id: str,
    title: str,
    description: str,
    technique: str,
    technique_id: Optional[str],
    severity: str,
    score: float,
    evidence: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    return {
        "schema_version": C.SCHEMA_VERSION,
        "alert_id": alert_id(detector, rule_id, vector["entity_id"], vector["window_start"]),
        "tenant_id": vector["tenant_id"],
        "detector": detector,
        "detector_version": detector_version,
        "rule_id": rule_id,
        "title": title,
        "description": description,
        "technique": technique,
        "technique_id": technique_id,
        "severity": severity,
        "entity_id": vector["entity_id"],
        "event_ids": list(vector["event_ids"]),
        "observed_at": vector["window_end"],
        "window_start": vector["window_start"],
        "window_end": vector["window_end"],
        "score": round(float(score), 6),
        "confidence": None,  # set by fusion (contract section 5), never by a detector
        "evidence": [dict(item) for item in evidence],
    }


def validate_alert(alert: Mapping[str, Any]) -> List[str]:
    problems = [f"missing field: {name}" for name in REQUIRED_FIELDS if name not in alert]
    if problems:
        return problems
    if alert["detector"] not in DETECTORS:
        problems.append(f"unknown detector: {alert['detector']}")
    if alert["technique"] not in TECHNIQUES:
        problems.append(f"unknown technique: {alert['technique']}")
    if alert["severity"] not in SEVERITIES:
        problems.append(f"unknown severity: {alert['severity']}")
    score = alert["score"]
    if not isinstance(score, (int, float)) or isinstance(score, bool) or not 0.0 <= score <= 1.0:
        problems.append("score must be a number in [0, 1]")
    if alert["confidence"] is not None:
        problems.append("confidence must be null at detector stage")
    if not alert["rule_id"]:
        problems.append("rule_id must be set (ML detectors use ML-* ids)")
    if not isinstance(alert["event_ids"], list) or not alert["event_ids"]:
        problems.append("event_ids must be a non-empty list")
    if not isinstance(alert["evidence"], list) or not alert["evidence"]:
        problems.append("evidence must be a non-empty list")
    else:
        for item in alert["evidence"]:
            if not isinstance(item, Mapping) or "feature" not in item or "value" not in item:
                problems.append("evidence items need feature and value")
                break
    return problems
