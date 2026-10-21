"""Constants and validators shared by all detection modules.

Mirrors docs/DETECTION_CONTRACT.md (sections 1 and 3). Change this file and the
contract together, never one without the other.
"""
from __future__ import annotations

from typing import Any, Dict, List, Mapping, Tuple

SCHEMA_VERSION = "1.0"
FEATURE_SET_VERSION = "fs-1.0.0"

LAYERS: Tuple[str, ...] = (
    "identity",
    "endpoint",
    "application",
    "database",
    "network",
    "cloud",
)

ENTITY_TYPES: Tuple[str, ...] = (
    "user",
    "host",
    "ip",
    "process",
    "file",
    "domain",
    "cloud_identity",
    "application",
    "database",
    "device",
)

# Top-level canonical event fields every event must carry (EVENT_SCHEMA.md).
REQUIRED_EVENT_FIELDS: Tuple[str, ...] = (
    "tenant_id",
    "source_layer",
    "event_type",
    "observed_at",
)

# Payload keys detection relies on, per (source_layer, event_type)
# (DETECTION_CONTRACT.md section 1.2).
REQUIRED_PAYLOAD_KEYS: Dict[Tuple[str, str], Tuple[str, ...]] = {
    ("identity", "user_login"): ("result", "source_ip"),
    ("identity", "mfa_challenge"): ("result",),
    ("identity", "privilege_change"): ("role_before", "role_after"),
    ("identity", "token_issued"): ("token_type",),
    ("application", "http_request"): ("method", "path", "status_code"),
    ("database", "db_query"): ("operation", "object"),
    ("endpoint", "process_execution"): ("process_name", "command_line"),
    ("endpoint", "remote_session"): ("protocol", "result", "source_host"),
    ("network", "network_connection"): ("dst_ip", "dst_port"),
    ("network", "dns_query"): ("query_name",),
    ("cloud", "cloud_api_call"): ("event_name", "service"),
}

SUCCESS_VALUES = frozenset({"success", "succeeded", "ok", "allowed", "granted"})
FAILURE_VALUES = frozenset({"failure", "failed", "fail", "error", "denied"})

# Feature-engine definitions of "privileged" activity (feature
# privilege.privileged_ops). Kept here so rules and features agree.
ADMIN_PROCESSES = frozenset({"sudo", "su", "runas.exe", "psexec.exe", "psexec64.exe"})
PRIVILEGED_DB_OPERATIONS = frozenset({"GRANT", "DDL"})


def _blank(value: Any) -> bool:
    return value is None or value == ""


def missing_payload_keys(event: Mapping[str, Any]) -> List[str]:
    """Required payload keys (contract 1.2) that ``event`` lacks.

    Event types the contract does not list have no required keys.
    """
    payload = event.get("payload")
    if not isinstance(payload, Mapping):
        payload = {}
    required = REQUIRED_PAYLOAD_KEYS.get(
        (event.get("source_layer"), event.get("event_type")), ()
    )
    return [key for key in required if _blank(payload.get(key))]


def validate_event(event: Mapping[str, Any]) -> List[str]:
    """Strict contract check. Returns a list of problems (empty = valid).

    Stricter than the feature engine's skip rule: it also flags unknown layers
    and unknown entity types, which is what corpus validation wants.
    """
    if not isinstance(event, Mapping):
        return ["event is not an object"]

    problems: List[str] = []
    for name in REQUIRED_EVENT_FIELDS:
        if _blank(event.get(name)):
            problems.append(f"missing field: {name}")

    layer = event.get("source_layer")
    if not _blank(layer) and layer not in LAYERS:
        problems.append(f"unknown source_layer: {layer}")

    if not isinstance(event.get("payload"), Mapping):
        problems.append("payload must be an object")
    else:
        problems.extend(f"missing payload key: {k}" for k in missing_payload_keys(event))

    entities = event.get("entities")
    if entities is not None:
        if not isinstance(entities, list):
            problems.append("entities must be a list")
        else:
            for item in entities:
                if not isinstance(item, Mapping) or _blank(item.get("entity_type")) or _blank(item.get("identifier")):
                    problems.append("entity needs entity_type and identifier")
                elif item["entity_type"] not in ENTITY_TYPES:
                    problems.append(f"unknown entity_type: {item['entity_type']}")
    return problems


def normalize_outcome(value: Any) -> str:
    """Map a free-form result value to ``success`` / ``failure`` / ``unknown``."""
    if isinstance(value, str):
        text = value.strip().lower()
        if text in SUCCESS_VALUES:
            return "success"
        if text in FAILURE_VALUES:
            return "failure"
    return "unknown"
