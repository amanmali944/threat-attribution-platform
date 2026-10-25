"""Tiny builders for canonical test events (documentation-range IPs only)."""
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

TENANT = "t1"
# 2026-10-05T10:00:00Z. Its epoch second is a multiple of 300 and of 150, so
# offsets 0..299 land in one 300 s window.
BASE = datetime(2026, 10, 5, 10, 0, 0, tzinfo=timezone.utc)


def iso(offset_s: float) -> str:
    moment = BASE + timedelta(seconds=offset_s)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _event(eid, offset, layer, etype, entities, payload, tenant=TENANT) -> Dict[str, Any]:
    return {
        "event_id": eid,
        "tenant_id": tenant,
        "source_layer": layer,
        "event_type": etype,
        "observed_at": iso(offset),
        "severity": "info",
        "entities": entities,
        "payload": payload,
        "metadata": {},
    }


def login(eid, offset, user, ip, result, tenant=TENANT, host="idp-1", **extra) -> Dict[str, Any]:
    payload = {"result": result, "source_ip": ip}
    payload.update(extra)
    return _event(
        eid, offset, "identity", "user_login",
        [{"entity_type": "user", "identifier": user}, {"entity_type": "host", "identifier": host}],
        payload, tenant,
    )


def http(eid, offset, user, ip, path, status, app="portal", tenant=TENANT, **extra) -> Dict[str, Any]:
    payload = {"method": "GET", "path": path, "status_code": status, "source_ip": ip}
    payload.update(extra)
    return _event(
        eid, offset, "application", "http_request",
        [{"entity_type": "user", "identifier": user}, {"entity_type": "application", "identifier": app}],
        payload, tenant,
    )


def dbq(eid, offset, user, operation, obj, db="db-1", tenant=TENANT, **extra) -> Dict[str, Any]:
    payload = {"operation": operation, "object": obj}
    payload.update(extra)
    return _event(
        eid, offset, "database", "db_query",
        [{"entity_type": "user", "identifier": user}, {"entity_type": "database", "identifier": db}],
        payload, tenant,
    )


def proc(eid, offset, user, host, process_name, command_line="x", tenant=TENANT) -> Dict[str, Any]:
    return _event(
        eid, offset, "endpoint", "process_execution",
        [{"entity_type": "host", "identifier": host}, {"entity_type": "user", "identifier": user}],
        {"process_name": process_name, "command_line": command_line}, tenant,
    )


def vector_for(vectors: List[Dict[str, Any]], entity_id: str, window_start: Optional[str] = None):
    """The single vector for an entity (optionally in one window)."""
    found = [
        v for v in vectors
        if v["entity_id"] == entity_id and (window_start is None or v["window_start"] == window_start)
    ]
    assert len(found) == 1, f"expected 1 vector for {entity_id}, got {len(found)}"
    return found[0]
