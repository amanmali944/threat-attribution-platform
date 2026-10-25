"""Entity resolution: canonical event -> enriched event (contract section 2).

Turns identifiers scattered across ``entities[]`` and ``payload`` into one set
of deterministic entity IDs, and derives who acted (user / ip / host / device)
and what they acted on (target). This is what lets one question span layers.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from app.services.detection import contract as C

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ONE_US = timedelta(microseconds=1)


class EventSkipped(ValueError):
    """The event cannot be used by detection (reason is recorded, not raised)."""

    def __init__(self, reason: str, missing: Sequence[str] = ()):
        super().__init__(reason)
        self.reason = reason
        self.missing = tuple(missing)


@dataclass(frozen=True)
class EntityRef:
    entity_id: str
    entity_type: str
    identifier: str


@dataclass(frozen=True, eq=False)
class EnrichedEvent:
    event_id: str
    tenant_id: str
    source_layer: str
    event_type: str
    observed_at: datetime
    ts_us: int  # exact microseconds since the Unix epoch (ordering, windows)
    actor_user: Optional[EntityRef]
    actor_ip: Optional[EntityRef]
    actor_host: Optional[EntityRef]
    actor_device: Optional[EntityRef]
    target: Optional[EntityRef]
    target_criticality: int
    outcome: str
    payload: Mapping[str, Any]

    @property
    def ts(self) -> float:
        return self.ts_us / 1_000_000

    def subjects(self) -> List[EntityRef]:
        """Actor-side entities this event contributes features to (contract 3.2)."""
        seen: Dict[str, EntityRef] = {}
        for ref in (self.actor_user, self.actor_ip, self.actor_host):
            if ref is not None and ref.entity_id not in seen:
                seen[ref.entity_id] = ref
        return list(seen.values())

    def to_dict(self) -> Dict[str, Any]:
        """Enriched Event in the contract section 2.2 shape."""

        def _id(ref: Optional[EntityRef]) -> Optional[str]:
            return ref.entity_id if ref else None

        return {
            "schema_version": C.SCHEMA_VERSION,
            "event_id": self.event_id,
            "tenant_id": self.tenant_id,
            "source_layer": self.source_layer,
            "event_type": self.event_type,
            "observed_at": iso_utc(self.observed_at),
            "actor_user": _id(self.actor_user),
            "actor_ip": _id(self.actor_ip),
            "actor_host": _id(self.actor_host),
            "actor_device": _id(self.actor_device),
            "target": _id(self.target),
            "target_criticality": self.target_criticality,
            "outcome": self.outcome,
        }


def entity_id(entity_type: str, tenant_id: str, identifier: str) -> str:
    """``ent-{type}-{sha256(tenant_id:identifier)[:8]}`` - same as the platform.

    Identifiers are used verbatim (no case folding) so IDs stay identical to the
    ones the platform stores; normalising identifiers is the producer's job.
    """
    digest = hashlib.sha256(f"{tenant_id}:{identifier}".encode("utf-8")).hexdigest()[:8]
    return f"ent-{entity_type}-{digest}"


def make_ref(entity_type: str, tenant_id: str, identifier: str) -> EntityRef:
    return EntityRef(entity_id(entity_type, tenant_id, identifier), entity_type, identifier)


def parse_timestamp(value: Any) -> datetime:
    """ISO 8601 string or datetime -> timezone-aware UTC datetime.

    Naive values are taken to be UTC (the schema says observed_at is UTC).
    """
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if text[-1:] in ("Z", "z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    else:
        raise ValueError(f"unsupported timestamp: {value!r}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def iso_utc(value: datetime) -> str:
    """UTC datetime -> ``2026-10-05T10:18:45Z`` (fractional seconds only if non-zero)."""
    value = value.astimezone(timezone.utc)
    if value.microsecond:
        return value.strftime("%Y-%m-%dT%H:%M:%S.%f").rstrip("0") + "Z"
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _event_id(raw: Mapping[str, Any]) -> str:
    """Stable ID: the event's own, else a hash of its content (never random)."""
    own = raw.get("event_id") or raw.get("id")
    if own:
        return str(own)
    blob = json.dumps(raw, sort_keys=True, default=str)
    return "evt-" + hashlib.sha256(blob.encode("utf-8")).hexdigest()[:12]


def _clamp_criticality(value: Any) -> int:
    try:
        return max(1, min(5, int(value)))
    except (TypeError, ValueError):
        return 1


def _outcome(payload: Mapping[str, Any]) -> str:
    result = C.normalize_outcome(payload.get("result"))
    if result == "unknown":
        result = C.normalize_outcome(payload.get("outcome"))
    if result != "unknown":
        return result
    status = payload.get("status_code")
    if isinstance(status, bool):
        return "unknown"
    try:
        return "failure" if int(status) >= 400 else "success"
    except (TypeError, ValueError):
        return "unknown"


def resolve_event(
    raw: Mapping[str, Any],
    assets: Optional[Mapping[str, Any]] = None,
) -> EnrichedEvent:
    """Resolve one canonical event. Raises :class:`EventSkipped` if unusable.

    ``assets`` maps an identifier *or* entity ID to a criticality (1-5).
    """
    if not isinstance(raw, Mapping):
        raise EventSkipped("event is not an object")
    for name in C.REQUIRED_EVENT_FIELDS:
        if raw.get(name) in (None, ""):
            raise EventSkipped(f"missing field: {name}", [name])
    payload = raw.get("payload")
    if not isinstance(payload, Mapping):
        raise EventSkipped("payload must be an object")
    missing = C.missing_payload_keys(raw)
    if missing:
        raise EventSkipped("missing required payload keys", missing)
    try:
        observed_at = parse_timestamp(raw["observed_at"])
    except (ValueError, TypeError) as exc:
        raise EventSkipped(f"bad observed_at: {exc}")

    tenant = str(raw["tenant_id"])
    layer = str(raw["source_layer"])

    ents: List[EntityRef] = []
    for item in raw.get("entities") or []:
        if not isinstance(item, Mapping):
            continue
        etype, ident = item.get("entity_type"), item.get("identifier")
        if etype and ident not in (None, ""):
            ents.append(make_ref(str(etype), tenant, str(ident)))

    def first(entity_type: str) -> Optional[EntityRef]:
        return next((e for e in ents if e.entity_type == entity_type), None)

    def from_payload(key: str, entity_type: str) -> Optional[EntityRef]:
        value = payload.get(key)
        if value in (None, ""):
            return None
        return make_ref(entity_type, tenant, str(value))

    dst_ip = payload.get("dst_ip")
    dst_ip = str(dst_ip) if dst_ip not in (None, "") else None

    actor_user = first("user") or first("cloud_identity")
    actor_ip = from_payload("source_ip", "ip") or next(
        (e for e in ents if e.entity_type == "ip" and e.identifier != dst_ip), None
    )
    source_host = from_payload("source_host", "host")
    if source_host is not None:
        actor_host = source_host
    elif layer == "endpoint":
        actor_host = first("host")
    else:
        actor_host = None
    actor_device = from_payload("device_id", "device") or first("device")

    target: Optional[EntityRef]
    if layer == "database":
        target = first("database")
    elif layer == "application":
        target = first("application")
    elif layer == "endpoint":
        hosts = [e for e in ents if e.entity_type == "host"]
        destinations = [
            h for h in hosts if not (source_host and h.entity_id == source_host.entity_id)
        ]
        target = destinations[0] if destinations else (hosts[0] if hosts else None)
    elif layer == "identity":
        target = first("application") or first("host")
    elif layer == "network":
        target = first("domain") or from_payload("dst_ip", "ip")
    elif layer == "cloud":
        target = from_payload("service", "application")
    else:
        target = None

    criticality = 1
    if target is not None and assets:
        value = assets.get(target.entity_id, assets.get(target.identifier))
        if value is not None:
            criticality = _clamp_criticality(value)

    return EnrichedEvent(
        event_id=_event_id(raw),
        tenant_id=tenant,
        source_layer=layer,
        event_type=str(raw["event_type"]),
        observed_at=observed_at,
        ts_us=(observed_at - _EPOCH) // _ONE_US,
        actor_user=actor_user,
        actor_ip=actor_ip,
        actor_host=actor_host,
        actor_device=actor_device,
        target=target,
        target_criticality=criticality,
        outcome=_outcome(payload),
        payload=payload,
    )


def resolve_events(
    raw_events: Iterable[Mapping[str, Any]],
    assets: Optional[Mapping[str, Any]] = None,
) -> Tuple[List[EnrichedEvent], Dict[str, Any]]:
    """Resolve a batch. Unusable events are skipped *and counted*, never raised.

    Returns ``(events sorted by time then id, report)``. Events repeated under
    the same ``(tenant_id, event_id)`` are kept once.
    """
    events: List[EnrichedEvent] = []
    skipped: List[Dict[str, Any]] = []
    unknown_types: Counter = Counter()
    seen = set()
    duplicates = 0
    total = 0

    for raw in raw_events:
        total += 1
        try:
            event = resolve_event(raw, assets)
        except EventSkipped as exc:
            skipped.append(
                {
                    "event_id": _event_id(raw) if isinstance(raw, Mapping) else None,
                    "reason": exc.reason,
                    "missing": list(exc.missing),
                }
            )
            continue
        key = (event.tenant_id, event.event_id)
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        if (event.source_layer, event.event_type) not in C.REQUIRED_PAYLOAD_KEYS:
            unknown_types[f"{event.source_layer}:{event.event_type}"] += 1
        events.append(event)

    events.sort(key=lambda e: (e.ts_us, e.event_id))
    report = {
        "events_in": total,
        "events_resolved": len(events),
        "skipped_events": skipped,
        "duplicate_events": duplicates,
        "unknown_event_types": dict(sorted(unknown_types.items())),
    }
    return events, report
