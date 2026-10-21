"""Deterministic feature engine (contract section 3, feature set fs-1.0.0).

One feature definition serves training, evaluation and live inference:

    baseline = fit_baseline(normal_events, config)          # learn "normal"
    vectors  = compute_features(events, baseline, config)   # same code everywhere

Same input => byte-identical output: events are sorted, windows are aligned to
the Unix epoch, all arithmetic uses exact integer microseconds where it can,
and floats are rounded to 6 places.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from app.services.detection import contract as C
from app.services.detection.resolve import (
    EnrichedEvent,
    EntityRef,
    iso_utc,
    resolve_events,
)

# (name, kind) in output order. Kind "int" => integer count/flag, "float" => rounded float.
_FEATURE_SPEC: Tuple[Tuple[str, str], ...] = (
    ("volume.event_count", "int"),
    ("volume.bytes_out", "float"),
    ("volume.rows_read", "float"),
    ("volume.distinct_sessions", "int"),
    ("failure.login_failure_rate", "float"),
    ("failure.max_consecutive_failures", "int"),
    ("failure.http_error_rate", "float"),
    ("diversity.distinct_targets", "int"),
    ("diversity.distinct_accounts_from_ip", "int"),
    ("diversity.endpoint_entropy", "float"),
    ("timing.mean_interarrival_s", "float"),
    ("timing.interarrival_cv", "float"),
    ("timing.off_hours", "int"),
    ("novelty.new_source_ip", "int"),
    ("novelty.new_device", "int"),
    ("novelty.new_country", "int"),
    ("novelty.new_target", "int"),
    ("privilege.privileged_ops", "int"),
    ("privilege.role_changes", "int"),
    ("privilege.tokens_issued", "int"),
    ("peer.volume_zscore", "float"),
    ("peer.targets_zscore", "float"),
)
FEATURE_NAMES: Tuple[str, ...] = tuple(name for name, _ in _FEATURE_SPEC)
FEATURE_KINDS: Dict[str, str] = dict(_FEATURE_SPEC)


@dataclass(frozen=True)
class FeatureConfig:
    window_seconds: int = 300
    stride_seconds: Optional[int] = None  # None => tumbling (stride == window)
    min_history_events: int = 20          # below this a baseline entity is "cold"
    usual_hour_share: float = 0.02        # an hour is "usual" above this share of baseline events
    peer_std_floor: float = 1.0           # floor on cohort std (counts are integers)

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        stride = self.effective_stride
        if stride <= 0 or stride > self.window_seconds:
            raise ValueError("stride_seconds must be in (0, window_seconds]")
        if self.window_seconds % stride != 0:
            raise ValueError("window_seconds must be a multiple of stride_seconds")

    @property
    def effective_stride(self) -> int:
        return self.stride_seconds if self.stride_seconds is not None else self.window_seconds


# --------------------------------------------------------------------------- baseline


@dataclass
class EntityBaseline:
    event_count: int = 0
    known_ips: Set[str] = field(default_factory=set)
    known_devices: Set[str] = field(default_factory=set)
    known_countries: Set[str] = field(default_factory=set)
    known_targets: Set[str] = field(default_factory=set)
    hour_counts: Dict[int, int] = field(default_factory=dict)


@dataclass
class Baseline:
    """What "normal" looked like. Fit on a normal period; input to feature extraction."""

    feature_set_version: str
    window_seconds: int
    stride_seconds: int
    n_events: int
    entities: Dict[str, EntityBaseline]
    cohort_of: Dict[str, str]
    cohort_stats: Dict[str, Dict[str, float]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feature_set_version": self.feature_set_version,
            "window_seconds": self.window_seconds,
            "stride_seconds": self.stride_seconds,
            "n_events": self.n_events,
            "entities": {
                eid: {
                    "event_count": eb.event_count,
                    "known_ips": sorted(eb.known_ips),
                    "known_devices": sorted(eb.known_devices),
                    "known_countries": sorted(eb.known_countries),
                    "known_targets": sorted(eb.known_targets),
                    "hour_counts": {str(h): c for h, c in sorted(eb.hour_counts.items())},
                }
                for eid, eb in sorted(self.entities.items())
            },
            "cohort_of": dict(sorted(self.cohort_of.items())),
            "cohort_stats": {k: dict(v) for k, v in sorted(self.cohort_stats.items())},
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Baseline":
        return cls(
            feature_set_version=data["feature_set_version"],
            window_seconds=int(data["window_seconds"]),
            stride_seconds=int(data["stride_seconds"]),
            n_events=int(data["n_events"]),
            entities={
                eid: EntityBaseline(
                    event_count=int(e["event_count"]),
                    known_ips=set(e["known_ips"]),
                    known_devices=set(e["known_devices"]),
                    known_countries=set(e["known_countries"]),
                    known_targets=set(e["known_targets"]),
                    hour_counts={int(h): int(c) for h, c in e["hour_counts"].items()},
                )
                for eid, e in data["entities"].items()
            },
            cohort_of=dict(data.get("cohort_of", {})),
            cohort_stats={k: dict(v) for k, v in data["cohort_stats"].items()},
        )


# --------------------------------------------------------------------------- windowing


def _order(event: EnrichedEvent) -> Tuple[int, str]:
    return (event.ts_us, event.event_id)


def _window_starts(ts_us: int, config: FeatureConfig) -> List[int]:
    """Start seconds (ascending) of every window that contains the event."""
    second = ts_us // 1_000_000
    stride = config.effective_stride
    last = (second // stride) * stride
    count = config.window_seconds // stride
    return [last - i * stride for i in range(count - 1, -1, -1)]


def _group(
    events: Sequence[EnrichedEvent], config: FeatureConfig
) -> Tuple[Dict[Tuple[str, str, int], List[EnrichedEvent]], Dict[str, EntityRef]]:
    groups: Dict[Tuple[str, str, int], List[EnrichedEvent]] = defaultdict(list)
    refs: Dict[str, EntityRef] = {}
    for event in events:  # callers pass events already sorted by _order
        for subject in event.subjects():
            refs[subject.entity_id] = subject
            for start in _window_starts(event.ts_us, config):
                groups[(event.tenant_id, subject.entity_id, start)].append(event)
    return groups, refs


def _cohort(entity_id: str, entity_type: str, cohort_of: Mapping[str, str]) -> str:
    return cohort_of.get(entity_id) or entity_type


def _mean_std(values: Sequence[float]) -> Tuple[float, float]:
    n = len(values)
    mean = math.fsum(values) / n
    var = math.fsum((v - mean) ** 2 for v in values) / n  # population std
    return mean, math.sqrt(var)


def _hour(ts_us: int) -> int:
    return (ts_us // 3_600_000_000) % 24


def fit_baseline(
    events: Iterable[EnrichedEvent],
    config: FeatureConfig = FeatureConfig(),
    cohort_of: Optional[Mapping[str, str]] = None,
) -> Baseline:
    """Learn per-entity history and per-cohort volume statistics from normal events."""
    ordered = sorted(events, key=_order)
    cohort_of = dict(cohort_of or {})
    entities: Dict[str, EntityBaseline] = {}

    for event in ordered:
        hour = _hour(event.ts_us)
        country = event.payload.get("country")
        for subject in event.subjects():
            eb = entities.setdefault(subject.entity_id, EntityBaseline())
            eb.event_count += 1
            if event.actor_ip and event.actor_ip.entity_id != subject.entity_id:
                eb.known_ips.add(event.actor_ip.entity_id)
            if event.actor_device and event.actor_device.entity_id != subject.entity_id:
                eb.known_devices.add(event.actor_device.entity_id)
            if isinstance(country, str) and country:
                eb.known_countries.add(country)
            if event.target is not None:
                eb.known_targets.add(event.target.entity_id)
            eb.hour_counts[hour] = eb.hour_counts.get(hour, 0) + 1

    groups, refs = _group(ordered, config)
    volumes: Dict[str, List[float]] = defaultdict(list)
    targets: Dict[str, List[float]] = defaultdict(list)
    for (_tenant, eid, _start), window_events in groups.items():
        cohort = _cohort(eid, refs[eid].entity_type, cohort_of)
        volumes[cohort].append(float(len(window_events)))
        targets[cohort].append(
            float(len({e.target.entity_id for e in window_events if e.target is not None}))
        )

    cohort_stats: Dict[str, Dict[str, float]] = {}
    for cohort in sorted(volumes):
        v_mean, v_std = _mean_std(volumes[cohort])
        t_mean, t_std = _mean_std(targets[cohort])
        cohort_stats[cohort] = {
            "n_windows": len(volumes[cohort]),
            "volume_mean": v_mean,
            "volume_std": v_std,
            "targets_mean": t_mean,
            "targets_std": t_std,
        }

    return Baseline(
        feature_set_version=C.FEATURE_SET_VERSION,
        window_seconds=config.window_seconds,
        stride_seconds=config.effective_stride,
        n_events=len(ordered),
        entities=entities,
        cohort_of=cohort_of,
        cohort_stats=cohort_stats,
    )


# --------------------------------------------------------------------------- features


def _num(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _entropy_bits(counts: Mapping[str, int]) -> float:
    total = sum(counts.values())
    if total <= 0 or len(counts) < 2:
        return 0.0
    return -math.fsum(
        (c / total) * math.log2(c / total) for _, c in sorted(counts.items()) if c > 0
    )


def _status_code(payload: Mapping[str, Any]) -> Optional[int]:
    value = payload.get("status_code")
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _is_privileged_op(event: EnrichedEvent) -> bool:
    payload = event.payload
    if event.event_type == "db_query":
        operation = str(payload.get("operation", "")).upper()
        return payload.get("privileged") is True or operation in C.PRIVILEGED_DB_OPERATIONS
    if event.event_type == "process_execution":
        name = str(payload.get("process_name", "")).replace("\\", "/").rsplit("/", 1)[-1].lower()
        return name in C.ADMIN_PROCESSES
    return False


def _window_features(
    subject: EntityRef,
    events: Sequence[EnrichedEvent],
    baseline: Optional[Baseline],
    config: FeatureConfig,
) -> Dict[str, Any]:
    f: Dict[str, Any] = {}

    # ---- volume
    f["volume.event_count"] = len(events)
    f["volume.bytes_out"] = math.fsum(
        v for e in events if (v := _num(e.payload.get("bytes_out"))) is not None
    )
    f["volume.rows_read"] = math.fsum(
        v
        for e in events
        if e.event_type == "db_query"
        and str(e.payload.get("operation", "")).upper() == "SELECT"
        and (v := _num(e.payload.get("rows_returned"))) is not None
    )
    f["volume.distinct_sessions"] = len(
        {str(e.payload["session_id"]) for e in events if e.payload.get("session_id") not in (None, "")}
    )

    # ---- failure
    logins = [e for e in events if e.event_type == "user_login"]
    failures = sum(1 for e in logins if e.outcome == "failure")
    f["failure.login_failure_rate"] = failures / len(logins) if logins else 0.0
    run = best = 0
    for e in logins:
        run = run + 1 if e.outcome == "failure" else 0
        best = max(best, run)
    f["failure.max_consecutive_failures"] = best
    http = [e for e in events if e.event_type == "http_request"]
    http_errors = sum(1 for e in http if (code := _status_code(e.payload)) is not None and code >= 400)
    f["failure.http_error_rate"] = http_errors / len(http) if http else 0.0

    # ---- diversity
    f["diversity.distinct_targets"] = len({e.target.entity_id for e in events if e.target is not None})
    f["diversity.distinct_accounts_from_ip"] = len(
        {e.actor_user.entity_id for e in events if e.actor_user is not None}
    )
    tokens: Counter = Counter()
    for e in events:
        if e.event_type == "http_request" and e.payload.get("path") not in (None, ""):
            tokens[str(e.payload["path"]).split("?", 1)[0]] += 1
        elif e.event_type == "db_query" and e.payload.get("object") not in (None, ""):
            tokens[str(e.payload["object"])] += 1
    f["diversity.endpoint_entropy"] = _entropy_bits(tokens)

    # ---- timing
    times = [e.ts_us for e in events]
    gaps = [(b - a) / 1_000_000 for a, b in zip(times, times[1:])]
    mean_gap = math.fsum(gaps) / len(gaps) if gaps else 0.0
    f["timing.mean_interarrival_s"] = mean_gap
    if len(events) < 3:
        f["timing.interarrival_cv"] = 1.0
    elif mean_gap == 0:
        f["timing.interarrival_cv"] = 0.0
    else:
        var = math.fsum((g - mean_gap) ** 2 for g in gaps) / len(gaps)
        f["timing.interarrival_cv"] = math.sqrt(var) / mean_gap

    # ---- baseline-relative: off-hours + novelty
    entity_base = baseline.entities.get(subject.entity_id) if baseline else None
    warm = entity_base is not None and entity_base.event_count >= config.min_history_events
    f["timing.off_hours"] = 0
    f["novelty.new_source_ip"] = 0
    f["novelty.new_device"] = 0
    f["novelty.new_country"] = 0
    f["novelty.new_target"] = 0
    if warm:
        total_hours = sum(entity_base.hour_counts.values())
        usual = {
            h for h, c in entity_base.hour_counts.items() if c / total_hours >= config.usual_hour_share
        }
        off = sum(1 for e in events if _hour(e.ts_us) not in usual)
        f["timing.off_hours"] = 1 if off / len(events) > 0.5 else 0
        f["novelty.new_source_ip"] = int(
            any(
                e.actor_ip is not None
                and e.actor_ip.entity_id != subject.entity_id
                and e.actor_ip.entity_id not in entity_base.known_ips
                for e in events
            )
        )
        f["novelty.new_device"] = int(
            any(
                e.actor_device is not None
                and e.actor_device.entity_id != subject.entity_id
                and e.actor_device.entity_id not in entity_base.known_devices
                for e in events
            )
        )
        f["novelty.new_country"] = int(
            any(
                isinstance(e.payload.get("country"), str)
                and e.payload["country"]
                and e.payload["country"] not in entity_base.known_countries
                for e in events
            )
        )
        f["novelty.new_target"] = len(
            {
                e.target.entity_id
                for e in events
                if e.target is not None and e.target.entity_id not in entity_base.known_targets
            }
        )

    # ---- privilege
    f["privilege.privileged_ops"] = sum(1 for e in events if _is_privileged_op(e))
    f["privilege.role_changes"] = sum(1 for e in events if e.event_type == "privilege_change")
    f["privilege.tokens_issued"] = sum(1 for e in events if e.event_type == "token_issued")

    # ---- peer-relative
    f["peer.volume_zscore"] = 0.0
    f["peer.targets_zscore"] = 0.0
    if baseline is not None:
        stats = baseline.cohort_stats.get(_cohort(subject.entity_id, subject.entity_type, baseline.cohort_of))
        if stats:
            floor = config.peer_std_floor
            f["peer.volume_zscore"] = (f["volume.event_count"] - stats["volume_mean"]) / max(
                stats["volume_std"], floor
            )
            f["peer.targets_zscore"] = (f["diversity.distinct_targets"] - stats["targets_mean"]) / max(
                stats["targets_std"], floor
            )

    return _finalize(f)


def _finalize(raw: Mapping[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for name, kind in _FEATURE_SPEC:
        value = raw[name]
        if kind == "int":
            out[name] = int(value)
        else:
            out[name] = round(float(value), 6) + 0.0  # + 0.0 turns -0.0 into 0.0
    return out


def compute_features(
    events: Iterable[EnrichedEvent],
    baseline: Optional[Baseline] = None,
    config: FeatureConfig = FeatureConfig(),
) -> List[Dict[str, Any]]:
    """Feature Vectors (contract section 3) for every (entity, window) with events."""
    ordered = sorted(events, key=_order)
    groups, refs = _group(ordered, config)
    vectors: List[Dict[str, Any]] = []
    for key in sorted(groups, key=lambda k: (k[2], k[0], k[1])):
        tenant, eid, start = key
        window_events = groups[key]
        subject = refs[eid]
        vectors.append(
            {
                "schema_version": C.SCHEMA_VERSION,
                "feature_set_version": C.FEATURE_SET_VERSION,
                "tenant_id": tenant,
                "entity_id": eid,
                "entity_type": subject.entity_type,
                "window_start": iso_utc(datetime.fromtimestamp(start, tz=timezone.utc)),
                "window_end": iso_utc(
                    datetime.fromtimestamp(start + config.window_seconds, tz=timezone.utc)
                ),
                "window_seconds": config.window_seconds,
                "event_ids": [e.event_id for e in window_events],
                "features": _window_features(subject, window_events, baseline, config),
            }
        )
    return vectors


def extract(
    raw_events: Iterable[Mapping[str, Any]],
    baseline: Optional[Baseline] = None,
    config: FeatureConfig = FeatureConfig(),
    assets: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Raw canonical events -> ``{"vectors": [...], "report": {...}}`` in one call."""
    events, report = resolve_events(raw_events, assets)
    vectors = compute_features(events, baseline, config)
    report = dict(report, vectors=len(vectors))
    return {"vectors": vectors, "report": report}
