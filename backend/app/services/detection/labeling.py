"""Window labels, incident definition and time-ordered splits (Phase 1b).

Labels are kept apart from events and features: this module takes feature vectors and a
dataset spec and returns a label per window. Nothing here is visible to a detector.

Window labels
    incident    the window contains an event of the documented incident
    unknown     the window contains a *notable* event (a successful login, or a sudo command
                that is not routine) outside the documented incident - we cannot say whether
                it is benign or malicious, so it is excluded from scoring
    background  everything else (e.g. failed-login noise, routine cron-driven sudo)

An event is *notable* if it is a successful login or a sudo command whose (digit-normalised)
text did not recur in at least `routine_command_min_hours` distinct hours of the pre-incident
period. "Routine" is therefore learned from earlier data only.

An event is part of the *incident* if it is notable and falls inside the incident interval,
which comes from the dataset's own documentation (see the spec file's provenance).

Splits are time-ordered, half-open intervals aligned to the window size, so no window can
straddle a boundary, and the incident must lie wholly in the test split.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from app.services.detection.resolve import EnrichedEvent, parse_timestamp

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_US_PER_HOUR = 3_600_000_000
SPLIT_ORDER = ("baseline", "train", "validation", "gap", "test")


def to_us(value: Any) -> int:
    """ISO timestamp or datetime -> exact microseconds since the Unix epoch."""
    return (parse_timestamp(value) - _EPOCH) // timedelta(microseconds=1)


@dataclass(frozen=True)
class Interval:
    """Half-open [start_us, end_us)."""

    start_us: int
    end_us: int

    def contains(self, ts_us: int) -> bool:
        return self.start_us <= ts_us < self.end_us

    def overlaps(self, other: "Interval") -> bool:
        return self.start_us < other.end_us and other.start_us < self.end_us


@dataclass(frozen=True)
class DatasetSpec:
    dataset: str
    window_seconds: int
    incident: Interval
    splits: Dict[str, Interval]
    routine_command_min_hours: int
    provenance: Mapping[str, Any]


def load_spec(path: str) -> DatasetSpec:
    with open(path, "rt", encoding="utf-8") as handle:
        raw = json.load(handle)
    window_us = int(raw["window_seconds"]) * 1_000_000
    incident = Interval(to_us(raw["incident"]["start"]), to_us(raw["incident"]["end"]))
    if incident.start_us >= incident.end_us:
        raise ValueError("incident start must be before its end")

    splits: Dict[str, Interval] = {}
    previous_end: Optional[int] = None
    for name in SPLIT_ORDER:
        if name not in raw["splits"]:
            raise ValueError(f"missing split: {name}")
        start, end = (to_us(x) for x in raw["splits"][name])
        if start >= end:
            raise ValueError(f"split {name}: start must be before end")
        if start % window_us or end % window_us:
            raise ValueError(f"split {name}: boundaries must be multiples of the window size")
        if previous_end is not None and start < previous_end:
            raise ValueError(f"split {name} overlaps the previous split")
        splits[name] = Interval(start, end)
        previous_end = end

    for name in ("baseline", "train", "validation"):
        if incident.overlaps(splits[name]):
            raise ValueError(f"incident overlaps the {name} split (label leakage)")
    if not (splits["test"].start_us <= incident.start_us and incident.end_us <= splits["test"].end_us):
        raise ValueError("incident must lie wholly inside the test split")

    return DatasetSpec(
        dataset=raw["dataset"],
        window_seconds=int(raw["window_seconds"]),
        incident=incident,
        splits=splits,
        routine_command_min_hours=int(raw["routine_command_min_hours"]),
        provenance=raw.get("provenance", {}),
    )


def split_of(window_start: Any, window_end: Any, spec: DatasetSpec) -> Optional[str]:
    """Split a window lies wholly inside, or None if it lies in none (e.g. after the data ended)."""
    start, end = to_us(window_start), to_us(window_end) - 1
    for name, interval in spec.splits.items():
        if interval.contains(start) and interval.contains(end):
            return name
    return None


# --------------------------------------------------------------------------- events


def is_sudo(event: EnrichedEvent) -> bool:
    return event.event_type == "process_execution" and event.payload.get("process_name") == "sudo"


def normalize_command(command: str) -> str:
    """Collapse digit runs so temp-file numbers do not make every command unique."""
    return re.sub(r"\d+", "N", str(command).strip())


def routine_commands(events: Iterable[EnrichedEvent], period: Interval, min_hours: int) -> FrozenSet[str]:
    """Sudo commands seen in at least ``min_hours`` distinct hours of ``period`` (cron-like)."""
    hours: Dict[str, Set[int]] = {}
    for event in events:
        if is_sudo(event) and period.contains(event.ts_us):
            key = normalize_command(event.payload.get("command_line", ""))
            hours.setdefault(key, set()).add(event.ts_us // _US_PER_HOUR)
    return frozenset(cmd for cmd, seen in hours.items() if len(seen) >= min_hours)


def is_notable(event: EnrichedEvent, routine: FrozenSet[str]) -> bool:
    if event.event_type == "user_login" and event.outcome == "success":
        return True
    if is_sudo(event):
        return normalize_command(event.payload.get("command_line", "")) not in routine
    return False


def classify_events(
    events: Iterable[EnrichedEvent], spec: DatasetSpec, routine: FrozenSet[str]
) -> Dict[str, str]:
    """event_id -> ``incident`` | ``unknown`` for notable events; ordinary events are absent."""
    classes: Dict[str, str] = {}
    for event in events:
        if is_notable(event, routine):
            classes[event.event_id] = "incident" if spec.incident.contains(event.ts_us) else "unknown"
    return classes


def label_windows(vectors: Sequence[Mapping[str, Any]], event_class: Mapping[str, str]) -> List[str]:
    """One label per feature vector: ``incident`` > ``unknown`` > ``background``."""
    labels = []
    for vector in vectors:
        seen = {event_class.get(event_id) for event_id in vector["event_ids"]}
        if "incident" in seen:
            labels.append("incident")
        elif "unknown" in seen:
            labels.append("unknown")
        else:
            labels.append("background")
    return labels


def load_event_labels(path: str) -> Dict[str, List[str]]:
    """Read a ``labels.jsonl`` sidecar -> event_id -> label names (moderate rules)."""
    labels: Dict[str, List[str]] = {}
    with open(path, "rt", encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            labels[record["event_id"]] = [hit["label"] for hit in record["labels"]]
    return labels
