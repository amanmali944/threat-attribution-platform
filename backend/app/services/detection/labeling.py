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

Event-label datasets (AIT-LDS)
    When the dataset ships per-event ground truth, the spec lists ``label_classes`` (class ->
    label names, in precedence order, ``incident`` first) and ``ignored_labels``. An event's
    class is the first class whose names it carries; the notable/routine heuristic is not used.
    Classes other than ``incident`` (e.g. ``exfiltration``) may overlap the training splits -
    that is a property of the data, recorded in the spec's provenance, not leakage of the
    incident under test.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
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
    routine_command_min_hours: Optional[int]
    provenance: Mapping[str, Any]
    label_classes: Mapping[str, FrozenSet[str]] = field(default_factory=dict)
    ignored_labels: FrozenSet[str] = frozenset()

    @property
    def uses_event_labels(self) -> bool:
        return bool(self.label_classes)


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

    label_classes: Dict[str, FrozenSet[str]] = {}
    for name, labels in raw.get("label_classes", {}).items():
        names = frozenset(labels)
        if not names:
            raise ValueError(f"label class {name} lists no labels")
        for other, other_names in label_classes.items():
            if names & other_names:
                raise ValueError(f"label classes {other} and {name} share labels: {sorted(names & other_names)}")
        label_classes[name] = names
    ignored = frozenset(raw.get("ignored_labels", []))
    if label_classes:
        if next(iter(label_classes)) != "incident":
            raise ValueError("label_classes must start with 'incident' (it has the highest precedence)")
        if "unknown" in label_classes or "background" in label_classes:
            raise ValueError("'unknown' and 'background' are window labels, not label classes")
        mapped = frozenset().union(*label_classes.values())
        if ignored & mapped:
            raise ValueError(f"labels both ignored and mapped: {sorted(ignored & mapped)}")
    elif "routine_command_min_hours" not in raw:
        raise ValueError("spec needs routine_command_min_hours or label_classes")

    min_hours = raw.get("routine_command_min_hours")
    return DatasetSpec(
        dataset=raw["dataset"],
        window_seconds=int(raw["window_seconds"]),
        incident=incident,
        splits=splits,
        routine_command_min_hours=int(min_hours) if min_hours is not None else None,
        provenance=raw.get("provenance", {}),
        label_classes=label_classes,
        ignored_labels=ignored,
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


def classify_by_event_labels(
    events: Iterable[EnrichedEvent], event_labels: Mapping[str, Sequence[str]], spec: DatasetSpec
) -> Tuple[Dict[str, str], Counter]:
    """event_id -> class from per-event ground truth; also returns labels mapped to no class.

    Labels in ``spec.ignored_labels`` are dropped. Any other label that maps to no class is
    counted and returned so the caller can refuse to continue - an unmapped label is a spec
    error, not something to skip silently.
    """
    if not spec.uses_event_labels:
        raise ValueError("spec has no label_classes")
    classes: Dict[str, str] = {}
    unmapped: Counter = Counter()
    mapped = frozenset().union(*spec.label_classes.values())
    for event in events:
        names = set(event_labels.get(event.event_id, ())) - spec.ignored_labels
        if not names:
            continue
        for cls, members in spec.label_classes.items():  # precedence order
            if names & members:
                classes[event.event_id] = cls
                break
        for name in names - mapped:
            unmapped[name] += 1
    return classes, unmapped


def label_windows(
    vectors: Sequence[Mapping[str, Any]],
    event_class: Mapping[str, str],
    precedence: Sequence[str] = ("incident", "unknown"),
) -> List[str]:
    """One label per feature vector: the first class in ``precedence`` it contains, else ``background``."""
    labels = []
    for vector in vectors:
        seen = {event_class.get(event_id) for event_id in vector["event_ids"]}
        labels.append(next((cls for cls in precedence if cls in seen), "background"))
    return labels


def load_event_labels(path: str) -> Dict[str, List[str]]:
    """Read a ``labels.jsonl`` sidecar -> event_id -> label names (moderate rules)."""
    labels: Dict[str, List[str]] = {}
    with open(path, "rt", encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            labels[record["event_id"]] = [hit["label"] for hit in record["labels"]]
    return labels
