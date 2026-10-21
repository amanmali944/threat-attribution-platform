"""Phase 1b: Org Y auth events -> labelled feature windows, split by time.

    python -I scripts/build_org_y_windows.py <derived auth dir> <spec json> <out dir>

Reads `events.jsonl` + `labels.jsonl` written by `scripts/adapters/syslog_auth.py` and a spec
(`data/specs/org_y_incident.json`). Writes, inside <out dir>:
    train.jsonl / validation.jsonl / test.jsonl   feature vectors + "split" + "label"
    baseline.json                                  the fitted baseline (entity IDs are hashes)
    dataset_report.json                            counts, cross-checks, assumptions

Processing is one UTC day at a time (300 s windows divide a day exactly, so no window crosses
a day boundary), which keeps memory low. Pass 1 learns the routine sudo commands from the
baseline + train period; pass 2 fits the baseline on the baseline day(s) and labels windows.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services.detection.features import (  # noqa: E402
    Baseline,
    FeatureConfig,
    compute_features,
    fit_baseline,
    update_history,
)
from app.services.detection.labeling import (  # noqa: E402
    Interval,
    classify_events,
    is_notable,
    label_windows,
    load_event_labels,
    load_spec,
    routine_commands,
    split_of,
    to_us,
)
from app.services.detection.resolve import resolve_events  # noqa: E402

SCORED_SPLITS = ("train", "validation", "test")


def iter_days(events_path: str) -> Iterator[Tuple[str, List[Dict[str, Any]]]]:
    """Yield (YYYY-MM-DD, raw events) per UTC day. The file must be in time order by day."""
    day, bucket, seen = None, [], set()
    with open(events_path, "rt", encoding="utf-8") as handle:
        for line in handle:
            event = json.loads(line)
            event_day = event["observed_at"][:10]
            if event_day != day:
                if day is not None:
                    yield day, bucket
                if event_day in seen:
                    raise ValueError(f"events are not grouped by day: {event_day} appears twice")
                seen.add(event_day)
                day, bucket = event_day, []
            bucket.append(event)
    if day is not None:
        yield day, bucket


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("derived_dir", help="output dir of syslog_auth.py (events.jsonl, labels.jsonl)")
    parser.add_argument("spec", help="dataset spec json")
    parser.add_argument("out_dir")
    args = parser.parse_args()

    started = time.perf_counter()
    spec = load_spec(args.spec)
    config = FeatureConfig(window_seconds=spec.window_seconds)
    events_path = os.path.join(args.derived_dir, "events.jsonl")
    sidecar = load_event_labels(os.path.join(args.derived_dir, "labels.jsonl"))
    post_compromise = {eid for eid, labels in sidecar.items() if any(not l.startswith("bruteforce") for l in labels)}
    os.makedirs(args.out_dir, exist_ok=True)

    # ---- pass 1: routine sudo commands from the pre-incident period (baseline + train)
    routine_period = Interval(spec.splits["baseline"].start_us, spec.splits["train"].end_us)
    sudo_events = []
    for _day, raw in iter_days(events_path):
        events, _ = resolve_events(e for e in raw if e["event_type"] == "process_execution")
        sudo_events.extend(e for e in events if routine_period.contains(e.ts_us))
    routine = routine_commands(sudo_events, routine_period, spec.routine_command_min_hours)
    del sudo_events

    # ---- pass 2: baseline, features, labels, splits
    baseline = None
    baseline_events: List[Any] = []
    windows = Counter()                 # (split, label, entity_type) -> n
    event_classes = Counter()           # class -> n
    post_in_incident = post_seen = 0
    days_report = []
    outputs = {name: open(os.path.join(args.out_dir, f"{name}.jsonl"), "w", encoding="utf-8", newline="\n")
               for name in SCORED_SPLITS}
    try:
        for day, raw in iter_days(events_path):
            events, report = resolve_events(raw)
            day_start = to_us(f"{day}T00:00:00Z")
            if spec.splits["baseline"].contains(day_start):
                baseline_events.extend(events)
                days_report.append({"day": day, "events": len(events), "role": "baseline (fit only)"})
                continue
            if baseline is None:
                baseline = fit_baseline(baseline_events, config)
                fitted = Baseline.from_dict(baseline.to_dict())   # saved as fitted; the live copy rolls forward
                baseline_events = []

            classes = classify_events(events, spec, routine)
            for cls in classes.values():
                event_classes[cls] += 1
            for event in events:
                if event.event_id in post_compromise:
                    post_seen += 1
                    post_in_incident += classes.get(event.event_id) == "incident"

            vectors = compute_features(events, baseline, config)
            update_history(baseline, events)                      # tomorrow's history includes today
            labels = label_windows(vectors, classes)
            per_day = Counter()
            for vector, label in zip(vectors, labels):
                split = split_of(vector["window_start"], vector["window_end"], spec) or "outside"
                windows[(split, label, vector["entity_type"])] += 1
                per_day[split] += 1
                if split in outputs:
                    record = dict(vector, split=split, label=label)
                    outputs[split].write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
            days_report.append({"day": day, "events": len(events), "windows": dict(per_day),
                                "skipped_events": len(report["skipped_events"])})
    finally:
        for handle in outputs.values():
            handle.close()

    with open(os.path.join(args.out_dir, "baseline.json"), "w", encoding="utf-8", newline="\n") as handle:
        json.dump(fitted.to_dict(), handle, sort_keys=True)

    by_split: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    by_split_type: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for (split, label, etype), n in windows.items():
        by_split[split][label] += n
        by_split_type[f"{split}:{label}"][etype] += n

    report = {
        "dataset": spec.dataset,
        "spec_file": os.path.basename(args.spec),
        "window_seconds": spec.window_seconds,
        "provenance": dict(spec.provenance),
        "routine_commands": {"count": len(routine), "min_hours": spec.routine_command_min_hours,
                             "examples": sorted(routine)[:10]},
        "baseline": {"events": fitted.n_events, "entities": len(fitted.entities),
                     "cohort_stats": fitted.cohort_stats,
                     "history_at_end": {"events": baseline.n_events, "entities": len(baseline.entities)},
                     "history": "rolls forward one UTC day at a time (fs-1.2.0)"},
        "notable_events": dict(event_classes),
        "post_compromise_labelled_events": {"seen_after_baseline": post_seen, "classified_incident": post_in_incident},
        "windows_by_split": {k: dict(v) for k, v in sorted(by_split.items())},
        "windows_by_split_label_entity_type": {k: dict(v) for k, v in sorted(by_split_type.items())},
        "days": days_report,
        "seconds": round(time.perf_counter() - started, 1),
    }
    with open(os.path.join(args.out_dir, "dataset_report.json"), "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({k: report[k] for k in ("routine_commands", "notable_events", "post_compromise_labelled_events",
                                              "windows_by_split", "windows_by_split_label_entity_type", "days", "seconds")},
                     indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
