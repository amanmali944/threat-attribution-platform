"""Phase 1b for AIT-LDS: converted multi-source events -> labelled feature windows, split by time.

    python -I scripts/build_ait_windows.py <derived scenario dir> <spec json> <out dir> [--clean-baseline]

Reads every source directory under <derived scenario dir> written by
`scripts/convert_ait_scenario.py` (each holds events.jsonl + labels.jsonl), merges them into one
time-ordered stream - windows are cross-layer, so an IP's web requests and DNS queries share a
window - and labels windows from the dataset's own per-event ground truth (spec `label_classes`).

Writes, inside <out dir>:
    train.jsonl / validation.jsonl / test.jsonl   feature vectors + "split" + "label"
    baseline.json                                  the fitted baseline (entity IDs are hashes)
    dataset_report.json                            counts, cross-checks, assumptions

`--clean-baseline` removes exfiltration-class events from the baseline fit (uses labels; the
report records it). Window labels: incident > exfiltration > background.

Cross-checks (the build stops if one fails):
  * every label maps to a class or is explicitly ignored;
  * every incident-class event lies inside the spec's incident interval;
  * labelled-event totals equal the sum over sources' labels.jsonl;
  * every incident / exfiltration event after the baseline lands in a window with that label.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services.detection.features import FeatureConfig, compute_features, fit_baseline  # noqa: E402
from app.services.detection.labeling import (  # noqa: E402
    classify_by_event_labels,
    label_windows,
    load_event_labels,
    load_spec,
    split_of,
    to_us,
)
from app.services.detection.resolve import resolve_events  # noqa: E402

SCORED_SPLITS = ("train", "validation", "test")


def load_sources(derived_dir: str) -> Tuple[List[Dict[str, Any]], Dict[str, List[str]], Dict[str, Dict[str, int]]]:
    events: List[Dict[str, Any]] = []
    labels: Dict[str, List[str]] = {}
    per_source: Dict[str, Dict[str, int]] = {}
    for name in sorted(os.listdir(derived_dir)):
        source = os.path.join(derived_dir, name)
        if not os.path.isfile(os.path.join(source, "events.jsonl")):
            continue
        with open(os.path.join(source, "events.jsonl"), "rt", encoding="utf-8") as handle:
            source_events = [json.loads(line) for line in handle]
        source_labels = load_event_labels(os.path.join(source, "labels.jsonl"))
        overlap = labels.keys() & source_labels.keys()
        if overlap:
            raise ValueError(f"event ids repeated across sources: {sorted(overlap)[:3]}")
        events.extend(source_events)
        labels.update(source_labels)
        per_source[name] = {"events": len(source_events), "labelled": len(source_labels)}
    ids = [e["event_id"] for e in events]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate event ids across sources")
    events.sort(key=lambda e: (e["observed_at"], e["event_id"]))
    return events, labels, per_source


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("derived_dir")
    parser.add_argument("spec")
    parser.add_argument("out_dir")
    parser.add_argument("--clean-baseline", action="store_true",
                        help="drop exfiltration-class events from the baseline fit (uses labels)")
    args = parser.parse_args()

    started = time.perf_counter()
    spec = load_spec(args.spec)
    if not spec.uses_event_labels:
        raise SystemExit("spec has no label_classes; use build_org_y_windows.py for heuristic labels")
    config = FeatureConfig(window_seconds=spec.window_seconds)
    precedence = tuple(spec.label_classes)
    raw_events, event_labels, per_source = load_sources(args.derived_dir)

    events, resolve_report = resolve_events(raw_events)
    if resolve_report["skipped_events"]:
        raise SystemExit(f"{len(resolve_report['skipped_events'])} events failed resolution")
    classes, unmapped = classify_by_event_labels(events, event_labels, spec)
    if unmapped:
        raise SystemExit(f"labels mapped to no class (fix the spec): {dict(unmapped)}")

    labelled_total = sum(s["labelled"] for s in per_source.values())
    ignored_only = sum(1 for eid, names in event_labels.items() if not set(names) - spec.ignored_labels)
    if len(classes) + ignored_only != labelled_total:
        raise SystemExit(f"classified {len(classes)} + ignored-only {ignored_only} != labelled {labelled_total}")

    by_id = {e.event_id: e for e in events}
    outside = [eid for eid, cls in classes.items() if cls == "incident" and not spec.incident.contains(by_id[eid].ts_us)]
    if outside:
        raise SystemExit(f"{len(outside)} incident events outside the spec interval, e.g. {outside[:3]}")

    class_span: Dict[str, List[str]] = {}
    class_by_split: Dict[str, Counter] = defaultdict(Counter)
    for eid, cls in classes.items():
        moment = by_id[eid].ts_us
        span = class_span.setdefault(cls, [moment, moment])
        span[0], span[1] = min(span[0], moment), max(span[1], moment)
        split = next((n for n, iv in spec.splits.items() if iv.contains(moment)), "outside")
        class_by_split[cls][split] += 1

    # ---- baseline
    baseline_iv = spec.splits["baseline"]
    baseline_events = [e for e in events if baseline_iv.contains(e.ts_us)]
    dropped_from_baseline = 0
    if args.clean_baseline:
        kept = [e for e in baseline_events if classes.get(e.event_id) != "exfiltration"]
        dropped_from_baseline = len(baseline_events) - len(kept)
        baseline_events = kept
    baseline = fit_baseline(baseline_events, config)

    # ---- windows, one UTC day at a time (300 s windows divide a day exactly)
    by_day: Dict[str, List[Any]] = defaultdict(list)
    for event in events:
        if not baseline_iv.contains(event.ts_us):
            by_day[_iso(event.ts_us)[:10]].append(event)

    windows = Counter()
    covered: Dict[str, set] = {cls: set() for cls in precedence}
    days_report = []
    os.makedirs(args.out_dir, exist_ok=True)
    outputs = {name: open(os.path.join(args.out_dir, f"{name}.jsonl"), "w", encoding="utf-8", newline="\n")
               for name in SCORED_SPLITS}
    try:
        for day in sorted(by_day):
            vectors = compute_features(by_day[day], baseline, config)
            labels = label_windows(vectors, classes, precedence)
            per_day = Counter()
            for vector, label in zip(vectors, labels):
                split = split_of(vector["window_start"], vector["window_end"], spec) or "outside"
                windows[(split, label, vector["entity_type"])] += 1
                per_day[f"{split}:{label}"] += 1
                if label in covered:
                    covered[label].update(eid for eid in vector["event_ids"] if classes.get(eid) == label)
                if split in outputs:
                    record = dict(vector, split=split, label=label)
                    outputs[split].write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
            days_report.append({"day": day, "events": len(by_day[day]), "windows": dict(sorted(per_day.items()))})
    finally:
        for handle in outputs.values():
            handle.close()

    coverage = {}
    for cls in precedence:
        expected = {eid for eid, c in classes.items() if c == cls and not baseline_iv.contains(by_id[eid].ts_us)}
        coverage[cls] = {"events_after_baseline": len(expected), "in_a_window_with_that_label": len(covered[cls] & expected)}
        if cls == "incident" and covered[cls] & expected != expected:
            raise SystemExit(f"{len(expected - covered[cls])} incident events not in an incident window")

    with open(os.path.join(args.out_dir, "baseline.json"), "w", encoding="utf-8", newline="\n") as handle:
        json.dump(baseline.to_dict(), handle, sort_keys=True)

    by_split: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    by_split_type: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for (split, label, etype), n in windows.items():
        by_split[split][label] += n
        by_split_type[f"{split}:{label}"][etype] += n

    report = {
        "dataset": spec.dataset,
        "spec_file": os.path.basename(args.spec),
        "variant": "clean-baseline" if args.clean_baseline else "as-is",
        "window_seconds": spec.window_seconds,
        "provenance": dict(spec.provenance),
        "sources": per_source,
        "events": len(events),
        "labelled_events": labelled_total,
        "events_by_class": dict(Counter(classes.values())),
        "events_by_class_and_split": {k: dict(v) for k, v in sorted(class_by_split.items())},
        "class_time_span": {k: [_iso(a), _iso(b)] for k, (a, b) in sorted(class_span.items())},
        "baseline": {"events": baseline.n_events, "entities": len(baseline.entities),
                     "exfiltration_events_removed": dropped_from_baseline, "cohort_stats": baseline.cohort_stats},
        "window_label_coverage": coverage,
        "windows_by_split": {k: dict(v) for k, v in sorted(by_split.items())},
        "windows_by_split_label_entity_type": {k: dict(v) for k, v in sorted(by_split_type.items())},
        "days": days_report,
        "seconds": round(time.perf_counter() - started, 1),
    }
    with open(os.path.join(args.out_dir, "dataset_report.json"), "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({k: v for k, v in report.items() if k not in ("provenance", "days")}, indent=2, sort_keys=True))
    return 0


def _iso(ts_us: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts_us // 1_000_000))


if __name__ == "__main__":
    raise SystemExit(main())
