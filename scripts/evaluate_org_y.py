"""Phase 3 evaluation on Org Y: rules + Isolation Forest, zero-shot, ONE incident.

    python -I scripts/evaluate_org_y.py <windows dir> <spec json> <results json> [--model-dir DIR]

Protocol (decided before looking at any detector output on the test split):
  * rule thresholds are calibrated on BACKGROUND windows of train + validation only;
  * the Isolation Forest is trained on train background and its scores are ranked (ECDF)
    against train + validation background;
  * the test split is scored once; `unknown` windows are excluded from precision/recall
    (alerts on them are reported separately);
  * metrics: ROC-AUC and average precision (PR-AUC) per detector, precision / recall /
    alerts-per-day at fixed operating points, incident-level detection and latency.
Limits that travel with every number: one incident (n = 1), the incident's shape was seen
while defining labels (optimistic), UTC assumed for the incident window.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import joblib  # noqa: E402
from sklearn.metrics import average_precision_score, roc_auc_score  # noqa: E402

from app.services.detection.anomaly import IsolationForestDetector  # noqa: E402
from app.services.detection.labeling import load_spec, to_us  # noqa: E402
from app.services.detection.rules import RuleEngine  # noqa: E402

OPERATING_POINTS = (0.99, 0.999)


def load(path: str) -> List[Dict[str, Any]]:
    with open(path, "rt", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle]


def ranking_metrics(labels: List[int], scores: List[float]) -> Dict[str, Optional[float]]:
    if not labels or len(set(labels)) < 2:
        return {"roc_auc": None, "average_precision": None, "positives": sum(labels), "n": len(labels)}
    return {"roc_auc": round(roc_auc_score(labels, scores), 4),
            "average_precision": round(average_precision_score(labels, scores), 4),
            "positives": sum(labels), "n": len(labels)}


def operating_point(records, flags, days) -> Dict[str, Any]:
    tp = sum(1 for r, f in zip(records, flags) if f and r["label"] == "incident")
    fp = sum(1 for r, f in zip(records, flags) if f and r["label"] == "background")
    on_unknown = sum(1 for r, f in zip(records, flags) if f and r["label"] == "unknown")
    positives = sum(1 for r in records if r["label"] == "incident")
    first = sorted(r["window_start"] for r, f in zip(records, flags) if f and r["label"] == "incident")
    return {
        "incident_windows_flagged": tp, "incident_windows_total": positives,
        "recall": round(tp / positives, 4) if positives else None,
        "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "false_alarm_windows": fp, "alerts_on_unknown_windows": on_unknown,
        "alerts_per_day": round((tp + fp + on_unknown) / days, 1),
        "false_alarms_per_day": round(fp / days, 1),
        "incident_detected": tp > 0,
        "first_flagged_incident_window": first[0] if first else None,
    }


def minutes_between(a: str, b: str) -> float:
    return round((to_us(b) - to_us(a)) / 60e6, 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("windows_dir")
    parser.add_argument("spec")
    parser.add_argument("results")
    parser.add_argument("--model-dir", default=None, help="where to save the fitted models (git-ignored)")
    args = parser.parse_args()
    started = time.perf_counter()

    spec = load_spec(args.spec)
    train = load(os.path.join(args.windows_dir, "train.jsonl"))
    validation = load(os.path.join(args.windows_dir, "validation.jsonl"))
    test = load(os.path.join(args.windows_dir, "test.jsonl"))
    for records in (train, validation, test):
        records.sort(key=lambda r: (r["window_start"], r["entity_type"], r["entity_id"]))
    bg_trval = [r for r in train + validation if r["label"] == "background"]
    bg_train = [r for r in train if r["label"] == "background"]
    assert not any(r["label"] == "incident" for r in train + validation), "incident outside test"

    last_end = max(r["window_end"] for r in test)
    days = (to_us(last_end) - spec.splits["test"].start_us) / 86_400e6
    scored = [r for r in test if r["label"] != "unknown"]
    y = [1 if r["label"] == "incident" else 0 for r in scored]
    first_incident_window = min(r["window_start"] for r in test if r["label"] == "incident")

    # ---------------------------------------------------------------- rules
    engine = RuleEngine().calibrate(bg_trval)
    per_rule = defaultdict(Counter)
    validation_fires = Counter()
    test_flags_any, test_flags_high = [], []
    for record in validation:
        for alert in engine.evaluate(record):
            validation_fires[alert["rule_id"]] += 1
    for record in test:
        alerts = engine.evaluate(record)
        for alert in alerts:
            per_rule[alert["rule_id"]][record["label"]] += 1
        test_flags_any.append(bool(alerts))
        test_flags_high.append(any(a["severity"] in ("high", "critical") for a in alerts))
    rule_meta = {r.rule_id: (r.title, r.severity) for r in engine.rules}
    rules_table = {}
    for rule_id, (title, severity) in rule_meta.items():
        counts = per_rule.get(rule_id, Counter())
        rules_table[rule_id] = {
            "title": title, "severity": severity,
            "test_fires": {k: counts.get(k, 0) for k in ("incident", "background", "unknown")},
            "validation_fires": validation_fires.get(rule_id, 0),
        }

    # ---------------------------------------------------------------- isolation forest
    detector = IsolationForestDetector().fit(bg_train, reference_vectors=bg_trval)
    test_scores = detector.scores(test)
    no_model = sum(1 for s in test_scores if s is None)
    filled = [s if s is not None else 0.0 for s in test_scores]
    score_of = {id(r): s for r, s in zip(test, filled)}
    iforest_rank = ranking_metrics(y, [score_of[id(r)] for r in scored])
    iforest_by_type = {}
    for etype in sorted({r["entity_type"] for r in scored}):
        sub = [r for r in scored if r["entity_type"] == etype]
        iforest_by_type[etype] = ranking_metrics([1 if r["label"] == "incident" else 0 for r in sub],
                                                 [score_of[id(r)] for r in sub])
    iforest_ops = {str(t): operating_point(test, [s >= t for s in filled], days) for t in OPERATING_POINTS}
    top = sorted(zip(test, filled), key=lambda p: -p[1])[:10]
    top10 = [{"score": s, "label": r["label"], "entity_type": r["entity_type"], "window_start": r["window_start"],
              "most_unusual": [e["feature"] for e in detector.explain(r)] if r["entity_type"] in detector.models else []}
             for r, s in top]

    # ---------------------------------------------------------------- dumb baselines
    volume = [float(r["features"]["volume.event_count"]) for r in scored]
    baselines = {
        "random_scoring_expected_average_precision": round(sum(y) / len(y), 4),
        "event_count_only": ranking_metrics(y, volume),
    }

    # ---------------------------------------------------------------- incident-level summary
    rules_any_op = operating_point(test, test_flags_any, days)
    rules_high_op = operating_point(test, test_flags_high, days)
    combined = [a or (s >= 0.999) for a, s in zip(test_flags_high, filled)]
    combined_op = operating_point(test, combined, days)
    for op in [rules_any_op, rules_high_op, combined_op, *iforest_ops.values()]:
        op["latency_minutes_from_first_incident_window"] = (
            minutes_between(first_incident_window, op["first_flagged_incident_window"]) + spec.window_seconds / 60
            if op["first_flagged_incident_window"] else None)

    results = {
        "dataset": spec.dataset,
        "evaluated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "protocol": "zero-shot: calibrate/train on background of train+validation, score test once",
        "limits": [
            "ONE incident: every recall figure is a single observation, not an estimate",
            "incident shape was seen while defining labels and adding fs-1.1.0 login counts: optimistic",
            "incident window assumes the syslog clock is UTC",
            "unknown windows excluded; alerts on them reported separately",
            "Isolation Forest ECDF reference includes its own training windows (in-sample), so test false alarms run above the nominal 1% / 0.1%",
        ],
        "data": {
            "train_windows": len(train), "validation_windows": len(validation), "test_windows": len(test),
            "test_incident_windows": sum(y), "test_unknown_windows": len(test) - len(scored),
            "test_days": round(days, 3), "first_incident_window": first_incident_window,
        },
        "rules": {"ruleset": engine.to_dict()["ruleset_version"], "thresholds": engine.thresholds,
                  "calibration": engine.calibration, "per_rule": rules_table,
                  "any_rule": rules_any_op, "high_severity_rules": rules_high_op},
        "isolation_forest": {"metadata": detector.metadata(), "test_windows_without_model": no_model,
                             "ranking": iforest_rank, "ranking_by_entity_type": iforest_by_type,
                             "operating_points": iforest_ops, "top10_test_windows": top10},
        "high_rules_or_iforest_0999": combined_op,
        "baselines": baselines,
        "seconds": round(time.perf_counter() - started, 1),
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.results)), exist_ok=True)
    with open(args.results, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(results, handle, indent=2, sort_keys=True)
        handle.write("\n")
    if args.model_dir:
        os.makedirs(args.model_dir, exist_ok=True)
        joblib.dump(detector, os.path.join(args.model_dir, "iforest-1.0.0.joblib"))
        with open(os.path.join(args.model_dir, "rules-1.0.0.json"), "w", encoding="utf-8") as handle:
            json.dump(engine.to_dict(), handle, indent=2, sort_keys=True)
    print(json.dumps(results, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
