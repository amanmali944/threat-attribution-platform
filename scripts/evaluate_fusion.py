"""Phase 4 evaluation: fusion + calibration + alert-fatigue controls, split BY SCENARIO RUN.

    python -I scripts/evaluate_fusion.py <dumps dir> <results json> --scenarios russellmitchell fox [--variant asis]

<dumps dir> holds `<scenario>-<variant>.jsonl` files written by `evaluate_ait.py --dump-windows`:
every scored TEST window of a scenario (rules calibrated and Isolation Forest trained on that
scenario's own earlier days, so every detector output is out-of-sample for that scenario).

For each scenario S in --scenarios: fit the fusion model on the windows of all OTHER listed
scenarios (calibration = leave-one-scenario-out inside them), then score S once. Reported per
fold and pooled:
  * ranking (PR-AUC / ROC-AUC) of fusion vs each single detector and vs event count;
  * calibration of the confidence on S (ECE, Brier, reliability bins);
  * decisions alert / review / suppress; recall per attack class (incident, exfiltration) and
    per attack stage at "alert" and at "alert or review";
  * alerts per day: windows before fusion (rules any OR IF >= 0.999), fused windows, and Fused
    Alerts after folding repeats (30-minute suppression window).
The design (inputs, model, targets) is fixed in detection/fusion.py; it was set on the
development scenarios only and is not changed after a held-out fold is scored.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from sklearn.metrics import average_precision_score, roc_auc_score  # noqa: E402

from app.services.detection.fusion import (  # noqa: E402
    FusionModel,
    decision_counts,
    fuse_alerts,
    is_hostile,
    reliability,
    rules_first,
)
from app.services.detection.labeling import to_us  # noqa: E402

STAGES = ("entry", "discovery", "web_attack", "privilege")
CLASSES = ("incident", "exfiltration")
SUPPRESSION_SECONDS = 1800


def load(path: Path) -> List[Dict[str, Any]]:
    with open(path, "rt", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle]


def ranking(y, scores) -> Dict[str, Any]:
    if len(set(y)) < 2:
        return {"roc_auc": None, "average_precision": None, "positives": int(sum(y)), "n": len(y)}
    return {"roc_auc": round(float(roc_auc_score(y, scores)), 4),
            "average_precision": round(float(average_precision_score(y, scores)), 4),
            "positives": int(sum(y)), "n": len(y)}


def recall_by(windows, flags, key_values, key) -> Dict[str, Any]:
    out = {}
    for value in key_values:
        idx = [i for i, w in enumerate(windows) if key(w, value)]
        out[value] = {"windows": len(idx), "flagged": sum(1 for i in idx if flags[i]),
                      "detected": any(flags[i] for i in idx)} if idx else None
    return out


def test_days(windows) -> float:
    start = min(to_us(w["window_start"]) for w in windows)
    end = max(to_us(w["window_end"]) for w in windows)
    return max(1.0, round((end - start) / 86_400e6))   # test splits run whole UTC days


def fold(train: List[Dict[str, Any]], test: List[Dict[str, Any]], model_name: str) -> Dict[str, Any]:
    model = FusionModel(model=model_name).fit(train, [w["scenario"] for w in train])
    confidence = model.confidence(test)
    decisions = model.decide(confidence)
    y = [is_hostile(w) for w in test]
    days = test_days(test)
    rules_any = [bool(w["rules"]) for w in test]
    rules_high = [any(s in ("high", "critical") for s in w["rules"].values()) for w in test]
    iforest = [w["iforest_score"] if w["iforest_score"] is not None else 0.0 for w in test]
    before = [a or s >= 0.999 for a, s in zip(rules_any, iforest)]
    alert = [d == "alert" for d in decisions]
    alert_or_review = [d != "suppress" for d in decisions]
    pipeline = rules_first(test, decisions)                      # the pre-registered pipeline decision
    p_alert = [d == "alert" for d in pipeline]
    p_alert_or_review = [d != "suppress" for d in pipeline]
    fused = fuse_alerts(test, confidence, pipeline, suppression_seconds=SUPPRESSION_SECONDS)

    def op(flags):
        tp = sum(1 for f, t in zip(flags, y) if f and t)
        fp = sum(1 for f, t in zip(flags, y) if f and not t)
        return {"hostile_flagged": tp, "hostile_total": sum(y), "false_alarms": fp,
                "precision": round(tp / (tp + fp), 4) if tp + fp else None,
                "recall": round(tp / sum(y), 4) if sum(y) else None,
                "per_day": round((tp + fp) / days, 1), "false_alarms_per_day": round(fp / days, 1)}

    by_class = lambda flags: recall_by(test, flags, CLASSES, lambda w, c: w["label"] == c)       # noqa: E731
    by_stage = lambda flags: recall_by(test, flags, STAGES, lambda w, s: s in w.get("stages", []))  # noqa: E731
    fused_hostile = sum(1 for a in fused if a["decision"] == "alert")
    return {
        "train_scenarios": sorted({w["scenario"] for w in train}),
        "test_windows": len(test), "test_hostile_windows": sum(y), "test_days": days,
        "model": model.metadata(),
        "ranking": {
            "fusion": ranking(y, confidence),
            "iforest": ranking(y, iforest),
            "rules_any": ranking(y, [float(f) for f in rules_any]),
            "rules_high": ranking(y, [float(f) for f in rules_high]),
            "event_count": ranking(y, [w["features"]["volume.event_count"] for w in test]),
        },
        "calibration_on_test": reliability(y, confidence),
        "decisions": {"fusion": decision_counts(decisions), "pipeline_rules_first": decision_counts(pipeline)},
        "operating_points": {
            "before_fusion: rules any | iforest>=0.999": op(before),
            "rules any": op(rules_any),
            "rules high": op(rules_high),
            "fusion alert": op(alert),
            "fusion alert|review": op(alert_or_review),
            "pipeline alert": op(p_alert),
            "pipeline alert|review": op(p_alert_or_review),
        },
        "recall_by_class": {"before_fusion": by_class(before), "fusion_alert": by_class(alert),
                            "fusion_alert_or_review": by_class(alert_or_review),
                            "pipeline_alert": by_class(p_alert), "pipeline_alert_or_review": by_class(p_alert_or_review)},
        "recall_by_stage": {"before_fusion": by_stage(before), "fusion_alert": by_stage(alert),
                            "fusion_alert_or_review": by_stage(alert_or_review),
                            "pipeline_alert": by_stage(p_alert), "pipeline_alert_or_review": by_stage(p_alert_or_review)},
        "alert_volume_per_day": {
            "windows_flagged_before_fusion": round(sum(before) / days, 1),
            "pipeline_windows_alert_or_review": round(sum(p_alert_or_review) / days, 1),
            "pipeline_fused_alerts": round(len(fused) / days, 1),
            "pipeline_fused_alerts_decision_alert": round(fused_hostile / days, 1),
            "suppressed_duplicates": sum(a["suppressed_duplicates"] for a in fused),
        },
        "fused_alerts_by_decision_and_label": fused_labels(fused, test),
    }


def fused_labels(fused, windows) -> Dict[str, int]:
    """decision:label counts; a Fused Alert is hostile if any window it folds is hostile."""
    by_entity: Dict[str, List[Dict[str, Any]]] = {}
    for w in windows:
        by_entity.setdefault(w["entity_id"], []).append(w)
    counts: Counter = Counter()
    for alert in fused:
        labels = {w["label"] for w in by_entity.get(alert["entity_id"], [])
                  if alert["window_start"] <= w["window_start"] < alert["window_end"]}
        label = next((c for c in CLASSES if c in labels), "background")
        counts[f"{alert['decision']}:{label}"] += 1
    return dict(sorted(counts.items()))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("dumps_dir")
    parser.add_argument("results")
    parser.add_argument("--scenarios", nargs="+", required=True)
    parser.add_argument("--variant", default="asis", choices=["asis", "clean"])
    parser.add_argument("--model", default="logreg", choices=["logreg", "hgb"])
    args = parser.parse_args()
    started = time.perf_counter()

    data = {s: load(Path(args.dumps_dir) / f"{s}-{args.variant}.jsonl") for s in args.scenarios}
    for s, windows in data.items():
        versions = {(w["ruleset"], w["iforest_version"], w["feature_set_version"]) for w in windows}
        if len(versions) != 1:
            raise SystemExit(f"{s}: mixed detector versions {versions}")
    folds = {}
    for s in args.scenarios:
        train = [w for other in args.scenarios if other != s for w in data[other]]
        folds[s] = fold(train, data[s], args.model)
        r = folds[s]
        print(f"{s:16s} fusion PR-AUC {r['ranking']['fusion']['average_precision']}  IF {r['ranking']['iforest']['average_precision']}"
              f"  alert {r['operating_points']['fusion alert']['hostile_flagged']}/{r['test_hostile_windows']}"
              f" fa/day {r['operating_points']['fusion alert']['false_alarms_per_day']}"
              f"  ECE {r['calibration_on_test']['ece']}", flush=True)

    results = {
        "evaluated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "protocol": "leave-one-scenario-out over the listed scenarios; fusion fit on the others, test scored once",
        "variant": args.variant, "model": args.model, "scenarios": args.scenarios,
        "suppression_seconds": SUPPRESSION_SECONDS, "folds": folds,
        "seconds": round(time.perf_counter() - started, 1),
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.results)), exist_ok=True)
    Path(args.results).write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
