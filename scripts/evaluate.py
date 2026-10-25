"""Phase 8: one command, corpus -> detectors -> fusion -> incidents -> attribution -> risk -> results.

    python -I scripts/evaluate.py                      # run every stage, then write the artefact
    python -I scripts/evaluate.py --assemble-only      # only rebuild the artefact from stage outputs

Stages (each a script with its own tests; all leave-one-scenario-out or per-scenario zero-shot):
    1. evaluate_ait.py        per scenario: rules, Isolation Forest, scored test windows (dumps)
    2. summarize_ait.py       detector table over the 8 scenarios
    3. evaluate_fusion.py     fusion leave-one-scenario-out (+ the final calibration artefact)
    4. evaluate_correlation.py  pipeline Fused Alerts -> incidents
    5. evaluate_attribution.py  incidents -> entry point, path, reach vs ground truth
    6. evaluate_risk.py       incident risk ranking
Then ``data/evaluation/evaluation_results.json`` (contract section 9) is assembled. Every
figure in it is a HELD-OUT figure (the 6 scenarios not used to design anything) unless the key
says otherwise; accuracy is deliberately absent. Deterministic: fixed random_state (42) in every
model, sorted inputs, no sampling - the same corpus gives the same numbers.
"""
from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"
EVAL = REPO / "data" / "evaluation"
CORPUS = REPO / "data" / "external" / "ait" / "corpus"
SCENARIOS = ("russellmitchell", "fox", "harrison", "santos", "shaw", "wardbeck", "wheeler", "wilson")
HELD_OUT = ("harrison", "santos", "shaw", "wardbeck", "wheeler", "wilson")
PIPELINE_VERSION = "pipeline-1.0.0"
COMPONENTS = {"features": "fs-1.2.0", "rules": "rules-1.2.0", "anomaly": "iforest-1.1.0", "fusion": "fusion-1.0.0",
              "calibration": "cal-1.0.0", "correlation": "entity-time-graph-1.0.0", "attribution": "graph-attribution-1.1.0"}
SEED = 42


def run(args: List[str]) -> None:
    print("  $ " + " ".join(Path(a).name if a.endswith(".py") else a for a in args), flush=True)
    proc = subprocess.run([sys.executable, "-I", *args], capture_output=True, text=True)
    if proc.returncode:
        raise SystemExit(proc.stderr[-3000:])


def run_stages() -> None:
    for s in SCENARIOS:
        for v in ("asis", "clean"):
            run([str(SCRIPTS / "evaluate_ait.py"), str(CORPUS / "windows" / f"{s}-{v}"), str(REPO / "data" / "specs" / "ait" / f"{s}.json"),
                 str(CORPUS / "derived" / s), str(CORPUS / "eval" / f"{s}-{v}.json"), "--dump-windows", str(CORPUS / "dumps" / f"{s}-{v}.jsonl")])
    for v in ("asis", "clean"):
        run([str(SCRIPTS / "summarize_ait.py"), str(CORPUS / "eval"), str(EVAL / f"phase3_ait_corpus_{v}.json"), "--variant", v])
    run([str(SCRIPTS / "evaluate_fusion.py"), str(CORPUS / "dumps"), str(EVAL / "phase4_fusion_loso_logreg.json"), "--scenarios",
         *SCENARIOS, "--variant", "asis", "--model", "logreg", "--final-model", str(EVAL / "calibration.json")])
    run([str(SCRIPTS / "evaluate_fusion.py"), str(CORPUS / "dumps"), str(EVAL / "phase4_fusion_loso_hgb.json"), "--scenarios",
         *SCENARIOS, "--variant", "asis", "--model", "hgb"])
    run([str(SCRIPTS / "evaluate_correlation.py"), str(CORPUS), str(EVAL / "phase5_correlation.json"),
         "--incidents-dir", str(CORPUS / "incidents")])
    run([str(SCRIPTS / "evaluate_attribution.py"), str(CORPUS), str(EVAL / "phase6_attribution.json"),
         "--attributions-dir", str(CORPUS / "attributions")])
    run([str(SCRIPTS / "evaluate_risk.py"), str(CORPUS), str(EVAL / "phase7_risk.json")])


def _f1(p, r):
    return round(2 * p * r / (p + r), 4) if p and r else 0.0


def _prf(op: Dict[str, Any]) -> Dict[str, Any]:
    p, r = op["precision"] or 0.0, op["recall"] or 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": _f1(p, r), "support": op["hostile_total"],
            "false_alarms_per_day": op["false_alarms_per_day"]}


def _ratio(text: str) -> float:
    a, b = text.split("/")
    return round(int(a) / int(b), 4) if int(b) else 0.0


def assemble(timestamp: str) -> Dict[str, Any]:
    load = lambda name: json.loads((EVAL / name).read_text(encoding="utf-8"))  # noqa: E731
    detectors, fusion = load("phase3_ait_corpus_asis.json"), load("phase4_fusion_loso_logreg.json")
    correlation, attribution, risk = load("phase5_correlation.json"), load("phase6_attribution.json"), load("phase7_risk.json")
    held = fusion["pooled"]["held-out"]
    ops = held["operating_points"]

    folds = [fusion["folds"][s] for s in HELD_OUT]
    bins: Dict[tuple, List[float]] = {}
    for fold in folds:
        for b in fold["calibration_on_test"]["bins"]:
            row = bins.setdefault((b["lo"], b["hi"]), [0, 0.0, 0.0])
            row[0] += b["n"]
            row[1] += b["mean_confidence"] * b["n"]
            row[2] += b["fraction_hostile"] * b["n"]
    reliability = [{"bin_lower": lo, "bin_upper": hi, "mean_confidence": round(c / n, 4), "observed_rate": round(o / n, 4),
                    "count": int(n)} for (lo, hi), (n, c, o) in sorted(bins.items())]
    total = sum(b["count"] for b in reliability)
    decisions = [fold["decisions"]["pipeline_rules_first"] for fold in folds]
    windows = sum(sum(d.values()) for d in decisions)

    per_class = {}
    for cls in ("incident", "exfiltration"):
        rows = [f["recall_by_class"]["pipeline_alert_or_review"][cls] for f in folds if f["recall_by_class"]["pipeline_alert_or_review"].get(cls)]
        flagged, support = sum(r["flagged"] for r in rows), sum(r["windows"] for r in rows)
        per_class[cls] = {"precision": None, "recall": round(flagged / support, 4) if support else None, "f1": None,
                          "support": support}
    latencies = [detectors["decisions"]["rules-1.2.0:any"]["per_scenario"][s]["latency_minutes"] * 60 for s in HELD_OUT
                 if detectors["decisions"]["rules-1.2.0:any"]["per_scenario"][s]["latency_minutes"] is not None]
    att_new, att_old = attribution["pooled"]["graph-attribution-1.1.0"]["held-out"], attribution["pooled"]["graph-attribution-1.0.0"]["held-out"]
    days = held["test_days"]
    pipeline = _prf(ops["pipeline alert|review"])
    return {
        "schema_version": "1.0",
        "model_version": PIPELINE_VERSION,
        "components": COMPONENTS,
        "corpus": "AIT-LDS v2.0, 8 scenarios (Zenodo 10.5281/zenodo.5789064); held-out = " + ", ".join(HELD_OUT),
        "corpus_seed": SEED,
        "evaluation_timestamp": timestamp,
        "scope": "held-out scenarios only, window level, hostile = intrusion or exfiltration; leave-one-scenario-out fusion",
        "overall_precision": pipeline["precision"], "overall_recall": pipeline["recall"], "overall_f1": pipeline["f1"],
        "per_class_metrics": per_class,
        "per_detector_metrics": {
            "rules": _prf(ops["rules any"]), "rules_high_severity": _prf(ops["rules high"]),
            "rules_or_isolation_forest": _prf(ops["before_fusion: rules any | iforest>=0.999"]),
            "fusion": _prf(ops["fusion alert"]), "pipeline_rules_first": pipeline,
        },
        "ranking_median_average_precision": held["median_average_precision"],
        "calibration": {
            "brier_score": held["brier_weighted"], "expected_calibration_error": held["ece_weighted"],
            "max_calibration_error": max((abs(b["mean_confidence"] - b["observed_rate"]) for b in reliability), default=None),
            "auc_roc": round(statistics.mean(f["ranking"]["fusion"]["roc_auc"] for f in folds), 4),
            "reliability_bins": reliability, "windows": total,
        },
        "abstention_rate": round(sum(d["review"] for d in decisions) / windows, 6) if windows else None,
        "alerts_per_analyst_day": {
            "raw_detector_alerts": held["alerts_per_day"]["windows_flagged_before_fusion"],
            "after_fusion": held["alerts_per_day"]["pipeline_fused_alerts"],
            "incidents": round(sum(correlation["scenarios"][s]["incidents"] for s in HELD_OUT) / days, 2),
            "benign_only_incidents": correlation["pooled"]["held-out"]["benign_only_incidents_per_day"],
        },
        "incident_consolidation_ratio": correlation["pooled"]["held-out"]["consolidation_ratio"],
        "incidents": {"intrusion_in_one_incident": correlation["pooled"]["held-out"]["intrusion_in_one_incident"],
                      "main_incident_share_of_intrusion_alerts": correlation["pooled"]["held-out"]["main_incident_share_of_intrusion_alerts"],
                      "intrusion_ranked_first_by_risk": risk["pooled"]["held-out"]["intrusion_ranked_first"]},
        # numeric-only objects (contract section 9; the platform's response model types them as numbers)
        "attribution": {
            "entry_point_accuracy": _ratio(att_new["entry_event_correct"]),
            "entry_point_accuracy_pre_registered": _ratio(att_old["entry_event_correct"]),
            "path_precision": att_new["mean_path_precision"],
            "path_recall": att_new["mean_reached_recall"],
            "reached_assets_jaccard": att_new["mean_reached_jaccard"],
            "privileged_host_reached": _ratio(att_new["privileged_host_reached"]),
        },
        "detection_latency_seconds": {"median": statistics.median(latencies) if latencies else None,
                                      "p95": sorted(latencies)[max(0, int(round(0.95 * len(latencies))) - 1)] if latencies else None},
        "notes": {
            "attribution": f"{COMPONENTS['attribution']}: " + attribution["post_hoc"]["graph-attribution-1.1.0"],
            "path_recall": "share of ground-truth hosts the attack path proves were reached",
            "detection_latency_seconds": "from the first incident window to the end of the first flagged window (5-minute resolution)",
            "auc_roc": "mean over the 6 held-out folds",
            "per_class_metrics": "windows; the pipeline flags hostile vs benign, it does not predict the class",
        },
        "sources": ["phase3_ait_corpus_asis.json", "phase4_fusion_loso_logreg.json", "phase5_correlation.json",
                    "phase6_attribution.json", "phase7_risk.json", "calibration.json"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--assemble-only", action="store_true")
    parser.add_argument("--out", default=str(EVAL / "evaluation_results.json"))
    args = parser.parse_args()
    started = time.perf_counter()
    if not args.assemble_only:
        run_stages()
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    result = assemble(timestamp)
    Path(args.out).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("overall_precision", "overall_recall", "overall_f1", "abstention_rate",
                                             "alerts_per_analyst_day", "incident_consolidation_ratio", "attribution",
                                             "detection_latency_seconds")}, indent=1))
    print(f"[{time.perf_counter() - started:.0f} s]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
