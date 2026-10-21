"""Summarise per-scenario AIT evaluations (evaluate_ait.py outputs) into one corpus table.

    python -I scripts/summarize_ait.py <eval dir> <out json> [--variant asis]

Per scenario and decision: incident windows flagged, stages detected, false alarms per day,
latency; exfiltration where the test day has it. Pooled separately over DEVELOPMENT and
HELD-OUT scenarios (sums of counts, so every window counts once; stage detection as
"scenarios where the stage was detected / scenarios").
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any, Dict, List

DEVELOPMENT = ("russellmitchell", "fox")
DECISIONS = ("rules-1.2.0:any", "rules-1.2.0:high", "rules-1.1.0:any", "rules-1.0.0:any",
             "iforest>=0.99", "iforest>=0.999", "rules-1.2.0:any|iforest>=0.999")
STAGES = ("entry", "discovery", "web_attack", "privilege")


def row(results: Dict[str, Any], decision: str) -> Dict[str, Any]:
    inc = results["tasks"]["incident"]["operating_points"][decision]
    stages = results["incident_stages"][decision]
    out = {
        "incident_windows_flagged": inc["positive_windows_flagged"],
        "incident_windows_total": inc["positive_windows_total"],
        "false_alarm_windows": inc["false_alarm_windows"],
        "false_alarms_per_day": inc["false_alarms_per_day"],
        "latency_minutes": inc["latency_minutes_from_first_positive_window"],
        "stages_detected": {s: stages[s]["detected"] for s in STAGES if stages[s]["windows"]},
    }
    exf = results["tasks"]["exfiltration"]["operating_points"][decision]
    if exf["positive_windows_total"]:
        out["exfiltration_windows_flagged"] = exf["positive_windows_flagged"]
        out["exfiltration_windows_total"] = exf["positive_windows_total"]
    return out


def pool(rows: List[Dict[str, Any]], days: List[float]) -> Dict[str, Any]:
    flagged = sum(r["incident_windows_flagged"] for r in rows)
    total = sum(r["incident_windows_total"] for r in rows)
    fa = sum(r["false_alarm_windows"] for r in rows)
    latencies = [r["latency_minutes"] for r in rows if r["latency_minutes"] is not None]
    out = {
        "scenarios": len(rows),
        "incidents_detected": sum(1 for r in rows if r["incident_windows_flagged"] > 0),
        "incident_windows_flagged": flagged, "incident_windows_total": total,
        "window_recall": round(flagged / total, 4) if total else None,
        "false_alarm_windows": fa, "test_days": round(sum(days), 3),
        "false_alarms_per_day": round(fa / sum(days), 2) if days else None,
        "median_latency_minutes": statistics.median(latencies) if latencies else None,
        "stages_detected": {s: f"{sum(1 for r in rows if r['stages_detected'].get(s))}/"
                               f"{sum(1 for r in rows if s in r['stages_detected'])}" for s in STAGES},
    }
    ex = [r for r in rows if "exfiltration_windows_total" in r]
    if ex:
        out["exfiltration_windows"] = (f"{sum(r['exfiltration_windows_flagged'] for r in ex)}/"
                                       f"{sum(r['exfiltration_windows_total'] for r in ex)}")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("eval_dir")
    parser.add_argument("out")
    parser.add_argument("--variant", default="asis", choices=["asis", "clean"])
    args = parser.parse_args()

    files = sorted(Path(args.eval_dir).glob(f"*-{args.variant}.json"))
    files = [f for f in files if not f.name.startswith("fusion")]
    results = {f.name[: -len(f"-{args.variant}.json")]: json.loads(f.read_text(encoding="utf-8")) for f in files}
    if not results:
        raise SystemExit("no evaluation files")
    table: Dict[str, Any] = {}
    for decision in DECISIONS:
        per = {s: row(r, decision) for s, r in sorted(results.items())}
        groups = {"development": [s for s in per if s in DEVELOPMENT],
                  "held-out": [s for s in per if s not in DEVELOPMENT]}
        table[decision] = {
            "per_scenario": per,
            "pooled": {g: pool([per[s] for s in names], [results[s]["data"]["test_days"] for s in names])
                       for g, names in groups.items() if names},
        }
    meta = {s: {"role": r["scenario_role"], "test_windows_by_label": r["data"]["test_windows_by_label"],
                "test_days": r["data"]["test_days"],
                "gate_disabled": r["rules-1.2.0"]["disabled"],
                "gate_persistent_findings": sorted(r["rules-1.2.0"]["gate"].get("persistent_findings", {})),
                "iforest_incident_roc_auc": r["tasks"]["incident"]["iforest_ranking"]["roc_auc"],
                "iforest_incident_roc_auc_ip": r["tasks"]["incident"]["iforest_ranking_by_entity_type"].get("ip", {}).get("roc_auc"),
                "versions": {"features": r["isolation_forest"]["metadata"]["feature_set_version"],
                             "iforest": r["isolation_forest"]["metadata"]["model_version"]}}
            for s, r in sorted(results.items())}
    out = {"variant": args.variant, "development_scenarios": list(DEVELOPMENT), "scenarios": meta,
           "decisions": table}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for decision in ("rules-1.2.0:any", "rules-1.2.0:high", "rules-1.1.0:any", "iforest>=0.999"):
        for group, p in table[decision]["pooled"].items():
            print(f"{decision:28s} {group:12s} {json.dumps(p)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
