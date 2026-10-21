"""Phase 3 evaluation on one AIT-LDS scenario: the current rule set, older rule sets, Isolation Forest.

    python -I scripts/evaluate_ait.py <windows dir> <spec json> <derived dir> <results json> [--model-dir DIR]

<windows dir> is an output of build_ait_windows.py (variant as-is or clean-baseline, read from
its dataset_report.json); <derived dir> holds the converted sources (for per-step labels only).

Protocol (fixed before any detector output on this dataset was looked at):
  * training pools: as-is = EVERY train / validation window (no labels used before the test -
    the exfiltration is in there, as it would be in production); clean-baseline = the same
    minus exfiltration windows (label-informed, disclosed). No incident window exists outside test.
  * the current rule set (primary) and rules-1.1.0 (comparison): calibrate on the train pool,
    validation gate on the validation pool (rules firing on > 0.5% of it are turned off), score
    test once.
  * rules-1.0.0 (comparison): calibrate on train + validation pools, no gate - its Org Y protocol.
  * Isolation Forest: fit on the train pool, ECDF reference = train + validation pools.
  * two tasks on the test split: incident (positive) vs background, exfiltration excluded; and
    exfiltration vs background, incident excluded. Alerts on the excluded class are reported,
    never counted as false alarms.
  * incident-level: which attack STAGES (entry, discovery, web attack, privilege) had at least
    one flagged window, and latency from the first incident window.
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
from typing import Any, Dict, List, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import joblib  # noqa: E402

from app.services.detection import contract as C  # noqa: E402
from app.services.detection.anomaly import MODEL_VERSION, IsolationForestDetector  # noqa: E402
from app.services.detection.evaluation import (  # noqa: E402
    latency_minutes,
    operating_point,
    task_ranking,
)
from app.services.detection.labeling import load_event_labels, load_spec, to_us  # noqa: E402
from app.services.detection.rules import RULESET_VERSION, RuleEngine  # noqa: E402

DEVELOPMENT_SCENARIOS = ("russellmitchell", "fox")   # detector changes may be designed on these only
IFOREST_POINTS = (0.99, 0.999)
COMBINED_IFOREST = 0.999
TASKS = ("incident", "exfiltration")
# AIT step labels -> attack stage (the umbrella labels foothold / escalate carry no stage).
STAGES = {
    "entry": {"attacker_vpn"},
    "discovery": {"dns_scan", "traceroute", "network_scan", "service_scan"},
    "web_attack": {"dirb", "wpscan", "attacker_http", "webshell_upload", "webshell_cmd"},
    "privilege": {"attacker_change_user", "escalated_command", "escalated_sudo_command", "escalated_sudo_session"},
}


def load(path: str) -> List[Dict[str, Any]]:
    with open(path, "rt", encoding="utf-8") as handle:
        records = [json.loads(line) for line in handle]
    records.sort(key=lambda r: (r["window_start"], r["entity_type"], r["entity_id"]))
    return records


def load_all_event_labels(derived_dir: str) -> Dict[str, List[str]]:
    labels: Dict[str, List[str]] = {}
    for name in sorted(os.listdir(derived_dir)):
        path = os.path.join(derived_dir, name, "labels.jsonl")
        if os.path.isfile(path):
            labels.update(load_event_labels(path))
    return labels


def window_stages(record: Mapping[str, Any], event_labels: Mapping[str, Sequence[str]]) -> List[str]:
    names = set()
    for eid in record["event_ids"]:
        names.update(event_labels.get(eid, ()))
    return [stage for stage, members in STAGES.items() if names & members]


def stage_coverage(test, flags, stages_of) -> Dict[str, Any]:
    out = {}
    for stage in STAGES:
        windows = [i for i, r in enumerate(test) if r["label"] == "incident" and stage in stages_of[i]]
        out[stage] = {"windows": len(windows), "flagged": sum(1 for i in windows if flags[i]),
                      "detected": any(flags[i] for i in windows)}
    return out


def rule_flags(engine: RuleEngine, records, include_disabled: bool = False):
    any_rule, high, fired_ids = [], [], []
    for record in records:
        alerts = engine.evaluate(record, include_disabled=include_disabled)
        any_rule.append(bool(alerts))
        high.append(any(a["severity"] in ("high", "critical") for a in alerts))
        fired_ids.append(sorted({a["rule_id"] for a in alerts}))
    return any_rule, high, fired_ids


def per_rule_table(engine: RuleEngine, fired_ids, test, validation_pool) -> Dict[str, Any]:
    counts: Dict[str, Counter] = defaultdict(Counter)
    for ids, record in zip(fired_ids, test):
        for rule_id in ids:
            counts[rule_id][record["label"]] += 1
    val = Counter()
    for record in validation_pool:
        for alert in engine.evaluate(record, include_disabled=True):
            val[alert["rule_id"]] += 1
    return {r.rule_id: {"title": r.title, "severity": r.severity, "disabled_by_gate": r.rule_id in engine.disabled,
                        "test_fires": {k: counts[r.rule_id].get(k, 0) for k in ("incident", "exfiltration", "background")},
                        "validation_fires": val.get(r.rule_id, 0)}
            for r in engine.rules}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("windows_dir")
    parser.add_argument("spec")
    parser.add_argument("derived_dir")
    parser.add_argument("results")
    parser.add_argument("--model-dir", default=None, help="where to save the fitted models (git-ignored)")
    parser.add_argument("--dump-windows", default=None,
                        help="write every scored test window (label, stages, rule hits, IF score, features) as "
                             "jsonl - the input of the Phase 4 fusion model (git-ignored)")
    args = parser.parse_args()
    started = time.perf_counter()

    spec = load_spec(args.spec)
    report = json.loads(Path(args.windows_dir, "dataset_report.json").read_text(encoding="utf-8"))
    variant = report["variant"]
    train = load(os.path.join(args.windows_dir, "train.jsonl"))
    validation = load(os.path.join(args.windows_dir, "validation.jsonl"))
    test = load(os.path.join(args.windows_dir, "test.jsonl"))
    if any(r["label"] == "incident" for r in train + validation):
        raise SystemExit("incident window outside test")

    keep = (lambda r: True) if variant == "as-is" else (lambda r: r["label"] != "exfiltration")
    train_pool = [r for r in train if keep(r)]
    validation_pool = [r for r in validation if keep(r)]
    event_labels = load_all_event_labels(args.derived_dir)
    stages_of = [window_stages(r, event_labels) if r["label"] == "incident" else [] for r in test]
    days = (spec.splits["test"].end_us - spec.splits["test"].start_us) / 86_400e6
    first_incident = min(r["window_start"] for r in test if r["label"] == "incident")
    n_incident = sum(1 for r in test if r["label"] == "incident")
    n_background = sum(1 for r in test if r["label"] == "background")

    # ---------------------------------------------------------------- rules
    primary = RULESET_VERSION
    gated = [primary] + [v for v in ("rules-1.1.0",) if v != primary]
    engines = {v: RuleEngine(ruleset=v).calibrate(train_pool).gate(validation_pool) for v in gated}
    engines["rules-1.0.0"] = RuleEngine(ruleset="rules-1.0.0").calibrate(train_pool + validation_pool)
    rule_out = {v: rule_flags(engine, test) for v, engine in engines.items()}
    ids_incl_gated = {v: rule_flags(engines[v], test, include_disabled=True)[2] for v in gated}

    # ---------------------------------------------------------------- isolation forest
    detector = IsolationForestDetector().fit(train_pool, reference_vectors=train_pool + validation_pool)
    raw = detector.scores(test)
    scores = [s if s is not None else 0.0 for s in raw]

    decisions: Dict[str, List[bool]] = {}
    for version in engines:
        decisions[f"{version}:any"], decisions[f"{version}:high"] = rule_out[version][0], rule_out[version][1]
    decisions.update({f"iforest>={t}": [s >= t for s in scores] for t in IFOREST_POINTS})
    decisions[f"{primary}:high|iforest>={COMBINED_IFOREST}"] = [
        h or s >= COMBINED_IFOREST for h, s in zip(rule_out[primary][1], scores)]
    decisions[f"{primary}:any|iforest>={COMBINED_IFOREST}"] = [
        a or s >= COMBINED_IFOREST for a, s in zip(rule_out[primary][0], scores)]
    scenario = spec.dataset.rsplit("/", 1)[-1]
    tasks: Dict[str, Any] = {}
    for task in TASKS:
        task_records_first = sorted(r["window_start"] for r in test if r["label"] == task)
        ops = {}
        for name, flags in decisions.items():
            op = operating_point(test, flags, days, positive=task)
            op["latency_minutes_from_first_positive_window"] = latency_minutes(
                task_records_first[0], op["first_flagged_positive_window"], spec.window_seconds) if task_records_first else None
            ops[name] = op
        by_type = {}
        for etype in sorted({r["entity_type"] for r in test}):
            idx = [i for i, r in enumerate(test) if r["entity_type"] == etype]
            by_type[etype] = task_ranking([test[i] for i in idx], [scores[i] for i in idx], task)
        tasks[task] = {
            "operating_points": ops,
            "iforest_ranking": task_ranking(test, scores, task),
            "iforest_ranking_by_entity_type": by_type,
            "baselines": {
                "event_count_only": task_ranking(test, [float(r["features"]["volume.event_count"]) for r in test], task),
                "random_expected_average_precision": round(
                    sum(1 for r in test if r["label"] == task)
                    / max(1, sum(1 for r in test if r["label"] in (task, "background"))), 4),
            },
        }

    incident_windows = []
    for i, r in enumerate(test):
        if r["label"] != "incident":
            continue
        row = {
            "window_start": r["window_start"], "entity_type": r["entity_type"], "entity_id": r["entity_id"],
            "events": len(r["event_ids"]), "stages": stages_of[i],
            "iforest_score": raw[i],
            "iforest_most_unusual": [e["feature"] for e in detector.explain(r)] if r["entity_type"] in detector.models else [],
        }
        for version in engines:
            row[version] = rule_out[version][2][i]
        for version in gated:
            row[f"{version}_incl_gated"] = ids_incl_gated[version][i]
        incident_windows.append(row)
    top = sorted(range(len(test)), key=lambda i: (-scores[i], test[i]["window_start"]))[:10]
    top10 = [{"score": scores[i], "label": test[i]["label"], "entity_type": test[i]["entity_type"],
              "window_start": test[i]["window_start"],
              "most_unusual": [e["feature"] for e in detector.explain(test[i])] if test[i]["entity_type"] in detector.models else []}
             for i in top]

    results = {
        "dataset": spec.dataset,
        "variant": variant,
        "evaluated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scenario_role": "development" if scenario in DEVELOPMENT_SCENARIOS else "held-out",
        "protocol": (f"{primary} (primary) and rules-1.1.0 calibrated on train, gated on validation; rules-1.0.0 "
                     "calibrated on train+validation; Isolation Forest fit on train, ECDF on train+validation; "
                     "test scored once"),
        "limits": [
            f"ONE intrusion ({n_incident} incident windows): recall moves in steps of {round(1 / n_incident, 3):g} "
            "and is a single observation",
            ("the attack timeline and the incident windows' features were read while building labels (Phase 1b)"
             if scenario == "russellmitchell" else
             "the attack timeline was read to generate the spec (scripts/make_ait_spec.py)"),
            "rules-1.1.0 was decided on Org Y before AIT was opened; no rule or threshold was changed after",
            (f"{primary} and {C.FEATURE_SET_VERSION} were designed on this DEVELOPMENT scenario: its results are "
             "in-sample (optimistic)" if scenario in DEVELOPMENT_SCENARIOS else
             f"{primary} and {C.FEATURE_SET_VERSION} were frozen before this held-out scenario was scored"),
            f"{'one test day' if days == 1 else f'{days:g} test days'}; false-alarm rates rest on {n_background} "
            "background windows",
            ("as-is: the exfiltration is inside the training pools, exactly as an unlabelled system would see it"
             if variant == "as-is" else
             "clean-baseline: exfiltration windows removed from baseline and training pools using labels - optimistic for exfiltration"),
            "Isolation Forest ECDF reference includes its own training windows (in-sample)",
        ],
        "data": {
            "train_pool_windows": len(train_pool), "validation_pool_windows": len(validation_pool),
            "test_windows": len(test), "test_days": days, "first_incident_window": first_incident,
            "test_windows_by_label": dict(sorted(Counter(r["label"] for r in test).items())),
            "test_windows_by_entity_type": dict(sorted(Counter(r["entity_type"] for r in test).items())),
        },
        **{version: {"thresholds": engines[version].thresholds, "threshold_ops": engines[version].threshold_ops,
                     "gate": engines[version].gate_report, "disabled": engines[version].disabled,
                     "calibration": engines[version].calibration,
                     "per_rule": per_rule_table(engines[version], ids_incl_gated[version], test, validation_pool)}
           for version in gated},
        "rules-1.0.0": {"thresholds": engines["rules-1.0.0"].thresholds, "calibration": engines["rules-1.0.0"].calibration,
                        "per_rule": per_rule_table(engines["rules-1.0.0"], rule_out["rules-1.0.0"][2], test, validation_pool)},
        "isolation_forest": {"metadata": detector.metadata(),
                             "test_windows_without_model": sum(1 for s in raw if s is None),
                             "test_windows_without_model_by_label": dict(sorted(
                                 Counter(r["label"] for r, s in zip(test, raw) if s is None).items())),
                             "top10_test_windows": top10},
        "tasks": tasks,
        "incident_stages": {name: stage_coverage(test, flags, stages_of) for name, flags in decisions.items()},
        "incident_windows": incident_windows,
        "seconds": round(time.perf_counter() - started, 1),
    }
    if args.dump_windows:
        primary_engine = engines[primary]
        severity_of = {r.rule_id: r.severity for r in primary_engine.rules}
        os.makedirs(os.path.dirname(os.path.abspath(args.dump_windows)), exist_ok=True)
        with open(args.dump_windows, "w", encoding="utf-8", newline="\n") as handle:
            for i, r in enumerate(test):
                handle.write(json.dumps({
                    "scenario": scenario, "variant": variant, "window_start": r["window_start"],
                    "window_end": r["window_end"], "entity_id": r["entity_id"], "entity_type": r["entity_type"],
                    "label": r["label"], "stages": stages_of[i], "n_events": len(r["event_ids"]),
                    "ruleset": primary, "rules": {rid: severity_of[rid] for rid in rule_out[primary][2][i]},
                    "iforest_version": MODEL_VERSION, "iforest_score": raw[i],
                    "feature_set_version": C.FEATURE_SET_VERSION, "features": r["features"],
                }, sort_keys=True, separators=(",", ":")) + "\n")
    os.makedirs(os.path.dirname(os.path.abspath(args.results)), exist_ok=True)
    with open(args.results, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(results, handle, indent=2, sort_keys=True)
        handle.write("\n")
    if args.model_dir:
        os.makedirs(args.model_dir, exist_ok=True)
        joblib.dump(detector, os.path.join(args.model_dir, f"{MODEL_VERSION}.joblib"))
        for engine in engines.values():
            with open(os.path.join(args.model_dir, f"{engine.ruleset}.json"), "w", encoding="utf-8") as handle:
                json.dump(engine.to_dict(), handle, indent=2, sort_keys=True)
    summary = {name: {t: {k: tasks[t]["operating_points"][name][k]
                          for k in ("positive_windows_flagged", "positive_windows_total", "false_alarm_windows")}
                      for t in TASKS} for name in decisions}
    print(json.dumps({"variant": variant, "operating_points": summary,
                      "iforest": {t: tasks[t]["iforest_ranking"] for t in TASKS},
                      "gate": {v: engines[v].disabled for v in gated}, "seconds": results["seconds"]}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
