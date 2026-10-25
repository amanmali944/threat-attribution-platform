"""Phase 6 evaluation: attribution of each scenario's intrusion incident against AIT ground truth.

    python -I scripts/evaluate_attribution.py <corpus dir> <results json> [--attributions-dir DIR]

Input: the Phase 5 incidents (`<corpus>/incidents/<scenario>.json`, written by
evaluate_correlation.py: leave-one-scenario-out pipeline, so out-of-sample). For each scenario
the MAIN intrusion incident (the one holding the most intrusion alerts) is attributed with
attribution/graph.py and compared with the labels:

  entry      the account of the event labelled `attacker_vpn` (the stolen-certificate VPN login),
             its origin address, and the exact event;
  reach      company hosts touched by intrusion-labelled events (any role, canonicalised with the
             asset inventory) vs the reached assets: precision, recall, Jaccard; and whether the
             host of the labelled privilege escalation (`escalated_*`) is reached;
  path       every step cites an event of the incident, steps are in time order, share of steps
             whose event is intrusion-labelled (path precision);
  dwell      attributed dwell time vs the labelled one (first to last intrusion event).
The committed results hold no identifiers (only flags and numbers); full Attribution Results go
to --attributions-dir (git-ignored).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Set

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services.attribution.correlation import AssetInventory  # noqa: E402
from app.services.attribution.graph import METHODS, _host_ids, _Namer, attribute, observed_graph  # noqa: E402
from app.services.detection.labeling import load_event_labels, load_spec  # noqa: E402
from app.services.detection.resolve import resolve_events  # noqa: E402

SCENARIOS = ("russellmitchell", "fox", "harrison", "santos", "shaw", "wardbeck", "wheeler", "wilson")
DEVELOPMENT = ("russellmitchell", "fox")
ESCALATION = {"escalated_command", "escalated_sudo_command", "escalated_sudo_session", "attacker_change_user"}


def _iso(ts_us: int) -> str:
    return datetime.fromtimestamp(ts_us / 1e6, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def load_scenario(derived: Path, test_start: str, test_end: str):
    """All test-period events (resolved) and all event labels of a scenario."""
    raw, labels = [], {}
    for source in sorted(p for p in derived.iterdir() if (p / "events.jsonl").exists()):
        labels.update(load_event_labels(str(source / "labels.jsonl")))
        with open(source / "events.jsonl", "rt", encoding="utf-8") as handle:
            for line in handle:
                at = line.find('"observed_at":"') + 15
                stamp = line[at:at + 20]
                if test_start <= stamp < test_end:
                    raw.append(json.loads(line))
    events, report = resolve_events(raw)
    if report["skipped_events"]:
        raise SystemExit(f"{derived.name}: {len(report['skipped_events'])} events failed resolution")
    return {e.event_id: e for e in events}, labels


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("corpus_dir")
    parser.add_argument("results")
    parser.add_argument("--attributions-dir", default=None)
    args = parser.parse_args()
    started = time.perf_counter()
    corpus = Path(args.corpus_dir)
    repo = Path(__file__).resolve().parents[1]
    per: Dict[str, Any] = {}

    for s in SCENARIOS:
        data = json.loads((corpus / "incidents" / f"{s}.json").read_text(encoding="utf-8"))
        fused, labels_of_alert = data["fused_alerts"], data["fused_alert_labels"]
        label_by_id = {a["fused_alert_id"]: l["label"] for a, l in zip(fused, labels_of_alert)}
        main_incident = max(data["incidents"], key=lambda inc: (
            sum(1 for f in inc["fused_alert_ids"] if label_by_id[f] == "incident"), len(inc["fused_alert_ids"])))
        spec = load_spec(str(repo / "data" / "specs" / "ait" / f"{s}.json"))
        test = spec.splits["test"]
        events, event_labels = load_scenario(corpus / "derived" / s, _iso(test.start_us), _iso(test.end_us))
        assets = AssetInventory.from_dict(json.loads((corpus / "derived" / s / "assets.json").read_text(encoding="utf-8")))
        access = observed_graph(events.values(), assets)

        # ---- ground truth
        name = _Namer(assets)
        intrusion = {eid for eid, ls in event_labels.items() if set(ls) & set(spec.label_classes["incident"])}
        # the stolen-certificate VPN login; with several sessions (wheeler) the entry is the first one
        gt_entry = sorted((eid for eid, ls in event_labels.items() if "attacker_vpn" in ls),
                          key=lambda eid: (events[eid].ts_us, eid))
        if not gt_entry:
            raise SystemExit(f"{s}: no attacker_vpn event")
        entry_event = events[gt_entry[0]]
        all_hosts = _host_ids(assets)
        gt_reached: Set[str] = set()
        gt_privileged: Set[str] = set()
        intrusion_ts = []
        for eid in intrusion:
            event = events.get(eid)
            if event is None:
                continue
            intrusion_ts.append(event.ts_us)
            for ref in (event.actor_user, event.actor_ip, event.actor_host, event.target):
                if ref is not None and name(ref) in all_hosts:
                    gt_reached.add(name(ref))
            if set(event_labels[eid]) & ESCALATION and event.actor_host is not None:
                gt_privileged.add(name(event.actor_host))
        entry_host = name(entry_event.target) if entry_event.target else None
        incident_events = {e for f in main_incident["fused_alert_ids"]
                           for a in fused if a["fused_alert_id"] == f for e in a["event_ids"]}
        per[s] = {"role": "development" if s in DEVELOPMENT else "held-out", "methods": {}}
        for method in METHODS:
            result = attribute(main_incident, fused, events, assets, access, method=method)
            per[s]["methods"][method] = score(result, name, entry_event, gt_entry[0], entry_host, gt_reached,
                                              gt_privileged, intrusion, intrusion_ts, incident_events)
            if args.attributions_dir:
                out = Path(args.attributions_dir)
                out.mkdir(parents=True, exist_ok=True)
                (out / f"{s}-{method}.json").write_text(json.dumps(result, indent=1, sort_keys=True) + "\n", encoding="utf-8")
            r = per[s]["methods"][method]
            print(f"{s:16s} {method[-5:]} entry acct {r['entry_account_correct']} origin {r['entry_origin_correct']}"
                  f" event {r['entry_event_correct']} | priv host {r['privileged_host_reached']} | reached J"
                  f" {r['reached_jaccard']} (P {r['reached_precision']} R {r['reached_recall']}) | path {r['path_steps']}"
                  f" steps prec {r['path_precision']} | dwell {r['dwell_time_seconds']}s vs {r['ground_truth_dwell_seconds']}s"
                  f" | conf {r['confidence']}", flush=True)

    pooled: Dict[str, Any] = {}
    for method in METHODS:
        pooled[method] = {}
        for group in ("development", "held-out"):
            rows = [per[s]["methods"][method] for s in SCENARIOS if per[s]["role"] == group]
            count = lambda key: f"{sum(1 for r in rows if r[key])}/{len(rows)}"  # noqa: E731
            mean = lambda key: round(sum(r[key] for r in rows if r[key] is not None)  # noqa: E731
                                     / max(1, sum(1 for r in rows if r[key] is not None)), 4)
            pooled[method][group] = {
                "scenarios": len(rows),
                "entry_account_correct": count("entry_account_correct"), "entry_origin_correct": count("entry_origin_correct"),
                "entry_event_correct": count("entry_event_correct"), "privileged_host_reached": count("privileged_host_reached"),
                "path_valid": f"{sum(1 for r in rows if r['path_cites_incident_events'] and r['path_time_ordered'])}/{len(rows)}",
                "mean_reached_jaccard": mean("reached_jaccard"), "mean_reached_precision": mean("reached_precision"),
                "mean_reached_recall": mean("reached_recall"), "mean_path_precision": mean("path_precision"),
                "dwell_exact": count("dwell_exact"), "mean_confidence": mean("confidence"),
            }
    results = {"methods": list(METHODS), "pre_registered": "graph-attribution-1.0.0",
               "post_hoc": {"graph-attribution-1.1.0": "entry = graph root; decided AFTER the 1.0.0 entry errors on two "
                                                       "held-out scenarios (shaw, wilson) were seen"},
               "input": "Phase 5 incidents (leave-one-scenario-out pipeline)", "scenarios": per,
               "pooled": pooled, "seconds": round(time.perf_counter() - started, 1)}
    os.makedirs(os.path.dirname(os.path.abspath(args.results)), exist_ok=True)
    Path(args.results).write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for method, groups in pooled.items():
        for group, body in groups.items():
            print(f"-- {method} {group}: {json.dumps(body)}")
    return 0


def score(result, name, entry_event, entry_event_id, entry_host, gt_reached, gt_privileged, intrusion,
          intrusion_ts, incident_events) -> Dict[str, Any]:
    host_ids = {a["entity_id"] for a in result["reached_assets"] if a["entity_type"] == "host"}
    steps = result["attack_path"]
    tp = host_ids & gt_reached
    gt_dwell = int((max(intrusion_ts) - entry_event.ts_us) // 1_000_000) if intrusion_ts else None
    return {
        "entry_account_correct": result["entry_point"]["entity_id"] == name(entry_event.actor_user),
        "entry_origin_correct": result["entry_point"]["origin_entity_id"] == (name(entry_event.actor_ip) if entry_event.actor_ip else None),
        "entry_event_correct": result["entry_point"]["first_anomalous_event_id"] == entry_event_id,
        "entry_host_reached_first": bool(result["reached_assets"]) and result["reached_assets"][0]["entity_id"] == entry_host,
        "privileged_host_reached": bool(gt_privileged) and gt_privileged <= host_ids,
        "reached_hosts": len(host_ids), "ground_truth_hosts": len(gt_reached),
        "reached_precision": round(len(tp) / len(host_ids), 4) if host_ids else None,
        "reached_recall": round(len(tp) / len(gt_reached), 4) if gt_reached else None,
        "reached_jaccard": round(len(tp) / len(host_ids | gt_reached), 4) if host_ids | gt_reached else None,
        "path_steps": len(steps),
        "path_cites_incident_events": all(st["event_id"] in incident_events for st in steps),
        "path_time_ordered": [st["observed_at"] for st in steps] == sorted(st["observed_at"] for st in steps),
        "path_precision": round(sum(1 for st in steps if st["event_id"] in intrusion) / len(steps), 4) if steps else None,
        "path_layers": sorted({st["layer"] for st in steps}),
            "dwell_time_seconds": result["dwell_time_seconds"],
            "ground_truth_dwell_seconds": gt_dwell,
            "dwell_exact": gt_dwell is not None and result["dwell_time_seconds"] == gt_dwell,
            "confidence": result["confidence"],
            "blast_radius": result["blast_radius"],
            "techniques": [t["technique_id"] for t in result["techniques"]],
    }


if __name__ == "__main__":
    raise SystemExit(main())
