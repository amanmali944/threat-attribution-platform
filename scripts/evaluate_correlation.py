"""Phase 5 evaluation: pipeline Fused Alerts -> incidents, per AIT scenario.

    python -I scripts/evaluate_correlation.py <corpus dir> <results json> [--variant asis] [--incidents-dir DIR]

For every scenario S (all 8):
  1. the leave-one-scenario-out fusion model (fit on the other 7 scenarios' dumps), rules-first
     decisions on S's test windows - exactly the Phase 4 pipeline, out-of-sample for S;
  2. windows decided alert / review are folded into Fused Alerts (event IDs from the window files);
  3. the alerts' events are resolved and correlated with S's asset inventory (correlation.py);
  4. incidents are scored against the labels:
       - intrusion fragmentation: incidents holding intrusion alerts (ideal 1);
       - the main intrusion incident: share of intrusion alerts it holds, attack stages it covers,
         benign alerts and exfiltration alerts merged into it;
       - benign-only incidents per day (what an analyst would open for nothing);
       - consolidation ratio (Fused Alerts per incident).
Incident Objects are written per scenario to --incidents-dir (git-ignored) for Phase 6.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services.attribution.correlation import (  # noqa: E402
    DEFAULT_HORIZON_SECONDS,
    METHOD,
    AssetInventory,
    consolidation,
    correlate,
)
from app.services.detection.fusion import FusionModel, fuse_alerts, rules_first  # noqa: E402
from app.services.detection.labeling import to_us  # noqa: E402
from app.services.detection.resolve import resolve_events  # noqa: E402

SCENARIOS = ("russellmitchell", "fox", "harrison", "santos", "shaw", "wardbeck", "wheeler", "wilson")
DEVELOPMENT = ("russellmitchell", "fox")
STAGES = ("entry", "discovery", "web_attack", "privilege")
CLASSES = ("incident", "exfiltration")


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    with open(path, "rt", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle]


def load_events(derived: Path, wanted: set) -> Dict[str, Any]:
    raw = []
    for source in sorted(p for p in derived.iterdir() if (p / "events.jsonl").exists()):
        with open(source / "events.jsonl", "rt", encoding="utf-8") as handle:
            for line in handle:
                # cheap pre-filter on the id before parsing the line
                start = line.find('"event_id":"') + 12
                if line[start:line.find('"', start)] in wanted:
                    raw.append(json.loads(line))
    events, report = resolve_events(raw)
    if report["skipped_events"]:
        raise SystemExit(f"{derived.name}: {len(report['skipped_events'])} events failed resolution")
    return {e.event_id: e for e in events}


def alert_labels(alert, windows_by_entity) -> Dict[str, Any]:
    start, end = alert["window_start"], alert["window_end"]
    members = [w for w in windows_by_entity.get(alert["entity_id"], []) if start <= w["window_start"] < end]
    labels = {w["label"] for w in members}
    return {"label": next((c for c in CLASSES if c in labels), "background"),
            "stages": sorted({s for w in members for s in w.get("stages", [])})}


def score(incidents, fused, labels, days) -> Dict[str, Any]:
    by_id = {a["fused_alert_id"]: labels[i] for i, a in enumerate(fused)}
    rows = []
    for inc in incidents:
        member = [by_id[f] for f in inc["fused_alert_ids"]]
        counts = Counter(m["label"] for m in member)
        rows.append({"incident_id": inc["incident_id"], "alerts": len(member), "labels": dict(counts),
                     "stages": sorted({s for m in member for s in m["stages"]}), "layers": inc["layers"],
                     "title": inc["title"], "first_seen": inc["first_seen"], "last_seen": inc["last_seen"],
                     "link_reasons": [r.split(":")[0] for r in inc["correlation"]["link_reasons"]]})
    intrusion_total = sum(1 for m in labels if m["label"] == "incident")
    exfil_total = sum(1 for m in labels if m["label"] == "exfiltration")
    with_intrusion = [r for r in rows if r["labels"].get("incident")]
    main = max(with_intrusion, key=lambda r: (r["labels"]["incident"], r["alerts"]), default=None)
    benign_only = [r for r in rows if set(r["labels"]) == {"background"}]
    out = {
        "fused_alerts": len(fused), "fused_alerts_by_label": dict(Counter(m["label"] for m in labels)),
        "incidents": len(incidents), "incidents_per_day": round(len(incidents) / days, 2),
        "consolidation_ratio": consolidation(fused, incidents),
        "intrusion_incidents": len(with_intrusion),
        "benign_only_incidents": len(benign_only), "benign_only_incidents_per_day": round(len(benign_only) / days, 2),
        "exfiltration_incidents": sum(1 for r in rows if r["labels"].get("exfiltration")),
        "main_intrusion_incident": None,
        "incident_table": rows,
    }
    if main:
        out["main_intrusion_incident"] = {
            "incident_id": main["incident_id"], "intrusion_alerts": main["labels"]["incident"],
            "intrusion_alerts_total": intrusion_total,
            "share_of_intrusion_alerts": round(main["labels"]["incident"] / intrusion_total, 4),
            "benign_alerts_merged": main["labels"].get("background", 0),
            "exfiltration_alerts_merged": main["labels"].get("exfiltration", 0),
            "exfiltration_alerts_total": exfil_total,
            "stages": main["stages"], "all_stages_present": all(s in main["stages"] for s in STAGES),
            "layers": main["layers"], "title": main["title"], "link_reasons": sorted(set(main["link_reasons"])),
        }
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("corpus_dir")
    parser.add_argument("results")
    parser.add_argument("--variant", default="asis", choices=["asis", "clean"])
    parser.add_argument("--incidents-dir", default=None)
    parser.add_argument("--horizon-seconds", type=int, default=DEFAULT_HORIZON_SECONDS)
    args = parser.parse_args()
    started = time.perf_counter()
    corpus = Path(args.corpus_dir)
    dumps = {s: load_jsonl(corpus / "dumps" / f"{s}-{args.variant}.jsonl") for s in SCENARIOS}

    per: Dict[str, Any] = {}
    for s in SCENARIOS:
        train = [w for o in SCENARIOS if o != s for w in dumps[o]]
        model = FusionModel().fit(train, [w["scenario"] for w in train])
        test = dumps[s]
        windows = {(w["entity_id"], w["window_start"]): w
                   for w in load_jsonl(corpus / "windows" / f"{s}-{args.variant}" / "test.jsonl")}
        for w in test:
            src = windows[(w["entity_id"], w["window_start"])]
            w["event_ids"], w["tenant_id"] = src["event_ids"], src["tenant_id"]
        confidence = model.confidence(test)
        decisions = rules_first(test, model.decide(confidence))
        fused = fuse_alerts(test, confidence, decisions)
        events = load_events(corpus / "derived" / s, {e for a in fused for e in a["event_ids"]})
        assets = AssetInventory.from_dict(json.loads((corpus / "derived" / s / "assets.json").read_text(encoding="utf-8")))
        incidents = correlate(fused, events, assets, args.horizon_seconds)
        windows_by_entity: Dict[str, List[Dict[str, Any]]] = {}
        for w in test:
            windows_by_entity.setdefault(w["entity_id"], []).append(w)
        labels = [alert_labels(a, windows_by_entity) for a in fused]
        days = max(1.0, round((max(to_us(w["window_end"]) for w in test) - min(to_us(w["window_start"]) for w in test)) / 86_400e6))
        per[s] = score(incidents, fused, labels, days) | {"role": "development" if s in DEVELOPMENT else "held-out",
                                                         "test_days": days}
        if args.incidents_dir:
            out_dir = Path(args.incidents_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / f"{s}.json").write_text(json.dumps(
                {"scenario": s, "incidents": incidents, "fused_alerts": fused, "fused_alert_labels": labels},
                indent=1, sort_keys=True) + "\n", encoding="utf-8")
        m = per[s]["main_intrusion_incident"]
        print(f"{s:16s} fused {per[s]['fused_alerts']:3d} incidents {per[s]['incidents']:3d} intrusion-incidents "
              f"{per[s]['intrusion_incidents']} main {m['intrusion_alerts']}/{m['intrusion_alerts_total']} "
              f"stages {len(m['stages'])}/4 benign-merged {m['benign_alerts_merged']} exfil-merged "
              f"{m['exfiltration_alerts_merged']} benign-only {per[s]['benign_only_incidents']}", flush=True)

    pooled = {}
    for group in ("development", "held-out"):
        names = [s for s in SCENARIOS if per[s]["role"] == group]
        mains = [per[s]["main_intrusion_incident"] for s in names]
        days = sum(per[s]["test_days"] for s in names)
        pooled[group] = {
            "scenarios": len(names),
            "intrusion_in_one_incident": sum(1 for s in names if per[s]["intrusion_incidents"] == 1),
            "main_incident_share_of_intrusion_alerts": round(
                sum(m["intrusion_alerts"] for m in mains) / sum(m["intrusion_alerts_total"] for m in mains), 4),
            "main_incident_all_4_stages": sum(1 for m in mains if m["all_stages_present"]),
            "benign_alerts_merged_into_main": sum(m["benign_alerts_merged"] for m in mains),
            "exfiltration_merged_into_main": sum(1 for m in mains if m["exfiltration_alerts_merged"]),
            "benign_only_incidents_per_day": round(sum(per[s]["benign_only_incidents"] for s in names) / days, 2),
            "consolidation_ratio": round(sum(per[s]["fused_alerts"] for s in names)
                                         / sum(per[s]["incidents"] for s in names), 3),
        }
    results = {"method": METHOD, "horizon_seconds": args.horizon_seconds, "variant": args.variant,
               "pipeline": "leave-one-scenario-out fusion-1.0.0 + rules_first, Fused Alerts (30 min folding)",
               "scenarios": per, "pooled": pooled, "seconds": round(time.perf_counter() - started, 1)}
    os.makedirs(os.path.dirname(os.path.abspath(args.results)), exist_ok=True)
    Path(args.results).write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for group, body in pooled.items():
        print(f"-- {group}: {json.dumps(body)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
