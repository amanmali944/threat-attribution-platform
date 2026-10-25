"""Phase 7 evaluation: risk of every Phase 5 incident at the end of each scenario's test period.

    python -I scripts/evaluate_risk.py <corpus dir> <results json>

Per scenario: every incident gets a Risk Score (attribution/risk.py; alert criticality from the
asset inventory) computed at the end of the test split. Reported: whether the intrusion incident
is ranked first, its score and level, the highest benign-only incident score, and how many
benign-only incidents reach "high" or "critical". The committed file holds no identifiers.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.services.attribution.correlation import AssetInventory  # noqa: E402
from app.services.attribution.risk import alert_criticality, incident_risk  # noqa: E402
from app.services.detection.labeling import load_spec  # noqa: E402
from evaluate_correlation import DEVELOPMENT, SCENARIOS, load_events  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("corpus_dir")
    parser.add_argument("results")
    args = parser.parse_args()
    corpus, repo = Path(args.corpus_dir), Path(__file__).resolve().parents[1]
    per: Dict[str, Any] = {}
    for s in SCENARIOS:
        data = json.loads((corpus / "incidents" / f"{s}.json").read_text(encoding="utf-8"))
        fused, labels = data["fused_alerts"], data["fused_alert_labels"]
        label_of = {a["fused_alert_id"]: l["label"] for a, l in zip(fused, labels)}
        events = load_events(corpus / "derived" / s, {e for a in fused for e in a["event_ids"]})
        assets = AssetInventory.from_dict(json.loads((corpus / "derived" / s / "assets.json").read_text(encoding="utf-8")))
        crit = {a["fused_alert_id"]: alert_criticality(a, events, assets) for a in fused}
        end = load_spec(str(repo / "data" / "specs" / "ait" / f"{s}.json")).splits["test"].end_us
        computed_at = datetime.fromtimestamp(end / 1e6, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        rows = []
        for inc in data["incidents"]:
            risk = incident_risk(inc, fused, crit, computed_at)
            kinds = {label_of[f] for f in inc["fused_alert_ids"]}
            kind = "intrusion" if "incident" in kinds else "exfiltration" if "exfiltration" in kinds else "benign"
            rows.append({"kind": kind, "score": risk["score"], "level": risk["level"],
                         "alerts": len(inc["fused_alert_ids"]), "contributors": len(risk["contributors"])})
        rows.sort(key=lambda r: -r["score"])
        intrusion = max((r for r in rows if r["kind"] == "intrusion"), key=lambda r: r["score"])
        benign = [r for r in rows if r["kind"] == "benign"]
        per[s] = {
            "role": "development" if s in DEVELOPMENT else "held-out", "computed_at": computed_at,
            "incidents": len(rows), "intrusion_rank": 1 + sum(1 for r in rows if r["score"] > intrusion["score"]),
            "intrusion_score": intrusion["score"], "intrusion_level": intrusion["level"],
            "max_benign_score": max((r["score"] for r in benign), default=None),
            "benign_high_or_critical": sum(1 for r in benign if r["level"] in ("high", "critical")),
            "every_nonzero_score_explained": all(r["contributors"] > 0 for r in rows if r["score"] > 0),
            "ranked": rows,
        }
        r = per[s]
        print(f"{s:16s} incidents {r['incidents']:2d} intrusion rank {r['intrusion_rank']} score {r['intrusion_score']}"
              f" ({r['intrusion_level']}) | max benign {r['max_benign_score']} | benign high/critical "
              f"{r['benign_high_or_critical']}", flush=True)
    pooled = {}
    for group in ("development", "held-out"):
        rows = [r for r in per.values() if r["role"] == group]
        pooled[group] = {"scenarios": len(rows),
                         "intrusion_ranked_first": f"{sum(1 for r in rows if r['intrusion_rank'] == 1)}/{len(rows)}",
                         "intrusion_high_or_critical": f"{sum(1 for r in rows if r['intrusion_level'] in ('high', 'critical'))}/{len(rows)}",
                         "benign_incidents_high_or_critical": sum(r["benign_high_or_critical"] for r in rows)}
    results = {"method": "contract section 8, half-life 24 h, weight 0.5 + 0.1 x criticality",
               "scenarios": per, "pooled": pooled}
    os.makedirs(os.path.dirname(os.path.abspath(args.results)), exist_ok=True)
    Path(args.results).write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for group, body in pooled.items():
        print(f"-- {group}: {json.dumps(body)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
