"""The committed Phase 5 correlation results must be internally consistent."""
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
RESULTS = json.loads((REPO / "data" / "evaluation" / "phase5_correlation.json").read_text(encoding="utf-8"))
DEVELOPMENT = {"russellmitchell", "fox"}


def test_every_scenario_accounts_for_all_fused_alerts():
    assert len(RESULTS["scenarios"]) == 8 and RESULTS["method"] == "entity-time-graph-1.0.0"
    for name, s in RESULTS["scenarios"].items():
        table = s["incident_table"]
        assert len(table) == s["incidents"], name
        assert sum(r["alerts"] for r in table) == s["fused_alerts"], name          # every alert in exactly one incident
        assert s["intrusion_incidents"] == sum(1 for r in table if r["labels"].get("incident")), name
        assert s["benign_only_incidents"] == sum(1 for r in table if set(r["labels"]) == {"background"}), name
        assert s["role"] == ("development" if name in DEVELOPMENT else "held-out"), name


def test_pooled_figures_match_the_scenarios():
    for group in ("development", "held-out"):
        names = [n for n, s in RESULTS["scenarios"].items() if s["role"] == group]
        pooled = RESULTS["pooled"][group]
        assert pooled["scenarios"] == len(names)
        assert pooled["intrusion_in_one_incident"] == sum(1 for n in names if RESULTS["scenarios"][n]["intrusion_incidents"] == 1)
        mains = [RESULTS["scenarios"][n]["main_intrusion_incident"] for n in names]
        assert pooled["benign_alerts_merged_into_main"] == sum(m["benign_alerts_merged"] for m in mains)
        assert pooled["main_incident_all_4_stages"] == sum(1 for m in mains if m["all_stages_present"])
