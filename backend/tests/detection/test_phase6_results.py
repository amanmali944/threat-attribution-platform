"""The committed Phase 6 attribution results must be consistent and free of identifiers."""
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
PATH = REPO / "data" / "evaluation" / "phase6_attribution.json"
RESULTS = json.loads(PATH.read_text(encoding="utf-8"))


def test_both_methods_scored_on_all_scenarios_and_the_pre_registration_is_recorded():
    assert RESULTS["methods"] == ["graph-attribution-1.0.0", "graph-attribution-1.1.0"]
    assert RESULTS["pre_registered"] == "graph-attribution-1.0.0" and "graph-attribution-1.1.0" in RESULTS["post_hoc"]
    assert len(RESULTS["scenarios"]) == 8
    for name, row in RESULTS["scenarios"].items():
        assert set(row["methods"]) == set(RESULTS["methods"]), name


def test_pooled_counts_match_the_scenarios():
    for method in RESULTS["methods"]:
        for group in ("development", "held-out"):
            rows = [r["methods"][method] for r in RESULTS["scenarios"].values() if r["role"] == group]
            pooled = RESULTS["pooled"][method][group]
            for key in ("entry_account_correct", "entry_event_correct", "privileged_host_reached", "dwell_exact"):
                assert pooled[key] == f"{sum(1 for r in rows if r[key])}/{len(rows)}", (method, group, key)


def test_every_path_is_valid_and_reached_precision_is_reported():
    for name, row in RESULTS["scenarios"].items():
        for method, r in row["methods"].items():
            assert r["path_cites_incident_events"] and r["path_time_ordered"], (name, method)
            assert r["reached_precision"] is None or 0 <= r["reached_precision"] <= 1


def test_no_identifiers_in_the_committed_file():
    text = PATH.read_text(encoding="utf-8")
    assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)
    assert '"identifier"' not in text and "ent-" not in text
