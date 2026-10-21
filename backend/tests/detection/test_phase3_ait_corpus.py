"""The committed 8-scenario AIT summary (scripts/summarize_ait.py) must be internally consistent."""
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
DEVELOPMENT = {"russellmitchell", "fox"}
HELD_OUT = {"harrison", "santos", "shaw", "wardbeck", "wheeler", "wilson"}


@pytest.fixture(scope="module", params=["asis", "clean"])
def summary(request):
    return json.loads((REPO / "data" / "evaluation" / f"phase3_ait_corpus_{request.param}.json").read_text(encoding="utf-8"))


def test_all_eight_scenarios_with_the_right_roles_and_frozen_versions(summary):
    roles = {s: m["role"] for s, m in summary["scenarios"].items()}
    assert set(roles) == DEVELOPMENT | HELD_OUT
    assert {s for s, r in roles.items() if r == "development"} == DEVELOPMENT
    for name, meta in summary["scenarios"].items():
        assert meta["versions"] == {"features": "fs-1.2.0", "iforest": "iforest-1.1.0"}, name


def test_pooled_counts_are_sums_of_the_scenarios(summary):
    for decision, body in summary["decisions"].items():
        per = body["per_scenario"]
        for group, names in (("development", DEVELOPMENT), ("held-out", HELD_OUT)):
            pooled = body["pooled"][group]
            assert pooled["scenarios"] == len(names)
            for key in ("incident_windows_flagged", "incident_windows_total", "false_alarm_windows"):
                assert pooled[key] == sum(per[s][key] for s in names), (decision, group, key)
            assert pooled["incidents_detected"] == sum(1 for s in names if per[s]["incident_windows_flagged"]), decision
            days = sum(summary["scenarios"][s]["test_days"] for s in names)
            assert pooled["false_alarms_per_day"] == round(pooled["false_alarm_windows"] / days, 2), decision


def test_every_scenario_counts_match_its_test_windows(summary):
    for name, meta in summary["scenarios"].items():
        row = summary["decisions"]["rules-1.2.0:any"]["per_scenario"][name]
        assert row["incident_windows_total"] == meta["test_windows_by_label"]["incident"], name
        assert ("exfiltration_windows_total" in row) == ("exfiltration" in meta["test_windows_by_label"]), name


def test_no_addresses_in_the_committed_summary():
    import re
    for variant in ("asis", "clean"):
        text = (REPO / "data" / "evaluation" / f"phase3_ait_corpus_{variant}.json").read_text(encoding="utf-8")
        assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)
