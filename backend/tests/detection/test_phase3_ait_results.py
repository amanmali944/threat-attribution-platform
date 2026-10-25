"""The committed AIT Phase 3 results must be internally consistent and reproducible."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from app.services.detection import contract as C

REPO = Path(__file__).resolve().parents[3]
SPEC = REPO / "data" / "specs" / "ait_russellmitchell.json"
DERIVED = REPO / "data" / "external" / "ait" / "derived" / "russellmitchell"
VARIANTS = {
    "as-is": ("phase3_ait_russellmitchell_asis.json", "russellmitchell-asis"),
    "clean-baseline": ("phase3_ait_russellmitchell_clean.json", "russellmitchell-clean"),
}


def load(variant):
    return json.loads((REPO / "data" / "evaluation" / VARIANTS[variant][0]).read_text(encoding="utf-8"))


@pytest.mark.parametrize("variant", VARIANTS)
def test_limits_and_protocol_travel_with_the_numbers(variant):
    results = load(variant)
    assert results["variant"] == variant
    text = " ".join(results["limits"])
    assert "ONE intrusion" in text and "decided on Org Y before AIT" in text and variant.split("-")[0] in text
    assert "rules-1.1.0 calibrated on train, gated on validation" in results["protocol"]


@pytest.mark.parametrize("variant", VARIANTS)
def test_operating_points_are_arithmetically_consistent(variant):
    results = load(variant)
    labels = results["data"]["test_windows_by_label"]
    days = results["data"]["test_days"]
    for task, body in results["tasks"].items():
        for name, op in body["operating_points"].items():
            tp, fp = op["positive_windows_flagged"], op["false_alarm_windows"]
            other = sum(op["alerts_on_excluded_windows"].values())
            assert op["positive_windows_total"] == labels[task], (task, name)
            assert op["recall"] == round(tp / labels[task], 4), (task, name)
            assert op["precision"] == (round(tp / (tp + fp), 4) if tp + fp else None), (task, name)
            assert abs(op["alerts_per_day"] - (tp + fp + other) / days) <= 0.1, (task, name)
            assert op["detected"] == (tp > 0), (task, name)


@pytest.mark.parametrize("variant", VARIANTS)
def test_incident_windows_and_stage_coverage_agree(variant):
    results = load(variant)
    windows = results["incident_windows"]
    assert len(windows) == results["data"]["test_windows_by_label"]["incident"] == 10
    assert all(w["stages"] for w in windows)                       # every incident window maps to a stage
    flagged_any = [bool(w["rules-1.1.0"]) for w in windows]
    assert sum(flagged_any) == results["tasks"]["incident"]["operating_points"]["rules-1.1.0:any"]["positive_windows_flagged"]
    for stage, cover in results["incident_stages"]["rules-1.1.0:any"].items():
        hits = [f for w, f in zip(windows, flagged_any) if stage in w["stages"]]
        assert cover == {"windows": len(hits), "flagged": sum(hits), "detected": any(hits)}, stage
    for w in windows:                                               # gated rules only ever add, never remove
        assert set(w["rules-1.1.0"]) <= set(w["rules-1.1.0_incl_gated"])
        assert set(w["rules-1.1.0"]).isdisjoint(results["rules-1.1.0"]["disabled"])


@pytest.mark.parametrize("variant", VARIANTS)
def test_gate_report_matches_disabled_rules(variant):
    rules = load(variant)["rules-1.1.0"]
    assert rules["gate"]["max_fire_rate"] == 0.005
    failed = {rid for rid, row in rules["gate"]["rules"].items() if not row["passed"]}
    assert failed == set(rules["disabled"])
    for rid, row in rules["gate"]["rules"].items():
        assert row["passed"] == (row["fire_rate"] <= 0.005), rid


@pytest.mark.parametrize("variant", VARIANTS)
def test_evaluation_reproduces_the_committed_results(variant, tmp_path):
    windows = REPO / "data" / "external" / "ait" / "windows" / VARIANTS[variant][1]
    if not (windows / "test.jsonl").exists() or not DERIVED.exists():
        pytest.skip(f"AIT windows {variant} not built")
    produced_with = load(variant)["isolation_forest"]["metadata"]["feature_set_version"]
    if produced_with != C.FEATURE_SET_VERSION:
        pytest.skip(f"committed results were produced with {produced_with}; the engine is now "
                    f"{C.FEATURE_SET_VERSION} (re-run at the commit that produced them)")
    out = tmp_path / "again.json"
    subprocess.run([sys.executable, "-I", str(REPO / "scripts" / "evaluate_ait.py"),
                    str(windows), str(SPEC), str(DERIVED), str(out)], check=True, capture_output=True)
    fresh, committed = json.loads(out.read_text(encoding="utf-8")), load(variant)
    for volatile in ("evaluated_at", "seconds"):
        fresh.pop(volatile), committed.pop(volatile)
    assert fresh == committed
