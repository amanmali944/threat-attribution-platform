"""The committed Phase 3 results file must be internally consistent and reproducible."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from app.services.detection import contract as C

REPO = Path(__file__).resolve().parents[3]
RESULTS = REPO / "data" / "evaluation" / "phase3_org_y.json"
WINDOWS = REPO / "data" / "external" / "web_server_logs" / "derived" / "org-y" / "windows"
SPEC = REPO / "data" / "specs" / "org_y_incident.json"


@pytest.fixture(scope="module")
def results():
    return json.loads(RESULTS.read_text(encoding="utf-8"))


def _operating_points(results):
    yield "rules.any_rule", results["rules"]["any_rule"]
    yield "rules.high_severity_rules", results["rules"]["high_severity_rules"]
    yield "high_rules_or_iforest_0999", results["high_rules_or_iforest_0999"]
    for threshold, op in results["isolation_forest"]["operating_points"].items():
        yield f"iforest@{threshold}", op


def test_limits_travel_with_the_numbers(results):
    text = " ".join(results["limits"])
    assert "ONE incident" in text and "optimistic" in text and "UTC" in text
    assert results["protocol"].startswith("zero-shot")


def test_operating_points_are_arithmetically_consistent(results):
    days = results["data"]["test_days"]
    for name, op in _operating_points(results):
        tp, fp, unk = op["incident_windows_flagged"], op["false_alarm_windows"], op["alerts_on_unknown_windows"]
        assert op["incident_windows_total"] == results["data"]["test_incident_windows"], name
        assert op["recall"] == round(tp / op["incident_windows_total"], 4), name
        assert op["precision"] == (round(tp / (tp + fp), 4) if tp + fp else None), name
        assert abs(op["alerts_per_day"] - (tp + fp + unk) / days) <= 0.1, name
        assert op["incident_detected"] == (tp > 0), name


def test_ranking_metrics_are_valid_and_beat_random(results):
    random_ap = results["baselines"]["random_scoring_expected_average_precision"]
    ranking = results["isolation_forest"]["ranking"]
    assert 0 <= ranking["roc_auc"] <= 1 and 0 <= ranking["average_precision"] <= 1
    assert ranking["positives"] == results["data"]["test_incident_windows"]
    assert ranking["average_precision"] > random_ap          # quality floor, not a claim of quality


def test_rule_fire_counts_add_up(results):
    per_rule = results["rules"]["per_rule"]
    assert len(per_rule) == 9
    for rule_id, row in per_rule.items():
        assert set(row["test_fires"]) == {"incident", "background", "unknown"}, rule_id
    assert results["rules"]["thresholds"]["RULE-PRIV-001"]["host"] >= 5      # never below the floor


@pytest.mark.skipif(not (WINDOWS / "test.jsonl").exists(), reason="Org Y windows not built")
def test_evaluation_reproduces_the_committed_results(tmp_path, results):
    produced_with = results["isolation_forest"]["metadata"]["feature_set_version"]
    if produced_with != C.FEATURE_SET_VERSION:
        pytest.skip(f"committed results were produced with {produced_with}; the engine is now "
                    f"{C.FEATURE_SET_VERSION} (re-run at the commit that produced them)")
    out = tmp_path / "again.json"
    subprocess.run([sys.executable, "-I", str(REPO / "scripts" / "evaluate_org_y.py"),
                    str(WINDOWS), str(SPEC), str(out)], check=True, capture_output=True)
    fresh = json.loads(out.read_text(encoding="utf-8"))
    committed = json.loads(RESULTS.read_text(encoding="utf-8"))
    for volatile in ("evaluated_at", "seconds"):
        fresh.pop(volatile), committed.pop(volatile)
    assert fresh == committed
