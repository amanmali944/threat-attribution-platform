"""The committed Phase 4 fusion results (leave-one-scenario-out) and calibration artefact."""
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
EVAL = REPO / "data" / "evaluation"
ALL = ["russellmitchell", "fox", "harrison", "santos", "shaw", "wardbeck", "wheeler", "wilson"]


@pytest.fixture(scope="module", params=["logreg", "hgb"])
def results(request):
    return json.loads((EVAL / f"phase4_fusion_loso_{request.param}.json").read_text(encoding="utf-8"))


def test_every_fold_trains_on_the_other_seven(results):
    assert results["scenarios"] == ALL and set(results["folds"]) == set(ALL)
    for held_out, fold in results["folds"].items():
        assert fold["train_scenarios"] == sorted(s for s in ALL if s != held_out), held_out
        assert held_out not in fold["model"]["training"]["groups"], held_out
        assert fold["model"]["training"]["calibration_scheme"] == "leave-one-scenario-out"


def test_pooled_operating_points_are_sums_of_folds(results):
    for group, names in (("development", ["russellmitchell", "fox"]),
                         ("held-out", [s for s in ALL if s not in ("russellmitchell", "fox")])):
        pooled = results["pooled"][group]
        assert pooled["folds"] == len(names)
        for op, body in pooled["operating_points"].items():
            for key in ("hostile_flagged", "hostile_total", "false_alarms"):
                assert body[key] == sum(results["folds"][s]["operating_points"][op][key] for s in names), (group, op)


def test_pipeline_never_flags_less_than_rules_alone(results):
    for name, fold in results["folds"].items():
        ops = fold["operating_points"]
        assert ops["pipeline alert|review"]["hostile_flagged"] >= ops["rules any"]["hostile_flagged"], name
        assert ops["pipeline alert"]["hostile_flagged"] >= ops["rules high"]["hostile_flagged"], name


def test_calibration_artefact():
    art = json.loads((EVAL / "calibration.json").read_text(encoding="utf-8"))
    assert art["fusion_version"] == "fusion-1.0.0" and art["calibration_version"] == "cal-1.0.0"
    assert art["trained_on"] == ALL and art["training"]["folds"] == 8
    t = art["thresholds"]
    assert 0.0 <= t["tau_review"] <= t["tau_alert"] and t["target_precision"] == 0.8
    assert art["detector_versions"] == ["rules-1.2.0 / iforest-1.1.0 / fs-1.2.0"]
    assert len(art["coefficients"]) == len(art["inputs"]) == 16
