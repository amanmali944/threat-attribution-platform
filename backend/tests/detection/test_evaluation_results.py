"""Phase 8: data/evaluation/evaluation_results.json (contract section 9) from scripts/evaluate.py."""
import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location("evaluate_harness", REPO / "scripts" / "evaluate.py")
harness = importlib.util.module_from_spec(_spec)
sys.modules["evaluate_harness"] = harness
_spec.loader.exec_module(harness)
RESULTS = json.loads((REPO / "data" / "evaluation" / "evaluation_results.json").read_text(encoding="utf-8"))

CONTRACT_KEYS = {"schema_version", "model_version", "corpus_seed", "evaluation_timestamp", "overall_precision",
                 "overall_recall", "overall_f1", "per_class_metrics", "per_detector_metrics", "calibration",
                 "abstention_rate", "alerts_per_analyst_day", "incident_consolidation_ratio", "attribution",
                 "detection_latency_seconds"}


def test_artefact_has_every_contract_key_and_no_accuracy():
    assert CONTRACT_KEYS <= set(RESULTS)
    assert not any("accuracy" == k or k.endswith("_accuracy") and "entry" not in k for k in RESULTS)
    assert set(RESULTS["calibration"]) >= {"brier_score", "expected_calibration_error", "max_calibration_error",
                                           "auc_roc", "reliability_bins"}
    assert set(RESULTS["alerts_per_analyst_day"]) >= {"raw_detector_alerts", "after_fusion", "incidents"}
    assert set(RESULTS["attribution"]) >= {"entry_point_accuracy", "path_precision", "path_recall", "reached_assets_jaccard"}
    assert set(RESULTS["detection_latency_seconds"]) >= {"median", "p95"}


def test_values_are_in_range_and_f1_is_consistent():
    for key in ("overall_precision", "overall_recall", "overall_f1", "abstention_rate", "incident_consolidation_ratio"):
        assert RESULTS[key] is not None and RESULTS[key] >= 0, key
    p, r = RESULTS["overall_precision"], RESULTS["overall_recall"]
    assert abs(RESULTS["overall_f1"] - 2 * p * r / (p + r)) < 1e-3
    for name, m in RESULTS["per_detector_metrics"].items():
        assert 0 <= m["precision"] <= 1 and 0 <= m["recall"] <= 1, name
    bins = RESULTS["calibration"]["reliability_bins"]
    assert sum(b["count"] for b in bins) == RESULTS["calibration"]["windows"] > 0
    assert RESULTS["alerts_per_analyst_day"]["after_fusion"] <= RESULTS["alerts_per_analyst_day"]["raw_detector_alerts"]
    assert RESULTS["alerts_per_analyst_day"]["incidents"] <= RESULTS["alerts_per_analyst_day"]["after_fusion"]


def test_figures_come_from_the_stage_outputs():
    fusion = json.loads((REPO / "data" / "evaluation" / "phase4_fusion_loso_logreg.json").read_text(encoding="utf-8"))
    pipeline = fusion["pooled"]["held-out"]["operating_points"]["pipeline alert|review"]
    assert RESULTS["overall_recall"] == round(pipeline["recall"], 4)
    assert RESULTS["per_detector_metrics"]["rules"]["support"] == pipeline["hostile_total"]
    corr = json.loads((REPO / "data" / "evaluation" / "phase5_correlation.json").read_text(encoding="utf-8"))
    assert RESULTS["incident_consolidation_ratio"] == corr["pooled"]["held-out"]["consolidation_ratio"]
    assert RESULTS["attribution"]["entry_point_accuracy_pre_registered"] <= RESULTS["attribution"]["entry_point_accuracy"]
    assert RESULTS["model_version"] == "pipeline-1.0.0" and RESULTS["components"]["rules"] == "rules-1.2.0"


def test_assembly_is_deterministic():
    a = harness.assemble("2026-10-21T00:00:00Z")
    b = harness.assemble("2026-10-21T00:00:00Z")
    assert a == b
    committed = dict(RESULTS)
    fresh = dict(a)
    committed.pop("evaluation_timestamp"), fresh.pop("evaluation_timestamp")
    assert fresh == committed
