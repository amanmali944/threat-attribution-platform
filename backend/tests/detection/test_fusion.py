import pytest

from app.services.detection.features import FEATURE_KINDS, FEATURE_NAMES
from app.services.detection.fusion import (
    FUSION_INPUTS,
    FusionModel,
    choose_thresholds,
    decision_counts,
    fuse_alerts,
    fusion_inputs,
    group_weights,
    reliability,
    rules_first,
)


def window(label="background", etype="ip", rules=None, score=0.3, minute=0, entity="ent-ip-00000001",
           scenario="s1", **features):
    values = {n: (0 if FEATURE_KINDS[n] == "int" else 0.0) for n in FEATURE_NAMES}
    values["volume.event_count"] = 3
    for key, value in features.items():
        values[key.replace("__", ".")] = value
    hh, mm = divmod(minute, 60)
    return {"scenario": scenario, "entity_id": entity, "entity_type": etype, "label": label,
            "window_start": f"2022-01-24T{hh:02d}:{mm:02d}:00Z", "window_end": f"2022-01-24T{hh:02d}:{mm + 5:02d}:00Z"
            if mm + 5 < 60 else f"2022-01-24T{hh + 1:02d}:{mm + 5 - 60:02d}:00Z",
            "rules": rules or {}, "iforest_score": score, "ruleset": "rules-1.2.0", "features": values,
            "event_ids": [f"e-{entity}-{minute}"]}


def toy_corpus():
    """Two scenario runs; hostile windows carry a high rule and a high IF score, background does not."""
    out, groups = [], []
    for g in ("s1", "s2", "s3"):
        for i in range(60):
            out.append(window(score=(i % 10) / 20, minute=i, entity=f"ent-ip-{g}{i:05d}", scenario=g))
            groups.append(g)
        for i in range(6):
            out.append(window("incident", rules={"RULE-PRIV-005": "high"}, score=0.97, minute=i,
                              entity=f"ent-host-{g}{i:04d}", etype="host", scenario=g,
                              privilege__privileged_ops=3))
            groups.append(g)
    return out, groups


def test_fusion_inputs_order_and_missing_model():
    row = fusion_inputs(window(rules={"RULE-PRIV-005": "high", "RULE-IDN-002": "medium"}, score=None,
                               volume__event_count=0, peer__volume_zscore=-3.0))
    assert len(row) == len(FUSION_INPUTS) == 16
    named = dict(zip(FUSION_INPUTS, row))
    assert named["rules.high"] == 1 and named["rules.medium"] == 1 and named["rules.count"] == 2
    assert named["iforest.score"] == 0.0 and named["iforest.missing"] == 1.0      # no model is not "normal"
    assert named["peer.volume_z"] < 0 and named["type.ip"] == 1 and named["type.host"] == 0


def test_reliability_of_perfect_and_overconfident_predictions():
    assert reliability([0, 0, 1, 1], [0.0, 0.0, 1.0, 1.0])["ece"] == 0.0
    over = reliability([0, 0, 0, 1], [0.95, 0.95, 0.95, 0.95])
    assert over["ece"] == pytest.approx(0.7) and over["brier"] == pytest.approx((3 * 0.9025 + 0.0025) / 4)
    assert reliability([], [])["ece"] is None


def test_choose_thresholds_meets_precision_and_recall_targets():
    y = [0, 0, 0, 0, 1, 0, 1, 1]
    p = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.8, 0.9]
    t = choose_thresholds(y, p, target_precision=0.75, review_recall=1.0)
    assert t["tau_alert"] == 0.5 and t["alert_reachable"]          # 3 hostile of 4 flagged at >= 0.5
    assert t["tau_review"] == 0.5                                   # all hostile kept at >= 0.5
    strict = choose_thresholds(y, p, target_precision=1.0, review_recall=1.0)
    assert strict["tau_alert"] == 0.8 and strict["tau_review"] == 0.5


def test_unreachable_precision_sends_everything_to_review():
    t = choose_thresholds([0, 1, 0, 1], [0.5, 0.5, 0.5, 0.5], target_precision=0.9, review_recall=0.9)
    assert not t["alert_reachable"] and t["tau_alert"] > 1.0 and t["tau_review"] == 0.5


def test_fusion_learns_separable_signal_calibrates_and_decides():
    windows, groups = toy_corpus()
    model = FusionModel().fit(windows, groups)
    assert model.training["calibration_scheme"] == "leave-one-scenario-out" and model.training["folds"] == 3
    hostile = window("incident", etype="host", rules={"RULE-PRIV-005": "high"}, score=0.97, privilege__privileged_ops=3)
    quiet = window(score=0.2)
    c_hostile, c_quiet = model.confidence([hostile, quiet])
    assert c_hostile > 0.9 and c_quiet < 0.1
    assert model.decide([c_hostile, c_quiet]) == ["alert", "suppress"]
    top = model.explain(hostile)
    assert len(top) == 3 and abs(top[0]["contribution"]) >= abs(top[-1]["contribution"])
    assert model.metadata()["coefficients"]["rules.high"] > 0


def test_fusion_is_deterministic_and_order_independent():
    windows, groups = toy_corpus()
    a = FusionModel().fit(windows, groups)
    b = FusionModel().fit(list(reversed(windows)), list(reversed(groups)))
    probe = [window(score=s / 10, minute=s) for s in range(10)]
    assert a.confidence(probe) == b.confidence(probe) and a.thresholds == b.thresholds


def test_fusion_refuses_one_class_and_falls_back_to_kfold_for_one_scenario():
    windows, groups = toy_corpus()
    with pytest.raises(ValueError, match="hostile and background"):
        FusionModel().fit([w for w in windows if w["label"] == "background"], ["s1"] * 180)
    single = [(w, g) for w, g in zip(windows, groups) if g == "s1"]
    model = FusionModel().fit([w for w, _ in single], [g for _, g in single])
    assert model.training["calibration_scheme"].startswith("stratified k-fold")


def test_challenger_model_fits_without_explanations():
    windows, groups = toy_corpus()
    model = FusionModel(model="hgb").fit(windows, groups)
    assert model.explain(windows[0]) == [] and model.coefficients() == {}
    with pytest.raises(ValueError, match="unknown fusion model"):
        FusionModel(model="magic").fit(windows, groups)


def test_fuse_alerts_folds_repeats_within_the_suppression_window():
    e = "ent-host-00000001"
    ws = [window("incident", etype="host", entity=e, minute=m, rules={"RULE-PRIV-004": "high"}) for m in (0, 5, 10)]
    ws.append(window("incident", etype="host", entity=e, minute=90, rules={"RULE-APP-001": "low"}))   # 75 min later
    ws.append(window(entity="ent-ip-00000009", minute=0))                                             # suppressed
    fused = fuse_alerts(ws, [0.9, 0.95, 0.7, 0.6, 0.1], ["alert", "alert", "review", "review", "suppress"],
                        suppression_seconds=1800, tenant_id="t1")
    assert len(fused) == 2
    first, second = fused
    assert (first["window_start"], first["window_end"]) == ("2022-01-24T00:00:00Z", "2022-01-24T00:15:00Z")
    assert first["suppressed_duplicates"] == 2 and first["decision"] == "alert" and first["confidence"] == 0.95
    assert first["technique"] == "privilege_escalation" and first["severity"] == "high"
    assert first["detectors"] == ["rules", "isolation_forest"] and len(first["member_alert_ids"]) == 3
    assert second["suppressed_duplicates"] == 0 and second["decision"] == "review"
    assert second["technique"] == "reconnaissance"
    assert first["fused_alert_id"].startswith("fal-") and first["calibration_version"] == "cal-1.0.0"
    again = fuse_alerts(ws, [0.9, 0.95, 0.7, 0.6, 0.1], ["alert", "alert", "review", "review", "suppress"])
    assert [a["fused_alert_id"] for a in again] == [a["fused_alert_id"] for a in fused]


def test_decide_maps_confidence_to_alert_review_suppress():
    model = FusionModel()
    model.thresholds = {"tau_alert": 0.8, "tau_review": 0.3}
    assert model.decide([0.9, 0.8, 0.5, 0.3, 0.29, 0.0]) == ["alert", "alert", "review", "review", "suppress", "suppress"]


def test_rules_first_never_silences_a_rule():
    ws = [window(rules={"RULE-PRIV-005": "high"}), window(rules={"RULE-APP-001": "low"}),
          window(rules={"RULE-APP-001": "low"}), window(), window()]
    fusion = ["suppress", "suppress", "alert", "review", "suppress"]
    assert rules_first(ws, fusion) == ["alert", "review", "alert", "review", "suppress"]


def test_group_weights_equalise_each_scenario_label_group():
    labels = ["background"] * 6 + ["exfiltration"] * 3 + ["incident"]
    weights = group_weights(labels, ["s1"] * 10)
    totals = {l: round(float(sum(w for w, x in zip(weights, labels) if x == l)), 6) for l in set(labels)}
    assert len(set(totals.values())) == 1                       # every group carries the same total weight
    assert round(float(weights.mean()), 6) == 1.0


def test_fuse_alerts_needs_aligned_inputs_and_counts_decisions():
    with pytest.raises(ValueError, match="one confidence"):
        fuse_alerts([window()], [0.5], [])
    assert decision_counts(["alert", "review", "review"]) == {"alert": 1, "review": 2, "suppress": 0}
