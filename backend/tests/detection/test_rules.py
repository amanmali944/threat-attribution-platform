import pytest

from app.services.detection.envelope import validate_alert
from app.services.detection.features import FEATURE_KINDS, FEATURE_NAMES
from app.services.detection.rules import (
    CALIBRATED,
    DEFAULT_RULES,
    Condition,
    RuleEngine,
    nearest_rank_quantile,
)


def vec(entity_type="user", window_start="2026-10-05T10:00:00Z", entity_id=None, **features):
    values = {n: (0 if FEATURE_KINDS[n] == "int" else 0.0) for n in FEATURE_NAMES}
    for key, value in features.items():
        values[key.replace("__", ".")] = value
    return {
        "schema_version": "1.0", "feature_set_version": "fs-1.1.0", "tenant_id": "t1",
        "entity_id": entity_id or f"ent-{entity_type}-00000001", "entity_type": entity_type,
        "window_start": window_start, "window_end": "2026-10-05T10:05:00Z", "window_seconds": 300,
        "event_ids": ["e1", "e2"], "features": values,
    }


def background():
    """Background the calibrated rules learn from: hosts ran 0..19 privileged ops per window."""
    hosts = [vec("host", privilege__privileged_ops=i, entity_id=f"ent-host-{i:08d}") for i in range(20)]
    users = [vec("user", privilege__privileged_ops=i % 3, volume__rows_read=float(i), entity_id=f"ent-user-{i:08d}")
             for i in range(50)]
    return hosts + users


@pytest.fixture
def engine():
    return RuleEngine().calibrate(background())


def fired(engine, vector):
    return [a["rule_id"] for a in engine.evaluate(vector)]


# Every rule: one window that must fire and one near-miss that must not.
CASES = [
    ("RULE-IDN-001", "user",
     dict(volume__login_count=12, failure__login_failure_rate=0.95, failure__max_consecutive_failures=12),
     dict(volume__login_count=12, failure__login_failure_rate=0.95, failure__max_consecutive_failures=9)),
    ("RULE-IDN-002", "ip",
     dict(diversity__distinct_accounts_from_ip=6, volume__login_count=6, failure__login_failure_rate=1.0),
     dict(diversity__distinct_accounts_from_ip=4, volume__login_count=6, failure__login_failure_rate=1.0)),
    ("RULE-IDN-003", "user",
     dict(volume__login_success_count=1, novelty__new_source_ip=1),
     dict(volume__login_success_count=1, novelty__new_source_ip=0)),
    ("RULE-IDN-004", "ip",
     dict(volume__login_success_count=1, failure__max_consecutive_failures=5),
     dict(volume__login_success_count=0, failure__max_consecutive_failures=50)),
    ("RULE-PRIV-001", "host",
     dict(privilege__privileged_ops=24),                      # must exceed background max 19 x 1.25 = 23.75
     dict(privilege__privileged_ops=23)),
    ("RULE-PRIV-002", "user",
     dict(privilege__role_changes=1),
     dict(privilege__role_changes=0)),
    ("RULE-PRIV-003", "host",
     dict(timing__off_hours=1, privilege__privileged_ops=1),
     dict(timing__off_hours=0, privilege__privileged_ops=5)),
    ("RULE-APP-001", "ip",
     dict(volume__event_count=25, failure__http_error_rate=0.6),
     dict(volume__event_count=19, failure__http_error_rate=0.9)),
    ("RULE-DB-001", "user",
     dict(volume__rows_read=20000.0),                         # background tiny, so the floor (10000) applies
     dict(volume__rows_read=9000.0)),
]


def test_every_default_rule_has_a_case():
    assert sorted(c[0] for c in CASES) == sorted(r.rule_id for r in DEFAULT_RULES)


@pytest.mark.parametrize("rule_id, etype, passing, failing", CASES, ids=[c[0] for c in CASES])
def test_rule_fires_and_near_miss_does_not(engine, rule_id, etype, passing, failing):
    assert rule_id in fired(engine, vec(etype, **passing))
    assert rule_id not in fired(engine, vec(etype, **failing))


def test_rules_only_apply_to_their_entity_types(engine):
    window = dict(volume__login_success_count=1, novelty__new_source_ip=1)     # IDN-003 is user-only
    assert "RULE-IDN-003" in fired(engine, vec("user", **window))
    assert "RULE-IDN-003" not in fired(engine, vec("ip", **window))


def test_quiet_window_fires_nothing(engine):
    assert engine.evaluate(vec("user")) == [] and engine.evaluate(vec("host")) == []


# ------------------------------------------------------------------ calibration


def test_nearest_rank_quantile():
    data = list(range(1, 11))
    assert nearest_rank_quantile(data, 0.9) == 9
    assert nearest_rank_quantile(data, 1.0) == 10
    assert nearest_rank_quantile(data, 0.001) == 1
    with pytest.raises(ValueError):
        nearest_rank_quantile([], 0.5)


def test_v100_threshold_is_max_of_floor_and_background_quantile():
    engine = RuleEngine(ruleset="rules-1.0.0").calibrate(background())
    assert engine.thresholds["RULE-PRIV-001"]["host"] == 19        # background max beats the floor of 5
    assert engine.thresholds["RULE-PRIV-001"]["user"] == 5         # background max 2 < floor 5
    assert engine.thresholds["RULE-DB-001"]["user"] == 10000       # floor
    assert engine.calibration["background_windows_by_type"] == {"host": 20, "user": 50}


def test_v110_bound_is_background_max_plus_margin_and_strict(engine):
    assert engine.ruleset == "rules-1.1.0"
    assert engine.thresholds["RULE-PRIV-001"]["host"] == pytest.approx(23.75)   # max 19 x 1.25
    assert engine.threshold_ops["RULE-PRIV-001"]["host"] == ">"
    assert engine.thresholds["RULE-PRIV-001"]["user"] == 5                      # 2 x 1.25 < floor 5
    assert engine.threshold_ops["RULE-PRIV-001"]["user"] == ">="                # the floor stays inclusive
    assert "RULE-PRIV-001" in fired(engine, vec("user", privilege__privileged_ops=5))


def test_v110_no_longer_fires_on_a_tie_with_the_background_maximum():
    # The Org Y flaw: a window equal to the routine maximum fired every routine hour under 1.0.0.
    tie = vec("host", privilege__privileged_ops=19)
    assert "RULE-PRIV-001" in fired(RuleEngine(ruleset="rules-1.0.0").calibrate(background()), tie)
    assert "RULE-PRIV-001" not in fired(RuleEngine().calibrate(background()), tie)


@pytest.mark.parametrize("ruleset", ["rules-1.0.0", "rules-1.1.0"])
def test_a_type_with_no_background_falls_back_to_the_floor(ruleset):
    engine = RuleEngine(ruleset=ruleset).calibrate([])
    assert engine.thresholds["RULE-PRIV-001"] == {"user": 5, "host": 5}
    assert "RULE-PRIV-001" in fired(engine, vec("host", privilege__privileged_ops=5))


def test_unknown_ruleset_is_rejected():
    with pytest.raises(ValueError, match="unknown rule set"):
        RuleEngine(ruleset="rules-9.9.9")


# ------------------------------------------------------------------ validation gate


def noisy_validation():
    """200 user windows; 2 of them (1%) look like a brute-force burst, nothing else fires."""
    quiet = [vec("user", entity_id=f"ent-user-{i:08d}") for i in range(198)]
    burst = dict(volume__login_count=12, failure__login_failure_rate=1.0, failure__max_consecutive_failures=12)
    return quiet + [vec("user", entity_id=f"ent-user-b{i:07d}", **burst) for i in range(2)]


def test_gate_disables_a_rule_above_the_budget_and_keeps_the_rest(engine):
    engine.gate(noisy_validation())
    assert set(engine.disabled) == {"RULE-IDN-001"}
    assert "2/200" in engine.disabled["RULE-IDN-001"]
    row = engine.gate_report["rules"]["RULE-IDN-001"]
    assert row == {"windows": 200, "fires": 2, "fire_rate": 0.01, "passed": False}
    assert engine.gate_report["max_fire_rate"] == 0.005
    assert engine.gate_report["rules"]["RULE-PRIV-001"]["passed"] is True
    assert engine.gate_report["rules"]["RULE-APP-001"]["windows"] == 0          # ip-only rule, no ip windows


def test_disabled_rules_stay_silent_unless_asked(engine):
    engine.gate(noisy_validation())
    burst = vec("user", volume__login_count=12, failure__login_failure_rate=1.0, failure__max_consecutive_failures=12)
    assert "RULE-IDN-001" not in fired(engine, burst)
    assert "RULE-IDN-001" in [a["rule_id"] for a in engine.evaluate(burst, include_disabled=True)]


def test_gate_budget_can_be_widened_and_recalibration_clears_it(engine):
    engine.gate(noisy_validation(), max_fire_rate=0.02)
    assert engine.disabled == {}
    engine.gate(noisy_validation())
    assert engine.disabled
    engine.calibrate(background())
    assert engine.disabled == {} and engine.gate_report == {}


def test_v100_has_no_gate_by_default():
    engine = RuleEngine(ruleset="rules-1.0.0").calibrate(background())
    with pytest.raises(ValueError, match="no validation gate"):
        engine.gate(noisy_validation())


def test_calibrated_rules_refuse_to_run_uncalibrated():
    with pytest.raises(RuntimeError, match="calibrate"):
        RuleEngine().evaluate(vec("host", privilege__privileged_ops=100))


def test_invalid_condition_is_rejected():
    with pytest.raises(ValueError, match="unknown feature"):
        Condition("not.a.feature", ">=", 1)
    with pytest.raises(ValueError, match="unknown operator"):
        Condition("volume.event_count", "~", 1)


# ------------------------------------------------------------------ alert envelopes


def test_rule_alerts_are_valid_envelopes_with_evidence(engine):
    alerts = engine.evaluate(vec("host", privilege__privileged_ops=40, timing__off_hours=1))
    assert {a["rule_id"] for a in alerts} == {"RULE-PRIV-001", "RULE-PRIV-003"}
    for alert in alerts:
        assert validate_alert(alert) == []
        assert alert["detector"] == "rules" and alert["detector_version"] == "rules-1.1.0"
        assert alert["score"] == 1.0 and alert["confidence"] is None
        assert alert["event_ids"] == ["e1", "e2"] and alert["observed_at"] == "2026-10-05T10:05:00Z"
    burst = next(a for a in alerts if a["rule_id"] == "RULE-PRIV-001")
    assert burst["evidence"] == [{"feature": "privilege.privileged_ops", "value": 40, "op": ">", "threshold": 23.75}]
    assert "privilege.privileged_ops=40" in burst["description"]


def test_alert_ids_are_deterministic_and_distinct(engine):
    a = engine.evaluate(vec("host", privilege__privileged_ops=40))[0]["alert_id"]
    b = engine.evaluate(vec("host", privilege__privileged_ops=40))[0]["alert_id"]
    c = engine.evaluate(vec("host", privilege__privileged_ops=40, window_start="2026-10-05T10:05:00Z"))[0]["alert_id"]
    assert a == b != c and a.startswith("alt-rules-")


def test_engine_round_trips_and_refuses_a_different_feature_set(engine):
    engine.gate(noisy_validation())
    restored = RuleEngine.from_dict(engine.to_dict())
    window = vec("host", privilege__privileged_ops=40)
    assert restored.evaluate(window) == engine.evaluate(window)
    assert (restored.ruleset, restored.threshold_ops, restored.disabled) == (engine.ruleset, engine.threshold_ops,
                                                                            engine.disabled)
    tie = vec("host", privilege__privileged_ops=19)
    old = RuleEngine(ruleset="rules-1.0.0").calibrate(background())
    assert RuleEngine.from_dict(old.to_dict()).evaluate(tie) == old.evaluate(tie) != []
    stale = engine.to_dict()
    stale["feature_set_version"] = "fs-1.0.0"
    with pytest.raises(ValueError, match="recalibrate"):
        RuleEngine.from_dict(stale)


def test_validate_alert_catches_contract_violations(engine):
    good = engine.evaluate(vec("host", privilege__privileged_ops=40))[0]
    assert validate_alert(good) == []
    assert "unknown detector: magic" in validate_alert(dict(good, detector="magic"))
    assert "unknown technique: vibes" in validate_alert(dict(good, technique="vibes"))
    assert "score must be a number in [0, 1]" in validate_alert(dict(good, score=1.5))
    assert "confidence must be null at detector stage" in validate_alert(dict(good, confidence=0.9))
    assert "evidence must be a non-empty list" in validate_alert(dict(good, evidence=[]))
    missing = dict(good)
    del missing["entity_id"]
    assert validate_alert(missing) == ["missing field: entity_id"]
