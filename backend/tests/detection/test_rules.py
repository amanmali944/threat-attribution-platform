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
     dict(privilege__privileged_ops=19),                      # threshold = background max (19)
     dict(privilege__privileged_ops=18)),
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


def test_calibrated_threshold_is_max_of_floor_and_background_quantile(engine):
    assert engine.thresholds["RULE-PRIV-001"]["host"] == 19        # background max beats the floor of 5
    assert engine.thresholds["RULE-PRIV-001"]["user"] == 5         # background max 2 < floor 5
    assert engine.thresholds["RULE-DB-001"]["user"] == 10000       # floor
    assert engine.calibration["background_windows_by_type"] == {"host": 20, "user": 50}


def test_a_type_with_no_background_falls_back_to_the_floor():
    engine = RuleEngine().calibrate([])
    assert engine.thresholds["RULE-PRIV-001"] == {"user": 5, "host": 5}


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
        assert alert["detector"] == "rules" and alert["detector_version"] == "rules-1.0.0"
        assert alert["score"] == 1.0 and alert["confidence"] is None
        assert alert["event_ids"] == ["e1", "e2"] and alert["observed_at"] == "2026-10-05T10:05:00Z"
    burst = next(a for a in alerts if a["rule_id"] == "RULE-PRIV-001")
    assert burst["evidence"] == [{"feature": "privilege.privileged_ops", "value": 40, "op": ">=", "threshold": 19.0}]
    assert "privilege.privileged_ops=40" in burst["description"]


def test_alert_ids_are_deterministic_and_distinct(engine):
    a = engine.evaluate(vec("host", privilege__privileged_ops=40))[0]["alert_id"]
    b = engine.evaluate(vec("host", privilege__privileged_ops=40))[0]["alert_id"]
    c = engine.evaluate(vec("host", privilege__privileged_ops=40, window_start="2026-10-05T10:05:00Z"))[0]["alert_id"]
    assert a == b != c and a.startswith("alt-rules-")


def test_engine_round_trips_and_refuses_a_different_feature_set(engine):
    restored = RuleEngine.from_dict(engine.to_dict())
    window = vec("host", privilege__privileged_ops=40)
    assert restored.evaluate(window) == engine.evaluate(window)
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
