"""attribution/risk.py: time-decayed, criticality-weighted, explainable risk (contract section 8)."""
import math

import pytest

from app.services.attribution.risk import alert_criticality, entity_risk, incident_risk, level, score, weight
from app.services.detection.resolve import entity_id

from .helpers import TENANT
from .test_correlation import ASSETS, attack, events_of

NOW = "2026-10-06T10:00:00Z"


def item(source, confidence, last_seen=NOW, criticality=5):
    return {"source_id": source, "confidence": confidence, "criticality": criticality, "last_seen": last_seen}


def test_formula_combines_independent_contributions():
    result = score([item("a", 0.5), item("b", 0.5)], NOW)
    assert result["score"] == 75.0                       # 100 x (1 - 0.5 x 0.5)
    assert result["level"] == "critical" and len(result["contributors"]) == 2


def test_half_life_halves_a_contribution():
    fresh = score([item("a", 0.8)], NOW)["contributors"][0]["decayed_contribution"]
    day_old = score([item("a", 0.8, last_seen="2026-10-05T10:00:00Z")], NOW)
    assert day_old["contributors"][0]["decayed_contribution"] == pytest.approx(fresh / 2)
    assert day_old["contributors"][0]["age_seconds"] == 86_400


def test_higher_criticality_ranks_higher_for_equal_confidence():
    low = score([item("a", 0.6, criticality=1)], NOW)["score"]
    high = score([item("a", 0.6, criticality=5)], NOW)["score"]
    assert high > low
    assert weight(5) == 1.0 and weight(1) == 0.6
    with pytest.raises(ValueError):
        weight(6)


def test_levels_and_empty_score():
    assert [level(s) for s in (0, 24.99, 25, 49.9, 50, 74.9, 75, 100)] == \
           ["low", "low", "medium", "medium", "high", "high", "critical", "critical"]
    empty = score([], NOW)
    assert empty["score"] == 0.0 and empty["contributors"] == [] and empty["level"] == "low"


def test_every_nonzero_score_has_contributors_sorted_by_size():
    result = score([item("small", 0.1), item("big", 0.9), item("mid", 0.5)], NOW)
    assert result["score"] > 0 and [c["source_id"] for c in result["contributors"]] == ["big", "mid", "small"]
    expected = 100 * (1 - (1 - 0.1) * (1 - 0.9) * (1 - 0.5))
    assert result["score"] == round(expected, 2)


def test_incident_and_entity_risk_use_member_alerts_and_inventory_criticality():
    raw, alerts = attack()
    for a, c in zip(alerts, (0.9, 0.3, 1.0)):
        a["confidence"], a["decision"] = c, "alert"
    events = events_of(raw)
    crit = {a["fused_alert_id"]: alert_criticality(a, events, ASSETS) for a in alerts}
    assert crit == {"fal-login": 1, "fal-scan": 4, "fal-priv": 4}       # the scan and su/sudo touch intranet (4)
    incident = {"incident_id": "inc-1", "tenant_id": TENANT, "fused_alert_ids": ["fal-login", "fal-scan"]}
    risk = incident_risk(incident, alerts, crit, NOW)
    assert risk["subject_type"] == "incident" and {c["source_id"] for c in risk["contributors"]} == {"fal-login", "fal-scan"}
    assert risk["schema_version"] == "1.0" and 0 < risk["score"] <= 100
    host = entity_risk(entity_id("host", TENANT, "intranet"), alerts, crit, NOW, TENANT)
    assert [c["source_id"] for c in host["contributors"]] == ["fal-priv"]
    assert "privilege_escalation" in host["contributors"][0]["reason"]
