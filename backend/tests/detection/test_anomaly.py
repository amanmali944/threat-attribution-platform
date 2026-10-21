import math
import random

import numpy as np
import pytest

from app.services.detection.anomaly import IsolationForestDetector, transform
from app.services.detection.envelope import validate_alert
from app.services.detection.features import FEATURE_KINDS, FEATURE_NAMES

from .test_rules import vec


def background(n=300, etype="user", seed=0):
    """Ordinary windows: a few logins, some failures, a little privileged activity."""
    rng = np.random.default_rng(seed)
    out = []
    for i in range(n):
        out.append(vec(
            etype, entity_id=f"ent-{etype}-{i:08d}", window_start=f"2026-10-05T{10 + i // 12:02d}:{(i % 12) * 5:02d}:00Z",
            volume__event_count=int(rng.integers(1, 20)),
            volume__login_count=int(rng.integers(0, 10)),
            failure__login_failure_rate=float(rng.uniform(0, 0.3)),
            privilege__privileged_ops=int(rng.integers(0, 3)),
            timing__interarrival_cv=float(rng.uniform(0.5, 2.0)),
        ))
    return out


def outlier(etype="user"):
    return vec(etype, entity_id=f"ent-{etype}-99999999", window_start="2026-10-06T00:00:00Z",
               volume__event_count=400, volume__login_count=0, privilege__privileged_ops=250,
               failure__login_failure_rate=0.0, timing__interarrival_cv=0.1)


@pytest.fixture(scope="module")
def detector():
    return IsolationForestDetector().fit(background())


def test_transform_logs_counts_but_not_rates():
    row = transform(vec("user", volume__event_count=99, failure__login_failure_rate=0.5, peer__volume_zscore=-2.0)["features"])
    by_name = dict(zip(FEATURE_NAMES, row))
    assert by_name["volume.event_count"] == pytest.approx(math.log1p(99))
    assert by_name["failure.login_failure_rate"] == 0.5          # rate: unchanged
    assert by_name["peer.volume_zscore"] == -2.0                 # z-score: unchanged (can be negative)
    assert len(row) == len(FEATURE_NAMES)


def test_outlier_scores_far_above_background(detector):
    scores = detector.scores(background(seed=1) + [outlier()])
    assert all(0.0 <= s <= 1.0 for s in scores)
    assert scores[-1] >= 0.99                                    # in the top 1% of the reference windows
    background_scores = sorted(scores[:-1])
    assert 0.2 < background_scores[len(background_scores) // 2] < 0.8   # fresh background sits mid-range


def test_scores_are_deterministic_and_order_independent():
    a = IsolationForestDetector().fit(background())
    shuffled = background()
    random.Random(3).shuffle(shuffled)
    b = IsolationForestDetector().fit(shuffled)
    probe = background(seed=2) + [outlier()]
    assert a.scores(probe) == b.scores(probe)


def test_types_without_enough_training_data_get_no_model():
    det = IsolationForestDetector(min_train_windows=20).fit(background() + background(5, etype="host"))
    assert set(det.models) == {"user"}
    assert det.scores([outlier("host")]) == [None]
    assert det.alerts([outlier("host")], threshold=0.0) == []


def test_explanation_points_at_the_unusual_features(detector):
    top = [e["feature"] for e in detector.explain(outlier())]
    assert "privilege.privileged_ops" in top and "volume.event_count" in top


def test_alerts_are_valid_envelopes_and_respect_the_threshold(detector):
    probe = background(seed=4) + [outlier()]
    alerts = detector.alerts(probe, threshold=0.99)
    assert outlier()["entity_id"] in {a["entity_id"] for a in alerts}
    assert len(alerts) <= 0.03 * len(probe)                      # ~1% of fresh background by construction
    for alert in alerts:
        assert validate_alert(alert) == []
        assert alert["detector"] == "isolation_forest" and alert["rule_id"] == "ML-IFOREST-001"
        assert alert["technique"] == "unknown" and alert["score"] >= 0.99
        assert alert["evidence"] and "baseline_z" in alert["evidence"][0]


def test_reference_set_defines_the_scale():
    """Scoring against a separate reference set (e.g. validation background) is supported."""
    det = IsolationForestDetector().fit(background(), reference_vectors=background(seed=9))
    assert det.metadata()["types"]["user"] == {"n_train": 300, "n_reference": 300}
    # Not necessarily 1.0: Isolation Forest scores saturate outside the training range, so an
    # extreme outlier can tie with the most extreme reference window.
    assert det.scores([outlier()])[0] >= 0.99


def test_metadata_records_versions_and_params(detector):
    meta = detector.metadata()
    assert meta["model_version"] == "iforest-1.0.0" and meta["feature_set_version"] == "fs-1.1.0"
    assert meta["params"]["random_state"] == 42
