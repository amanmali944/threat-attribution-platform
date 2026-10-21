import json
import math
import random
import time
from pathlib import Path

import pytest

from app.services.detection import contract as C
from app.services.detection.features import (
    FEATURE_KINDS,
    FEATURE_NAMES,
    Baseline,
    FeatureConfig,
    compute_features,
    extract,
    fit_baseline,
)
from app.services.detection.resolve import entity_id, resolve_events

from .helpers import TENANT, dbq, http, iso, login, proc, vector_for

W0 = "2026-10-05T10:00:00Z"   # window containing offsets 0..299
W1 = "2026-10-05T10:05:00Z"   # window containing offsets 300..599


def uid(ident):  return entity_id("user", TENANT, ident)
def ipid(ident): return entity_id("ip", TENANT, ident)


def vectors_of(raw, baseline=None, config=FeatureConfig()):
    return extract(raw, baseline, config)["vectors"]


def fit(raw, config=FeatureConfig(), cohort_of=None):
    return fit_baseline(resolve_events(raw)[0], config, cohort_of)


# ------------------------------------------------------------------ catalogue


def test_catalogue_matches_contract_table():
    """The 22 features in docs/DETECTION_CONTRACT.md section 3.1, in order."""
    contract_text = (Path(__file__).resolve().parents[3] / "docs" / "DETECTION_CONTRACT.md").read_text(encoding="utf-8")
    assert len(FEATURE_NAMES) == 22
    for name in FEATURE_NAMES:
        assert f"`{name}`" in contract_text, f"{name} missing from contract"
    assert C.FEATURE_SET_VERSION == "fs-1.0.0"


def test_vector_shape_and_types():
    raw = [login("a", 0, "u1", "203.0.113.9", "FAILURE")]
    vec = vector_for(vectors_of(raw), uid("u1"))
    assert set(vec) == {
        "schema_version", "feature_set_version", "tenant_id", "entity_id", "entity_type",
        "window_start", "window_end", "window_seconds", "event_ids", "features",
    }
    assert vec["entity_type"] == "user" and vec["window_seconds"] == 300
    assert vec["window_start"] == W0 and vec["window_end"] == "2026-10-05T10:05:00Z"
    assert list(vec["features"]) == list(FEATURE_NAMES)
    for name, kind in FEATURE_KINDS.items():
        assert type(vec["features"][name]) is (int if kind == "int" else float), name


# ------------------------------------------------------------------ hand-computed values


def test_login_feature_values():
    # u1: 10 logins from 203.0.113.9, 5 s apart: F F F F F S F F S S  -> 7 failures, longest run 5
    results = ["FAILURE"] * 5 + ["SUCCESS"] + ["FAILURE"] * 2 + ["SUCCESS"] * 2
    raw = [login(f"u1-{i}", i * 5, "u1", "203.0.113.9", r) for i, r in enumerate(results)]
    # u2 also uses the same IP: 2 failures at 50 s and 55 s
    raw += [login("u2-0", 50, "u2", "203.0.113.9", "FAILURE"), login("u2-1", 55, "u2", "203.0.113.9", "FAILURE")]
    vecs = vectors_of(raw)
    assert len(vecs) == 3  # u1, u2 and the IP

    u1 = vector_for(vecs, uid("u1"))["features"]
    assert u1["volume.event_count"] == 10
    assert u1["failure.login_failure_rate"] == 0.7          # 7 / 10
    assert u1["failure.max_consecutive_failures"] == 5
    assert u1["timing.mean_interarrival_s"] == 5.0
    assert u1["timing.interarrival_cv"] == 0.0              # perfectly regular
    assert u1["diversity.distinct_targets"] == 1            # one host (idp-1)
    assert u1["diversity.distinct_accounts_from_ip"] == 1

    u2 = vector_for(vecs, uid("u2"))["features"]
    assert u2["failure.login_failure_rate"] == 1.0
    assert u2["failure.max_consecutive_failures"] == 2
    assert u2["timing.interarrival_cv"] == 1.0              # <3 events => neutral

    ip = vector_for(vecs, ipid("203.0.113.9"))
    assert ip["entity_type"] == "ip"
    f = ip["features"]
    assert f["volume.event_count"] == 12
    assert f["failure.login_failure_rate"] == 0.75          # 9 failures / 12
    assert f["failure.max_consecutive_failures"] == 5       # F F F F F S F F S S F F
    assert f["diversity.distinct_accounts_from_ip"] == 2    # password-spray signal
    assert f["timing.mean_interarrival_s"] == 5.0


def test_http_feature_values():
    statuses = [200, 200, 404, 500, 200, 401, 200, 200]
    paths = ["/a", "/a", "/b", "/c?x=1", "/a", "/b?y=2", "/a", "/a"]   # query strings ignored
    sessions = ["s1", "s1", "s2", "s2", "s2", "s3", "s3", "s3"]
    raw = [
        http(f"h{i}", i * 10, "u3", "198.51.100.7", paths[i], statuses[i],
             bytes_out=(i + 1) * 100, session_id=sessions[i])
        for i in range(8)
    ]
    f = vector_for(vectors_of(raw), uid("u3"))["features"]
    assert f["volume.event_count"] == 8
    assert f["failure.http_error_rate"] == 0.375            # 404, 500, 401 -> 3 / 8
    assert f["volume.bytes_out"] == 3600.0                  # 100+200+...+800
    assert f["volume.distinct_sessions"] == 3
    # paths: /a x5, /b x2, /c x1 of 8 -> -(5/8 log2 5/8 + 2/8 log2 2/8 + 1/8 log2 1/8)
    assert f["diversity.endpoint_entropy"] == pytest.approx(1.298795, abs=1e-6)
    assert f["timing.mean_interarrival_s"] == 10.0


def test_database_and_privilege_feature_values():
    raw = [
        dbq("d1", 0, "u4", "SELECT", "customers", rows_returned=10),
        dbq("d2", 10, "u4", "SELECT", "customers", rows_returned=20, privileged=True),
        dbq("d3", 20, "u4", "INSERT", "orders", rows_returned=99),   # not a SELECT: ignored for rows_read
        dbq("d4", 30, "u4", "GRANT", "roles"),
        dbq("d5", 40, "u4", "DDL", "schema"),
    ]
    f = vector_for(vectors_of(raw), uid("u4"))["features"]
    assert f["volume.rows_read"] == 30.0                    # 10 + 20
    assert f["privilege.privileged_ops"] == 3               # privileged SELECT + GRANT + DDL
    # objects: customers x2, orders, roles, schema of 5 -> -(0.4 log2 0.4 + 3 * 0.2 log2 0.2)
    expected = -(0.4 * math.log2(0.4) + 3 * 0.2 * math.log2(0.2))
    assert f["diversity.endpoint_entropy"] == pytest.approx(expected, abs=1e-6)


def test_admin_process_counts_as_privileged_regardless_of_path_and_case():
    raw = [
        proc("p1", 0, "u1", "srv-1", "C:\\Tools\\PSEXEC.EXE"),
        proc("p2", 5, "u1", "srv-1", "/usr/bin/sudo"),
        proc("p3", 10, "u1", "srv-1", "notepad.exe"),
    ]
    assert vector_for(vectors_of(raw), uid("u1"))["features"]["privilege.privileged_ops"] == 2


def test_identity_privilege_events_are_counted():
    base = {"tenant_id": TENANT, "source_layer": "identity", "observed_at": "2026-10-05T10:00:00Z",
            "entities": [{"entity_type": "user", "identifier": "u1"}]}
    raw = [
        dict(base, event_id="r1", event_type="privilege_change", payload={"role_before": "user", "role_after": "admin"}),
        dict(base, event_id="r2", event_type="privilege_change", payload={"role_before": "admin", "role_after": "root"}),
        dict(base, event_id="t1", event_type="token_issued", payload={"token_type": "bearer"}),
    ]
    f = vector_for(vectors_of(raw), uid("u1"))["features"]
    assert f["privilege.role_changes"] == 2 and f["privilege.tokens_issued"] == 1


def test_degenerate_timing_values():
    same_instant = [login(f"s{i}", 0, "u1", "203.0.113.9", "FAILURE") for i in range(3)]
    f = vector_for(vectors_of(same_instant), uid("u1"))["features"]
    assert f["timing.mean_interarrival_s"] == 0.0 and f["timing.interarrival_cv"] == 0.0

    single = vector_for(vectors_of([login("x", 0, "u9", "203.0.113.9", "FAILURE")]), uid("u9"))["features"]
    assert single["timing.mean_interarrival_s"] == 0.0 and single["timing.interarrival_cv"] == 1.0
    assert single["failure.login_failure_rate"] == 1.0

    bursty = [login(f"b{i}", t, "u1", "203.0.113.9", "FAILURE") for i, t in enumerate([0, 1, 2, 60])]
    cv = vector_for(vectors_of(bursty), uid("u1"))["features"]["timing.interarrival_cv"]
    gaps = [1, 1, 58]
    mean = sum(gaps) / 3
    assert cv == pytest.approx(math.sqrt(sum((g - mean) ** 2 for g in gaps) / 3) / mean, abs=1e-6)
    assert cv > 1.0  # irregular => not automation-like


# ------------------------------------------------------------------ windows


def test_tumbling_windows_split_a_burst_at_the_boundary():
    raw = [login(f"w{i}", t, "u5", "203.0.113.9", "FAILURE") for i, t in enumerate([270, 280, 290, 300, 310, 320])]
    vecs = [v for v in vectors_of(raw) if v["entity_id"] == uid("u5")]
    assert [(v["window_start"], v["features"]["volume.event_count"]) for v in vecs] == [(W0, 3), (W1, 3)]


def test_window_boundaries_are_exact():
    # [start, start + 300) is half-open: 299.999 is inside W0, 300.000 starts W1, -0.001 is the previous window.
    raw = [login("m", -0.001, "u5", "203.0.113.9", "FAILURE"),
           login("a", 0, "u5", "203.0.113.9", "FAILURE"),
           login("b", 299.999, "u5", "203.0.113.9", "FAILURE"),
           login("c", 300, "u5", "203.0.113.9", "FAILURE")]
    vecs = [v for v in vectors_of(raw) if v["entity_id"] == uid("u5")]
    assert [(v["window_start"], v["event_ids"]) for v in vecs] == [
        ("2026-10-05T09:55:00Z", ["m"]), (W0, ["a", "b"]), (W1, ["c"]),
    ]


def test_hopping_windows_catch_the_whole_burst():
    raw = [login(f"w{i}", t, "u5", "203.0.113.9", "FAILURE") for i, t in enumerate([270, 280, 290, 300, 310, 320])]
    cfg = FeatureConfig(window_seconds=300, stride_seconds=150)
    vecs = [v for v in vectors_of(raw, config=cfg) if v["entity_id"] == uid("u5")]
    counts = {v["window_start"]: v["features"]["volume.event_count"] for v in vecs}
    assert counts == {W0: 3, "2026-10-05T10:02:30Z": 6, W1: 3}
    assert all(v["window_seconds"] == 300 for v in vecs)


def test_window_length_is_configurable():
    raw = [login(f"c{i}", i * 20, "u1", "203.0.113.9", "FAILURE") for i in range(6)]   # 0..100 s
    one_window = vector_for(vectors_of(raw, config=FeatureConfig(window_seconds=300)), uid("u1"))
    assert one_window["features"]["volume.event_count"] == 6
    short = [v for v in vectors_of(raw, config=FeatureConfig(window_seconds=60)) if v["entity_id"] == uid("u1")]
    assert [v["features"]["volume.event_count"] for v in short] == [3, 3]    # 0,20,40 | 60,80,100


def test_invalid_window_configs_are_rejected():
    for kwargs in ({"window_seconds": 0}, {"window_seconds": 300, "stride_seconds": 0},
                   {"window_seconds": 300, "stride_seconds": 400}, {"window_seconds": 300, "stride_seconds": 200}):
        with pytest.raises(ValueError):
            FeatureConfig(**kwargs)


def test_windows_are_per_tenant():
    raw = [login("a", 0, "u1", "203.0.113.9", "FAILURE", tenant="t1"),
           login("b", 0, "u1", "203.0.113.9", "FAILURE", tenant="t2")]
    vecs = vectors_of(raw)
    assert {v["tenant_id"] for v in vecs} == {"t1", "t2"}
    assert len(vecs) == 4   # user + IP, per tenant, never merged


# ------------------------------------------------------------------ determinism


def _mixed_events():
    raw = [login(f"l{i}", i * 5, "u1", "203.0.113.9", "FAILURE" if i % 3 else "SUCCESS") for i in range(12)]
    raw += [http(f"h{i}", 40 + i * 7, "u3", "198.51.100.7", f"/p{i % 3}", 200 + 100 * (i % 4)) for i in range(9)]
    raw += [dbq(f"d{i}", 100 + i, "u4", "SELECT", "customers", rows_returned=i) for i in range(5)]
    raw += [proc("p0", 150, "u1", "srv-1", "psexec.exe")]
    return raw


def test_same_input_replay_gives_identical_features():
    raw = _mixed_events()
    first = json.dumps(vectors_of(raw), sort_keys=False)
    second = json.dumps(vectors_of([dict(e) for e in raw]), sort_keys=False)
    assert first == second


def test_input_order_does_not_change_features():
    raw = _mixed_events()
    shuffled = list(raw)
    random.Random(7).shuffle(shuffled)
    assert json.dumps(vectors_of(raw)) == json.dumps(vectors_of(shuffled))


def test_replay_with_baseline_is_identical_and_baseline_round_trips():
    history = [login(f"h{i}", -86400 + i * 30, "u1", "203.0.113.9", "SUCCESS", country="IN") for i in range(40)]
    baseline = fit(history)
    restored = Baseline.from_dict(json.loads(json.dumps(baseline.to_dict())))
    raw = _mixed_events()
    assert json.dumps(vectors_of(raw, baseline)) == json.dumps(vectors_of(raw, restored))
    assert json.dumps(baseline.to_dict()) == json.dumps(fit(list(reversed(history))).to_dict())


# ------------------------------------------------------------------ baseline-relative features


def _history(user, ip, n=30, country="IN", host="idp-1"):
    """n logins on the previous day at 09:00, 10:00 and 11:00 UTC (hours 9, 10, 11)."""
    return [
        login(f"hist-{user}-{i}", -86400 + (i % 3 - 1) * 3600 + i * 5, user, ip, "SUCCESS", host=host, country=country)
        for i in range(n)
    ]


def test_novelty_and_off_hours_fire_on_unfamiliar_behaviour():
    baseline = fit(_history("u6", "203.0.113.50"))
    off_hours = -7 * 3600   # 03:00 UTC, not one of the entity's usual hours
    raw = [login(f"a{i}", off_hours + i, "u6", "198.51.100.77", "SUCCESS", country="RU") for i in range(3)]
    f = vector_for(vectors_of(raw, baseline), uid("u6"))["features"]
    assert f["novelty.new_source_ip"] == 1
    assert f["novelty.new_country"] == 1
    assert f["timing.off_hours"] == 1
    assert f["novelty.new_target"] == 0       # same host (idp-1) as in history
    assert f["novelty.new_device"] == 0


def test_familiar_behaviour_scores_zero_novelty():
    baseline = fit(_history("u6", "203.0.113.50"))
    raw = [login(f"b{i}", i, "u6", "203.0.113.50", "SUCCESS", country="IN") for i in range(3)]
    f = vector_for(vectors_of(raw, baseline), uid("u6"))["features"]
    assert (f["novelty.new_source_ip"], f["novelty.new_country"], f["timing.off_hours"], f["novelty.new_target"]) == (0, 0, 0, 0)


def test_new_target_counts_distinct_first_time_targets():
    baseline = fit(_history("u6", "203.0.113.50"))
    raw = [login(f"t{i}", i, "u6", "203.0.113.50", "SUCCESS", country="IN", host=h)
           for i, h in enumerate(["idp-1", "idp-2", "idp-3", "idp-3"])]
    assert vector_for(vectors_of(raw, baseline), uid("u6"))["features"]["novelty.new_target"] == 2


def test_cold_start_entities_are_not_flagged_as_novel():
    baseline = fit(_history("u6", "203.0.113.50") + _history("u8", "203.0.113.60", n=5))
    raw = [login("n1", -7 * 3600, "u7", "198.51.100.77", "SUCCESS", country="RU"),    # never seen
           login("n2", -7 * 3600, "u8", "198.51.100.77", "SUCCESS", country="RU")]    # only 5 events < 20
    vecs = vectors_of(raw, baseline)
    for user in ("u7", "u8"):
        f = vector_for(vecs, uid(user))["features"]
        assert (f["novelty.new_source_ip"], f["novelty.new_country"], f["timing.off_hours"]) == (0, 0, 0), user


def test_no_baseline_means_no_baseline_features():
    raw = [login("a", -7 * 3600, "u6", "198.51.100.77", "SUCCESS", country="RU")]
    f = vector_for(vectors_of(raw, baseline=None), uid("u6"))["features"]
    for name in ("novelty.new_source_ip", "novelty.new_country", "novelty.new_target", "timing.off_hours",
                 "peer.volume_zscore", "peer.targets_zscore"):
        assert f[name] == 0


def test_peer_zscores_against_cohort():
    # Four users in one baseline window each: 2, 2, 4, 4 events, one target each
    # => cohort volume mean 3, population std 1; targets mean 1, std 0 (floored to 1).
    history = []
    for user, n in (("p1", 2), ("p2", 2), ("p3", 4), ("p4", 4)):
        history += [login(f"{user}-{i}", -86400 + i, user, f"203.0.113.{10 + int(user[1])}", "SUCCESS") for i in range(n)]
    baseline = fit(history)
    assert baseline.cohort_stats["user"]["volume_mean"] == 3.0
    assert baseline.cohort_stats["user"]["volume_std"] == 1.0

    # u14: 8 events in a window touching 3 different applications
    raw = [http(f"z{i}", i, "u14", "198.51.100.14", "/x", 200, app=f"app-{i % 3}") for i in range(8)]
    f = vector_for(vectors_of(raw, baseline), uid("u14"))["features"]
    assert f["volume.event_count"] == 8 and f["diversity.distinct_targets"] == 3
    assert f["peer.volume_zscore"] == 5.0          # (8 - 3) / 1
    assert f["peer.targets_zscore"] == 2.0         # (3 - 1) / max(0, floor 1)


def test_custom_cohort_mapping_overrides_entity_type():
    history = [login(f"a{i}", -86400 + i, "admin1", "203.0.113.20", "SUCCESS") for i in range(10)]
    history += [login(f"b{i}", -86400 + i, "dev1", "203.0.113.21", "SUCCESS") for i in range(2)]
    cohorts = {uid("admin1"): "admins", uid("dev1"): "devs", uid("dev2"): "devs"}
    baseline = fit(history, cohort_of=cohorts)
    assert baseline.cohort_stats["admins"]["volume_mean"] == 10.0
    assert baseline.cohort_stats["devs"]["volume_mean"] == 2.0
    raw = [login(f"c{i}", i, "dev2", "203.0.113.22", "SUCCESS") for i in range(12)]
    f = vector_for(vectors_of(raw, baseline), uid("dev2"))["features"]
    assert f["peer.volume_zscore"] == 10.0         # (12 - 2) / max(0, floor 1): judged against devs, not admins


# ------------------------------------------------------------------ reporting + fixtures


def test_extract_reports_skipped_events():
    bad = login("bad", 0, "u1", "203.0.113.9", "FAILURE")
    del bad["payload"]["source_ip"]
    out = extract([bad, login("ok", 1, "u1", "203.0.113.9", "FAILURE")])
    assert out["report"]["events_in"] == 2 and out["report"]["events_resolved"] == 1
    assert out["report"]["skipped_events"][0]["missing"] == ["source_ip"]
    assert out["report"]["vectors"] == len(out["vectors"]) == 2
    assert vector_for(out["vectors"], uid("u1"))["event_ids"] == ["ok"]


def test_platform_fixture_features_match_golden_file():
    fixtures = Path(__file__).resolve().parents[3] / "data" / "fixtures"
    raw = json.loads((fixtures / "events.json").read_text(encoding="utf-8"))
    golden = json.loads((fixtures / "expected_features.json").read_text(encoding="utf-8"))
    assert vectors_of(raw) == golden


def test_golden_fixture_hand_checked_values():
    fixtures = Path(__file__).resolve().parents[3] / "data" / "fixtures"
    golden = json.loads((fixtures / "expected_features.json").read_text(encoding="utf-8"))
    tenant = "tenant-default-001"
    admin = next(v for v in golden if v["entity_id"] == entity_id("user", tenant, "corp\\admin_svc"))
    assert admin["window_start"] == "2026-10-05T10:15:00Z"            # logon at 10:18:45
    assert admin["event_ids"] == ["evt-1003"]
    assert admin["features"]["volume.event_count"] == 1
    assert admin["features"]["failure.login_failure_rate"] == 0.0     # the logon succeeded
    tor_ip = next(v for v in golden if v["entity_id"] == entity_id("ip", tenant, "185.220.101.4"))
    assert tor_ip["features"]["diversity.distinct_accounts_from_ip"] == 1
    cloud = next(v for v in golden if v["entity_id"] == entity_id("cloud_identity", tenant, "arn:aws:iam::123456789012:user/deployer"))
    assert cloud["window_start"] == "2026-10-05T10:20:00Z"            # 10:20:11 is the next window
    assert len(golden) == 6


def test_extraction_speed_on_20k_events():
    fixtures = Path(__file__).resolve().parents[3] / "data" / "fixtures"
    seed = json.loads((fixtures / "events.json").read_text(encoding="utf-8"))
    raw = []
    for i in range(5000):
        for event in seed:
            clone = dict(event, event_id=f"{event['event_id']}-{i}")
            clone["observed_at"] = iso(i * 60)
            raw.append(clone)
    start = time.perf_counter()
    out = extract(raw)
    elapsed = time.perf_counter() - start
    print(f"\n[perf] {len(raw)} events -> {len(out['vectors'])} vectors in {elapsed:.2f}s")
    assert out["report"]["events_resolved"] == len(raw)
    assert elapsed < 20
