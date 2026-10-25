import json
from pathlib import Path

import pytest

from app.models.entity import generate_entity_id as platform_entity_id
from app.services.detection import contract as C
from app.services.detection.resolve import (
    EventSkipped,
    entity_id,
    iso_utc,
    parse_timestamp,
    resolve_event,
    resolve_events,
)

from .helpers import BASE, TENANT, dbq, http, login, proc

FIXTURES = Path(__file__).resolve().parents[3] / "data" / "fixtures"


def load_platform_events():
    return json.loads((FIXTURES / "events.json").read_text(encoding="utf-8"))


# ------------------------------------------------------------------ entity IDs


def test_entity_id_matches_platform_helper():
    """Our ID scheme must stay byte-identical to the platform's (CR-06)."""
    for etype, tenant, ident in [
        ("user", "tenant-default-001", "corp\\jdoe"),
        ("ip", "t1", "203.0.113.9"),
        ("database", "t2", "prod-customers-db"),
    ]:
        assert entity_id(etype, tenant, ident) == platform_entity_id(etype, tenant, ident)


def test_entity_id_is_deterministic_and_tenant_scoped():
    a = entity_id("host", "t1", "srv-1")
    assert a == entity_id("host", "t1", "srv-1")
    assert a != entity_id("host", "t2", "srv-1")
    assert a.startswith("ent-host-") and len(a.split("-")[-1]) == 8


# ------------------------------------------------------------------ validation


def test_platform_fixtures_are_contract_valid():
    for event in load_platform_events():
        assert C.validate_event(event) == [], event["event_id"]


def test_validate_event_reports_every_problem():
    bad = {"tenant_id": "t1", "source_layer": "mainframe", "event_type": "user_login",
           "payload": {"result": "FAILURE"}, "entities": [{"entity_type": "alien", "identifier": "x"}]}
    problems = C.validate_event(bad)
    assert "missing field: observed_at" in problems
    assert "unknown source_layer: mainframe" in problems
    assert "unknown entity_type: alien" in problems


def test_missing_required_payload_key():
    event = login("e1", 0, "u1", "203.0.113.9", "FAILURE")
    del event["payload"]["source_ip"]
    assert C.missing_payload_keys(event) == ["source_ip"]


# ------------------------------------------------------------------ roles


def test_roles_on_platform_fixtures():
    by_id = {e.event_id: e for e in resolve_events(load_platform_events())[0]}
    tenant = "tenant-default-001"

    e1001 = by_id["evt-1001"]  # endpoint process_execution
    assert e1001.actor_user.identifier == "corp\\jdoe"
    assert e1001.actor_host.identifier == "workstation-01.corp.internal"
    assert e1001.target.identifier == "workstation-01.corp.internal"

    e1002 = by_id["evt-1002"]  # network dns_query
    assert e1002.actor_ip.identifier == "10.0.4.15"
    assert e1002.target.entity_type == "domain"
    assert e1002.target.identifier == "c2-command-node.badactor.org"
    assert e1002.actor_user is None

    e1003 = by_id["evt-1003"]  # identity user_login, source_ip only in payload
    assert e1003.actor_user.identifier == "corp\\admin_svc"
    assert e1003.actor_ip.entity_id == entity_id("ip", tenant, "185.220.101.4")
    assert e1003.target.identifier == "dc-primary.corp.internal"
    assert e1003.outcome == "success"

    e1004 = by_id["evt-1004"]  # cloud_api_call
    assert e1004.actor_user.entity_type == "cloud_identity"
    assert e1004.target.identifier == "iam.amazonaws.com"
    assert e1004.target.entity_type == "application"


def test_payload_ip_and_entity_list_ip_resolve_to_one_entity():
    via_payload = resolve_event(login("a", 0, "u1", "203.0.113.9", "SUCCESS"))
    listed = login("b", 0, "u1", "x", "SUCCESS")
    listed["payload"]["source_ip"] = "203.0.113.9"
    listed["entities"].append({"entity_type": "ip", "identifier": "203.0.113.9"})
    assert resolve_event(listed).actor_ip.entity_id == via_payload.actor_ip.entity_id


def test_network_connection_actor_ip_excludes_destination():
    event = {
        "event_id": "n1", "tenant_id": TENANT, "source_layer": "network",
        "event_type": "network_connection", "observed_at": "2026-10-05T10:00:00Z",
        "entities": [{"entity_type": "ip", "identifier": "198.51.100.5"},   # destination, listed first
                     {"entity_type": "ip", "identifier": "10.0.0.8"}],      # source
        "payload": {"dst_ip": "198.51.100.5", "dst_port": 443},
    }
    resolved = resolve_event(event)
    assert resolved.actor_ip.identifier == "10.0.0.8"
    assert resolved.target.identifier == "198.51.100.5"


def test_remote_session_source_host_is_actor_and_listed_host_is_target():
    event = {
        "event_id": "r1", "tenant_id": TENANT, "source_layer": "endpoint",
        "event_type": "remote_session", "observed_at": "2026-10-05T10:00:00Z",
        "entities": [{"entity_type": "host", "identifier": "srv-b"},
                     {"entity_type": "user", "identifier": "u1"}],
        "payload": {"protocol": "rdp", "result": "SUCCESS", "source_host": "srv-a"},
    }
    resolved = resolve_event(event)
    assert resolved.actor_host.identifier == "srv-a"
    assert resolved.actor_host.entity_type == "host"
    assert resolved.target.identifier == "srv-b"
    assert [s.identifier for s in resolved.subjects()] == ["u1", "srv-a"]


def test_target_criticality_from_assets_with_default_and_clamp():
    event = dbq("d1", 0, "u1", "SELECT", "customers", db="prod-db")
    assert resolve_event(event).target_criticality == 1
    assert resolve_event(event, {"prod-db": 5}).target_criticality == 5
    assert resolve_event(event, {"prod-db": 99}).target_criticality == 5
    assert resolve_event(event, {"prod-db": 0}).target_criticality == 1
    target_id = resolve_event(event).target.entity_id
    assert resolve_event(event, {target_id: 4}).target_criticality == 4


def test_outcome_normalisation():
    assert resolve_event(login("a", 0, "u", "203.0.113.1", "FAILURE")).outcome == "failure"
    assert resolve_event(login("b", 0, "u", "203.0.113.1", "success")).outcome == "success"
    assert resolve_event(login("c", 0, "u", "203.0.113.1", "weird")).outcome == "unknown"
    assert resolve_event(http("d", 0, "u", "203.0.113.1", "/x", 503)).outcome == "failure"
    assert resolve_event(http("e", 0, "u", "203.0.113.1", "/x", 200)).outcome == "success"
    assert resolve_event(dbq("f", 0, "u", "SELECT", "t")).outcome == "unknown"


# ------------------------------------------------------------------ batch behaviour


def test_batch_skips_and_counts_instead_of_raising():
    missing_key = login("bad1", 0, "u1", "203.0.113.9", "FAILURE")
    del missing_key["payload"]["result"]
    no_tenant = login("bad2", 0, "u1", "203.0.113.9", "FAILURE")
    del no_tenant["tenant_id"]
    bad_time = login("bad3", 0, "u1", "203.0.113.9", "FAILURE")
    bad_time["observed_at"] = "not-a-time"
    good = login("ok1", 0, "u1", "203.0.113.9", "FAILURE")

    events, report = resolve_events([missing_key, no_tenant, bad_time, "garbage", good])
    assert [e.event_id for e in events] == ["ok1"]
    assert report["events_in"] == 5 and report["events_resolved"] == 1
    reasons = {s["event_id"]: s for s in report["skipped_events"]}
    assert reasons["bad1"]["missing"] == ["result"]
    assert reasons["bad2"]["reason"] == "missing field: tenant_id"
    assert reasons["bad3"]["reason"].startswith("bad observed_at")
    assert len(report["skipped_events"]) == 4


def test_duplicates_and_unknown_types_are_reported():
    a = login("dup", 0, "u1", "203.0.113.9", "FAILURE")
    exotic = {"event_id": "x1", "tenant_id": TENANT, "source_layer": "cloud",
              "event_type": "novel_thing", "observed_at": "2026-10-05T10:00:00Z", "payload": {}}
    events, report = resolve_events([a, dict(a), exotic])
    assert len(events) == 2
    assert report["duplicate_events"] == 1
    assert report["unknown_event_types"] == {"cloud:novel_thing": 1}


def test_batch_output_is_sorted_by_time_then_id():
    raw = [login("b", 10, "u", "203.0.113.1", "FAILURE"),
           login("a", 10, "u", "203.0.113.1", "FAILURE"),
           login("c", 0, "u", "203.0.113.1", "FAILURE")]
    assert [e.event_id for e in resolve_events(raw)[0]] == ["c", "a", "b"]


def test_missing_event_id_gets_a_stable_content_hash():
    raw = login("x", 0, "u1", "203.0.113.9", "FAILURE")
    del raw["event_id"]
    assert resolve_event(raw).event_id == resolve_event(dict(raw)).event_id
    assert resolve_event(raw).event_id.startswith("evt-")


def test_platform_row_shape_uses_id_and_null_entities():
    """Rows read back from the platform use `id`, and `entities` may be null."""
    raw = proc("p1", 0, "u1", "srv-1", "cmd.exe")
    raw["id"] = raw.pop("event_id")
    raw["entities"] = None
    resolved = resolve_event(raw)
    assert resolved.event_id == "p1" and resolved.actor_user is None


# ------------------------------------------------------------------ timestamps


def test_timestamp_parsing():
    assert parse_timestamp("2026-10-05T10:00:00Z") == BASE
    assert parse_timestamp("2026-10-05T10:00:00.250Z").microsecond == 250000
    assert parse_timestamp("2026-10-05T15:30:00+05:30") == BASE
    assert parse_timestamp("2026-10-05T10:00:00") == BASE  # naive => UTC
    assert iso_utc(BASE) == "2026-10-05T10:00:00Z"
    assert iso_utc(parse_timestamp("2026-10-05T10:00:00.250Z")) == "2026-10-05T10:00:00.25Z"


def test_to_dict_matches_contract_shape():
    d = resolve_event(login("e1", 0, "u1", "203.0.113.9", "FAILURE")).to_dict()
    assert set(d) == {
        "schema_version", "event_id", "tenant_id", "source_layer", "event_type", "observed_at",
        "actor_user", "actor_ip", "actor_host", "actor_device", "target", "target_criticality", "outcome",
    }
    assert d["observed_at"] == "2026-10-05T10:00:00Z"
    assert d["actor_user"].startswith("ent-user-") and d["actor_ip"].startswith("ent-ip-")
    assert d["actor_host"] is None and d["outcome"] == "failure"
