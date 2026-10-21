"""attribution/correlation.py: Fused Alerts -> Incident Objects (entity-time-graph-1.0.0)."""
from app.services.attribution.correlation import (
    AssetInventory,
    consolidation,
    correlate,
    incident_id,
)
from app.services.detection.resolve import entity_id, resolve_events

from .helpers import TENANT, iso, login, proc

H = 3600
VPN_IP, INTRANET_IP = "10.0.0.5", "10.0.1.4"
ASSETS = AssetInventory(tenant_id=TENANT, ip_to_host={VPN_IP: "vpn", INTRANET_IP: "intranet"},
                        fqdn_to_host={"intranet.example.com": "intranet"}, criticality={"intranet": 4})


def web(eid, offset, ip, app="intranet.example.com", status=404):
    return {"event_id": eid, "tenant_id": TENANT, "source_layer": "application", "event_type": "http_request",
            "observed_at": iso(offset), "severity": "info",
            "entities": [{"entity_type": "application", "identifier": app}],
            "payload": {"method": "GET", "path": "/x", "status_code": status, "source_ip": ip}, "metadata": {}}


def events_of(raw):
    return {e.event_id: e for e in resolve_events(raw)[0]}


def alert(fid, entity, start, end, event_ids, technique="unknown", severity="medium"):
    return {"fused_alert_id": fid, "tenant_id": TENANT, "entity_id": entity, "entity_type": entity.split("-")[1],
            "window_start": iso(start).replace(".000Z", "Z"), "window_end": iso(end).replace(".000Z", "Z"),
            "event_ids": event_ids, "technique": technique, "severity": severity,
            "member_alert_ids": [f"alt-{fid}"], "decision": "alert"}


def attack():
    """VPN login (targets host vpn) -> scan FROM the VPN address at the intranet vhost -> su/sudo ON intranet."""
    raw = [login("e-login", 0, "jdoe", "198.51.100.9", "SUCCESS", host="vpn"),
           web("e-scan", 600, VPN_IP),
           proc("e-su", 3000, "www-data", "intranet", "su", "su jdoe"),
           proc("e-sudo", 3010, "jdoe", "intranet", "sudo", "/bin/cat /etc/shadow")]
    alerts = [alert("fal-login", entity_id("user", TENANT, "jdoe"), 0, 300, ["e-login"], "initial_access", "high"),
              alert("fal-scan", entity_id("ip", TENANT, VPN_IP), 600, 900, ["e-scan"], "reconnaissance", "low"),
              alert("fal-priv", entity_id("host", TENANT, "intranet"), 3000, 3300, ["e-su", "e-sudo"],
                    "privilege_escalation", "high")]
    return raw, alerts


def test_three_layer_attack_becomes_one_incident_through_pivots():
    raw, alerts = attack()
    incidents = correlate(alerts, events_of(raw), ASSETS)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["fused_alert_ids"] == ["fal-login", "fal-scan", "fal-priv"]
    reasons = inc["correlation"]["link_reasons"]
    assert f"pivot:{entity_id('host', TENANT, 'vpn')}" in reasons          # logged into vpn, then vpn acts
    assert f"pivot:{entity_id('host', TENANT, 'intranet')}" in reasons     # scanned intranet, then intranet acts
    assert inc["layers"] == ["application", "endpoint", "identity"]
    assert [s["technique"] for s in inc["stages"]] == ["initial_access", "reconnaissance", "privilege_escalation"]
    assert inc["title"] == "Initial access leading to privilege escalation"
    assert inc["severity"] == "critical" and inc["status"] == "open"
    assert inc["incident_id"] == incident_id(["fal-login", "fal-scan", "fal-priv"])
    assert inc["alert_ids"] == ["alt-fal-login", "alt-fal-priv", "alt-fal-scan"]


def test_without_the_asset_inventory_the_layers_do_not_meet():
    raw, alerts = attack()
    incidents = correlate(alerts, events_of(raw))       # the VPN address is not known to be host vpn
    assert len(incidents) > 1


def test_unrelated_alert_stays_separate_and_horizon_is_respected():
    raw, alerts = attack()
    raw.append(login("e-other", 600, "alice", "203.0.113.7", "SUCCESS", host="mail"))
    alerts.append(alert("fal-other", entity_id("user", TENANT, "alice"), 600, 900, ["e-other"], "initial_access"))
    incidents = correlate(alerts, events_of(raw), ASSETS)
    assert sorted(len(i["fused_alert_ids"]) for i in incidents) == [1, 3]
    # same chain, but the privilege step 25 h later: beyond the 24 h horizon
    late_raw, late_alerts = attack()
    late_raw[2] = proc("e-su", 25 * H, "www-data", "intranet", "su", "su jdoe")
    late_raw[3] = proc("e-sudo", 25 * H + 10, "jdoe", "intranet", "sudo", "/bin/cat /etc/shadow")
    late_alerts[2] = alert("fal-priv", entity_id("host", TENANT, "intranet"), 25 * H, 25 * H + 300,
                           ["e-su", "e-sudo"], "privilege_escalation", "high")
    assert len(correlate(late_alerts, events_of(late_raw), ASSETS)) == 2
    assert len(correlate(late_alerts, events_of(late_raw), ASSETS, horizon_seconds=30 * H)) == 1


def test_a_pivot_links_only_the_most_recent_alert_that_targeted_the_entity():
    raw, alerts = attack()
    # a benign client hit the intranet vhost two hours BEFORE the attacker's scan
    raw.append(web("e-benign", -2 * H, "203.0.113.50"))
    alerts.append(alert("fal-benign", entity_id("ip", TENANT, "203.0.113.50"), -2 * H, -2 * H + 300, ["e-benign"]))
    incidents = correlate(alerts, events_of(raw), ASSETS)
    main = max(incidents, key=lambda i: len(i["fused_alert_ids"]))
    assert "fal-benign" not in main["fused_alert_ids"]      # the scan is the latest cause, not the benign client


def test_shared_actor_links_and_consolidation():
    raw = [login("a1", 0, "jdoe", "198.51.100.9", "SUCCESS", host="vpn"),
           login("a2", 1800, "jdoe", "198.51.100.9", "SUCCESS", host="vpn")]
    alerts = [alert("f1", entity_id("user", TENANT, "jdoe"), 0, 300, ["a1"]),
              alert("f2", entity_id("user", TENANT, "jdoe"), 1800, 2100, ["a2"])]
    incidents = correlate(alerts, events_of(raw), ASSETS)
    assert len(incidents) == 1 and any(r.startswith("shared_entity:") for r in incidents[0]["correlation"]["link_reasons"])
    assert consolidation(alerts, incidents) == 2.0 and consolidation([], []) is None


def test_correlation_is_deterministic_and_order_independent():
    raw, alerts = attack()
    a = correlate(alerts, events_of(raw), ASSETS)
    b = correlate(list(reversed(alerts)), events_of(raw), ASSETS)
    assert [i["incident_id"] for i in a] == [i["incident_id"] for i in b]
    assert a[0]["correlation"]["link_reasons"] == b[0]["correlation"]["link_reasons"]


def test_inventory_canonicalises_addresses_and_vhosts():
    from app.services.detection.resolve import make_ref
    assert ASSETS.canonical(make_ref("ip", TENANT, VPN_IP)) == entity_id("host", TENANT, "vpn")
    assert ASSETS.canonical(make_ref("application", TENANT, "Intranet.Example.com")) == entity_id("host", TENANT, "intranet")
    assert ASSETS.canonical(make_ref("ip", TENANT, "203.0.113.1")) == entity_id("ip", TENANT, "203.0.113.1")
    inv = AssetInventory.from_dict({"tenant_id": "t9", "ip_to_host": {"1.2.3.4": "h"}, "fqdn_to_host": {"A.B": "h"},
                                    "hosts": [{"hostname": "h", "criticality": 4}]})
    assert inv.fqdn_to_host == {"a.b": "h"} and inv.criticality == {"h": 4}
