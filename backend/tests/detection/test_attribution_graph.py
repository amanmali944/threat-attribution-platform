"""attribution/graph.py: incident -> entry point, time-respecting path, reached assets (graph-attribution-1.0.0)."""
import pytest

from app.services.attribution.correlation import AssetInventory, correlate
from app.services.attribution.graph import attribute, event_edges, observed_graph, _Namer
from app.services.detection.resolve import entity_id, resolve_events

from .helpers import TENANT, iso, login, proc
from .test_correlation import ASSETS, VPN_IP, attack, events_of, web

JDOE, VPN, INTRANET = entity_id("user", TENANT, "jdoe"), entity_id("host", TENANT, "vpn"), entity_id("host", TENANT, "intranet")
ORIGIN = entity_id("ip", TENANT, "198.51.100.9")


def scored(alerts, confidences, decisions=None):
    for a, c, d in zip(alerts, confidences, decisions or ["alert"] * len(alerts)):
        a["confidence"], a["decision"] = c, d
    return alerts


def attributed(confidences=(0.9, 0.8, 1.0), decisions=None, access_graph=None):
    raw, alerts = attack()
    alerts = scored(alerts, confidences, decisions)
    events = events_of(raw)
    incident = correlate(alerts, events, ASSETS)[0]
    return attribute(incident, alerts, events, ASSETS, access_graph), incident


def test_entry_is_the_account_used_with_its_origin():
    result, incident = attributed()
    entry = result["entry_point"]
    assert (entry["entity_id"], entry["entity_type"], entry["identifier"]) == (JDOE, "user", "jdoe")
    assert entry["origin_entity_id"] == ORIGIN and entry["first_anomalous_event_id"] == "e-login"
    assert entry["observed_at"] == iso(0).replace(".000Z", "Z") and entry["confidence"] == 0.9
    assert result["attribution_id"] == "att-" + incident["incident_id"].split("-", 1)[1]


def test_path_is_time_respecting_and_cites_real_events():
    result, _ = attributed()
    path = result["attack_path"]
    assert [(s["source_entity_id"], s["target_entity_id"], s["relation"], s["event_id"]) for s in path] == [
        (ORIGIN, JDOE, "AUTHENTICATED_AS", "e-login"),
        (JDOE, VPN, "LOGGED_INTO", "e-login"),
        (VPN, INTRANET, "HTTP_REQUEST", "e-scan"),        # traffic from the VPN server's address
    ]
    assert [s["step"] for s in path] == [1, 2, 3]
    times = [s["observed_at"] for s in path]
    assert times == sorted(times)
    assert {s["layer"] for s in path} == {"identity", "application"}


def test_reached_assets_blast_radius_dwell_and_confidence():
    result, _ = attributed()
    reached = [(a["entity_id"], a["identifier"], a["criticality"]) for a in result["reached_assets"]]
    assert reached == [(VPN, "vpn", 1), (INTRANET, "intranet", 4)]       # criticality from the inventory
    assert result["blast_radius"] == {"reached_count": 2, "potential_reach_count": None, "critical_assets_reached": 1}
    assert result["dwell_time_seconds"] == 3010                        # last event (sudo) - entry
    assert result["confidence"] == round(min(0.9, (0.9 + 0.9 + 0.8) / 3), 6)
    assert "Entry via user jdoe" in result["explanation"] and "intranet" in result["explanation"]


def test_graph_uses_the_platform_node_and_edge_shape():
    result, _ = attributed()
    nodes = {n["id"]: n for n in result["graph"]["nodes"]}
    assert set(nodes) == {ORIGIN, JDOE, VPN, INTRANET}
    assert nodes[JDOE]["properties"]["is_entry_point"] and nodes[ORIGIN]["properties"]["is_origin"]
    for node in nodes.values():
        assert set(node) == {"id", "label", "type", "properties"}
    for edge in result["graph"]["edges"]:
        assert set(edge) == {"source", "target", "relation", "weight"} and 0 <= edge["weight"] <= 1


def test_root_rule_ignores_other_users_traffic_on_a_shared_address():
    # the scan alert's window on the VPN address also holds another user's request made BEFORE the login
    raw, alerts = attack()
    raw.append(web("e-early", -60, VPN_IP, app="cloud.example.com", status=200))
    alerts[1]["event_ids"] = ["e-early", "e-scan"]
    alerts = scored(alerts, (0.9, 0.8, 1.0))
    events = events_of(raw)
    incident = correlate(alerts, events, ASSETS)[0]
    old = attribute(incident, alerts, events, ASSETS, method="graph-attribution-1.0.0")
    new = attribute(incident, alerts, events, ASSETS)
    assert old["entry_point"]["first_anomalous_event_id"] == "e-early"          # 1.0.0: earliest edge - wrong
    assert new["method"] == "graph-attribution-1.1.0"
    assert new["entry_point"]["first_anomalous_event_id"] == "e-login"          # 1.1.0: the graph's root
    assert new["entry_point"]["entity_id"] == JDOE and new["entry_point"]["origin_entity_id"] == ORIGIN
    with pytest.raises(ValueError, match="unknown attribution method"):
        attribute(incident, alerts, events, ASSETS, method="magic")


def dns(eid, offset, ip, name):
    return {"event_id": eid, "tenant_id": TENANT, "source_layer": "network", "event_type": "dns_query",
            "observed_at": iso(offset), "severity": "info",
            "entities": [{"entity_type": "ip", "identifier": ip}, {"entity_type": "domain", "identifier": name}],
            "payload": {"query_name": name}, "metadata": {}}


def test_path_never_uses_an_edge_before_its_source_was_reached():
    # the intranet host talked to the mail vhost at t=300, but the attacker only reached intranet at t=600
    inv = AssetInventory(tenant_id=TENANT, ip_to_host={VPN_IP: "vpn", "10.0.1.4": "intranet"},
                         fqdn_to_host={"intranet.example.com": "intranet", "mail.example.com": "mail"},
                         criticality={"intranet": 4, "mail": 4, "vpn": 4})
    raw, alerts = attack()
    raw.append(web("e-pre", 300, "10.0.1.4", app="mail.example.com", status=200))
    alerts[1]["event_ids"] = ["e-pre", "e-scan"]
    alerts = scored(alerts, (0.9, 0.8, 1.0))
    events = events_of(raw)
    result = attribute(correlate(alerts, events, inv)[0], alerts, events, inv)
    assert [a["identifier"] for a in result["reached_assets"]] == ["vpn", "intranet"]   # mail was NOT reached


def test_external_destinations_are_not_company_assets():
    raw, alerts = attack()
    raw.append(dns("e-dns", 650, VPN_IP, "evil.example"))
    alerts[1]["event_ids"] = ["e-scan", "e-dns"]
    alerts = scored(alerts, (0.9, 0.8, 1.0))
    events = events_of(raw)
    result = attribute(correlate(alerts, events, ASSETS)[0], alerts, events, ASSETS)
    assert all(a["entity_type"] in ("host", "user") for a in result["reached_assets"])
    assert "evil.example" not in [a["identifier"] for a in result["reached_assets"]]


def test_review_level_alerts_do_not_start_the_story():
    # the login alert is only "review": the entry moves to the first alert-level evidence (the scan)
    result, _ = attributed(decisions=["review", "alert", "alert"])
    assert result["entry_point"]["first_anomalous_event_id"] == "e-scan"
    assert result["entry_point"]["entity_id"] == VPN and result["entry_point"]["origin_entity_id"] is None


def test_potential_reach_from_the_observed_access_graph():
    raw, _ = attack()
    raw += [web("e-x", -3600, VPN_IP, app="mail.example.com")]          # vpn has also talked to mail before
    inv = AssetInventory(tenant_id=TENANT, ip_to_host=dict(ASSETS.ip_to_host),
                         fqdn_to_host={"intranet.example.com": "intranet", "mail.example.com": "mail"},
                         criticality={"intranet": 4, "mail": 4, "vpn": 4})
    graph = observed_graph(resolve_events(raw)[0], inv)
    raw2, alerts = attack()
    alerts = scored(alerts, (0.9, 0.8, 1.0))
    events = events_of(raw2)
    result = attribute(correlate(alerts, events, inv)[0], alerts, events, inv, graph)
    assert result["blast_radius"]["potential_reach_count"] == 1          # mail: reachable, not yet reached
    assert result["blast_radius"]["critical_assets_reached"] == 2


def test_event_edges_by_type():
    name = _Namer(ASSETS)
    ev = {e.event_id: e for e in resolve_events([login("l", 0, "jdoe", "198.51.100.9", "SUCCESS", host="vpn"),
                                                  proc("p", 1, "jdoe", "intranet", "sudo", "id")])[0]}
    assert event_edges(ev["l"], name) == [(ORIGIN, JDOE, "AUTHENTICATED_AS"), (JDOE, VPN, "LOGGED_INTO")]
    assert event_edges(ev["p"], name) == [(JDOE, INTRANET, "EXECUTED_ON")]


def test_an_incident_without_resolvable_events_is_refused():
    with pytest.raises(ValueError, match="no resolvable events"):
        attribute({"incident_id": "inc-00000000", "fused_alert_ids": ["f"]},
                  [{"fused_alert_id": "f", "event_ids": ["missing"], "confidence": 0.5, "decision": "alert"}], {})
