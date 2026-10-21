"""Phase 9 end-to-end: canonical events -> Developer A pipeline -> Developer B platform API (in-memory DB).

A three-layer intrusion (stolen credentials on the VPN, a scan from the VPN address at the
intranet vhost, a web-shell account switching user and reading /etc/shadow) after a normal day,
run through ``services.pipeline`` in rules-only mode and delivered with FastAPI's TestClient.
"""
import os
import sys
from pathlib import Path

os.environ["TESTING"] = "1"                      # in-memory database, never the local platform DB
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.core.database import init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.services.attribution.correlation import AssetInventory  # noqa: E402
from app.services.detection.resolve import entity_id  # noqa: E402
from app.services.pipeline import alert_payload, deliver, run_pipeline  # noqa: E402

TENANT = "tenant-e2e-001"
VPN_IP, INTRANET_IP, HOME_IP, ATTACKER_IP = "10.0.0.5", "10.0.1.4", "198.51.100.9", "203.0.113.66"
DAY0 = "2026-10-05"   # normal day (baseline)
DAY1 = "2026-10-06"   # attack day (scored)
ASSETS = AssetInventory(tenant_id=TENANT, ip_to_host={VPN_IP: "vpn", INTRANET_IP: "intranet"},
                        fqdn_to_host={"intranet.example.com": "intranet"}, criticality={"vpn": 4, "intranet": 4})


def ev(eid, when, layer, etype, entities, payload):
    return {"event_id": eid, "tenant_id": TENANT, "source_layer": layer, "event_type": etype, "observed_at": when,
            "severity": "info", "entities": entities, "payload": payload, "metadata": {"source": "e2e"}}


def vpn_login(eid, when, user, ip):
    return ev(eid, when, "identity", "user_login",
              [{"entity_type": "user", "identifier": user}, {"entity_type": "host", "identifier": "vpn"}],
              {"result": "SUCCESS", "source_ip": ip, "service": "openvpn"})


def web(eid, when, ip, status):
    return ev(eid, when, "application", "http_request", [{"entity_type": "application", "identifier": "intranet.example.com"}],
              {"method": "GET", "path": f"/p{eid[-3:]}", "status_code": status, "source_ip": ip})


def cmd(eid, when, user, process, command):
    return ev(eid, when, "endpoint", "process_execution",
              [{"entity_type": "host", "identifier": "intranet"}, {"entity_type": "user", "identifier": user}],
              {"process_name": process, "command_line": command})


def corpus():
    raw = []
    for i, hour in enumerate((8, 10, 12, 14, 16)):                      # normal day: jdoe works over the VPN
        raw.append(vpn_login(f"b-login-{i}", f"{DAY0}T{hour:02d}:00:00Z", "jdoe", HOME_IP))
        raw += [web(f"b-web-{i}-{k:03d}", f"{DAY0}T{hour:02d}:{k + 1:02d}:00Z", VPN_IP, 200) for k in range(3)]
    raw.append(vpn_login("a-login", f"{DAY1}T03:01:00Z", "jdoe", ATTACKER_IP))          # stolen credentials
    raw += [web(f"a-scan-{k:03d}", f"{DAY1}T03:06:{k:02d}Z", VPN_IP, 404) for k in range(40)]   # scan from the VPN
    raw.append(cmd("a-su", f"{DAY1}T03:40:00Z", "www-data", "su", "su jdoe"))            # web shell switches user
    raw.append(cmd("a-shadow", f"{DAY1}T03:40:10Z", "jdoe", "sudo", "/bin/cat /etc/shadow"))
    return raw


@pytest.fixture(scope="module")
def result():
    return run_pipeline(corpus(), baseline=(f"{DAY0}T00:00:00Z", f"{DAY1}T00:00:00Z"),
                        score=(f"{DAY1}T00:00:00Z", f"{DAY1}T23:59:59Z"), assets=ASSETS)


@pytest.fixture(scope="module")
def client():
    init_db()
    return TestClient(app)


def test_pipeline_detects_every_stage_and_builds_one_incident(result):
    assert result["mode"] == "rules-only" and result["resolve_report"]["skipped"] == 0
    rules = {r for a in result["fused_alerts"] for r in (e["rule_id"] for e in a["evidence"])}
    assert {"RULE-IDN-003", "RULE-APP-001", "RULE-PRIV-004", "RULE-PRIV-005"} <= rules
    assert len(result["incidents"]) == 1
    incident = result["incidents"][0]
    assert incident["layers"] == ["application", "endpoint", "identity"]
    assert incident["severity"] == "critical"


def test_pipeline_attributes_the_entry_and_reach(result):
    (att,) = result["attributions"]
    assert att["entry_point"]["entity_id"] == entity_id("user", TENANT, "jdoe")
    assert att["entry_point"]["origin_entity_id"] == entity_id("ip", TENANT, ATTACKER_IP)
    assert att["entry_point"]["first_anomalous_event_id"] == "a-login"
    assert [a["identifier"] for a in att["reached_assets"]] == ["vpn", "intranet"]
    assert att["dwell_time_seconds"] == 39 * 60 + 10
    (risk,) = result["risks"]
    assert risk["level"] == "critical" and risk["contributors"]


def test_delivery_to_the_platform_api(result, client):
    def post(path, payload):
        response = client.post(path, json=payload)
        return response.status_code, (response.json() if response.content else None)

    report = deliver(post, result, raw_events=corpus())
    assert report["events"] == {"201": len({e for a in result["fused_alerts"] if a["decision"] != "suppress"
                                            for e in a["event_ids"]})}
    assert set(report["alerts"]) == {"201"} and report["alerts"]["201"] == len(report["alert_ids"]) >= 3
    assert report["incidents"] == {"201": 1}

    alerts = client.get(f"/api/v1/alerts?tenant_id={TENANT}&limit=100").json()
    mine = {a["id"]: a for a in alerts["items"] if a["id"] in set(report["alert_ids"].values())}
    assert len(mine) == len(report["alert_ids"])
    assert all(a["detector_version"] == "fusion-1.0.0" and a["decision"] in ("alert", "review") for a in mine.values())
    assert {a["technique"] for a in mine.values()} >= {"initial_access", "privilege_escalation"}

    (platform_incident,) = report["incident_ids"].values()
    incident = client.get(f"/api/v1/incidents/{platform_incident}?tenant_id={TENANT}").json()
    assert incident["risk_level"] == "critical" and incident["layers"] == ["application", "endpoint", "identity"]

    # attributions are mounted through the incidents module (app/api/v1/incidents.py)
    assert report["attributions"] == {"201": 1} and report["endpoint_missing"] == []
    listed = client.get(f"/api/v1/attributions?tenant_id={TENANT}").json()
    stored = next(a for a in listed["items"] if a["incident_id"] == platform_incident)
    assert stored["entry_point"]["first_anomalous_event_id"] == "a-login"
    assert [s["event_id"] for s in stored["attack_path"]][0] == "a-login"
    assert {n["type"] for n in stored["graph"]["nodes"]} >= {"user", "host", "ip"}


def test_platform_serves_the_measured_evaluation_not_its_fallback(client):
    import json
    measured = json.loads((backend_dir.parent / "data" / "evaluation" / "evaluation_results.json").read_text(encoding="utf-8"))
    served = client.get("/api/v1/evaluation/summary").json()
    # if the artefact failed the platform's response model it would silently serve hard-coded numbers
    assert served["model_version"] == measured["model_version"] == "pipeline-1.0.0"
    assert served["overall_precision"] == measured["overall_precision"]
    assert served["attribution"]["entry_point_accuracy"] == measured["attribution"]["entry_point_accuracy"]
    assert served["calibration"]["expected_calibration_error"] == measured["calibration"]["expected_calibration_error"]


def test_alert_payload_caps_event_ids_but_keeps_the_count(result):
    big = dict(result["fused_alerts"][0], event_ids=[f"e{i}" for i in range(500)])
    payload = alert_payload(big)
    assert len(payload["event_ids"]) == 200 and payload["evidence"][-1]["event_count"] == 500
