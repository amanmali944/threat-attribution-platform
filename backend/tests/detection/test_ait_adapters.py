import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

from app.services.detection import contract as C
from app.services.detection.features import extract
from app.services.detection.resolve import entity_id, resolve_event

REPO = Path(__file__).resolve().parents[3]


def _load(name):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / "adapters" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


common = _load("_common")
dnsmasq = _load("dnsmasq")
openvpn = _load("openvpn")
syslog_auth = _load("syslog_auth")
web = _load("web_server_logs")


def write(path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def label_line(n, *labels):
    return json.dumps({"line": n, "labels": list(labels), "rules": {lab: [f"rule.{lab}"] for lab in labels}})


# ------------------------------------------------------------------ AIT per-line labels


def test_line_labels_follow_the_gather_path(tmp_path):
    raw = tmp_path / "gather" / "h1" / "logs" / "x.log"
    write(raw, ["a", "b", "c"])
    write(tmp_path / "labels" / "h1" / "logs" / "x.log", [label_line(2, "foothold", "dirb")])
    assert common.ait_label_path(str(tmp_path), str(raw)) == str(tmp_path / "labels" / "h1" / "logs" / "x.log")
    labeller = common.LineLabeller(str(tmp_path))
    assert labeller.hits(str(raw), 2, "b")["moderate"] == [
        {"rule_id": "rule.foothold", "label": "foothold"}, {"rule_id": "rule.dirb", "label": "dirb"}]
    assert labeller.hits(str(raw), 1, "a") == {"moderate": [], "strict": []}


def test_a_log_without_a_label_file_has_no_attack_lines(tmp_path):
    raw = tmp_path / "gather" / "h1" / "logs" / "clean.log"
    write(raw, ["a"])
    assert common.load_line_labels(common.ait_label_path(str(tmp_path), str(raw))) == {}


# ------------------------------------------------------------------ dnsmasq

Q = "Jan 24 03:01:21 dnsmasq[3468]: query[A] host7.sub.example.com from 10.0.0.5"
FWD = "Jan 24 03:01:21 dnsmasq[3468]: forwarded host7.sub.example.com to 192.0.2.254"
REPLY = "Jan 24 03:01:21 dnsmasq[3468]: reply host7.sub.example.com is 198.51.100.4"
CACHED = "Jan 24 03:01:22 dnsmasq[3468]: cached host7.sub.example.com is 198.51.100.4"


def test_dnsmasq_parse_and_classify():
    rec = dnsmasq.parse_line(Q, 2022)
    assert rec["observed_at"].isoformat() == "2022-01-24T03:01:21+00:00"
    assert dnsmasq.classify(rec["message"])[0] == "query"
    for line, reason in ((FWD, "forwarded"), (REPLY, "reply"), (CACHED, "cached")):
        assert dnsmasq.classify(dnsmasq.parse_line(line, 2022)["message"]) == ("skip", reason)
    assert dnsmasq.parse_line("garbage", 2022) is None


def test_base_domain():
    assert dnsmasq.base_domain("a.b.example.com") == "example.com"
    assert dnsmasq.base_domain("example.com.") == "example.com"
    assert dnsmasq.base_domain("localhost") == "localhost"


def test_dnsmasq_event_is_valid_and_resolves():
    rec = dnsmasq.parse_line(Q, 2022)
    event = dnsmasq.to_event(dnsmasq.classify(rec["message"])[1], rec, "t", "dnsmasq.log", 7, "ait-fw", "ds")
    assert C.validate_event(event) == []
    assert event["event_id"] == "ait-fw-dnsmasq.log-0000007"
    assert event["payload"]["query_length"] == len("host7.sub.example.com") and event["payload"]["label_count"] == 4
    resolved = resolve_event(event)
    assert resolved.actor_ip.identifier == "10.0.0.5"
    assert resolved.target.entity_type == "domain" and resolved.target.identifier == "example.com"


def test_dnsmasq_convert_counts_and_labels(tmp_path):
    write(tmp_path / "gather" / "fw" / "logs" / "dnsmasq.log", [Q, FWD, REPLY, CACHED, "garbage",
                                                               Q.replace("host7", "host8")])
    write(tmp_path / "labels" / "fw" / "logs" / "dnsmasq.log", [label_line(1, "dns_scan"), label_line(2, "dns_scan")])
    report = dnsmasq.convert(str(tmp_path), str(tmp_path / "out"), "t", 2022, "gather/fw/logs/dnsmasq.log*")
    assert (report["lines"], report["events"], report["skipped_lines"], report["unparsed_lines"]) == (6, 2, 3, 1)
    assert report["skipped_by_reason"] == {"cached": 1, "forwarded": 1, "reply": 1}
    assert report["labelled_events_moderate"] == 1          # the labelled "forwarded" line makes no event
    assert report["distinct_base_domains"] == 1 and report["contract_problems"] == {}


# ------------------------------------------------------------------ openvpn

HANDSHAKE = [
    "2022-01-24 03:01:00 192.0.2.122:53581 TLS: Initial packet from [AF_INET]192.0.2.122:53581, sid=1 2",
    "2022-01-24 03:01:00 192.0.2.122:53581 VERIFY OK: depth=0, CN=jhall",
    "2022-01-24 03:01:00 192.0.2.122:53581 [jhall] Peer Connection Initiated with [AF_INET]192.0.2.122:53581",
    "2022-01-24 03:01:00 jhall/192.0.2.122:53581 MULTI: primary virtual IP for jhall/192.0.2.122:53581: 10.9.0.10",
    "2022-01-24 03:16:45 jhall/192.0.2.165:59384 TLS: soft reset sec=3261/3261 bytes=45388/-1 pkts=642/0",
]


def test_openvpn_one_login_per_connection():
    kinds = [openvpn.classify(openvpn.parse_line(l)["message"])[0:2] for l in HANDSHAKE]
    assert [k[0] for k in kinds] == ["skip", "skip", "skip", "connected", "skip"]
    assert kinds[4] == ("skip", "tls_soft_reset")
    assert openvpn.classify("TLS Error: TLS handshake failed") == ("skip", "tls_error")


def test_openvpn_event_is_valid_and_resolves():
    rec = openvpn.parse_line(HANDSHAKE[3])
    event = openvpn.to_event(openvpn.classify(rec["message"])[1], rec, "t", "openvpn.log", 4, "vpn", "ait-vpn", "ds")
    assert C.validate_event(event) == []
    assert event["payload"]["vpn_ip"] == "10.9.0.10" and event["payload"]["source_port"] == 53581
    resolved = resolve_event(event)
    assert resolved.actor_user.identifier == "jhall" and resolved.actor_ip.identifier == "192.0.2.122"
    assert resolved.target.identifier == "vpn" and resolved.outcome == "success"


def test_openvpn_convert(tmp_path):
    write(tmp_path / "gather" / "vpn" / "logs" / "openvpn.log", HANDSHAKE)
    write(tmp_path / "labels" / "vpn" / "logs" / "openvpn.log", [label_line(n, "attacker_vpn") for n in (1, 2, 3, 4)])
    report = openvpn.convert(str(tmp_path), str(tmp_path / "out"), "t", "gather/vpn/logs/openvpn.log*")
    assert (report["lines"], report["events"], report["skipped_lines"]) == (5, 1, 4)
    assert report["connections_by_user"] == {"jhall": 1} and report["labelled_events_moderate"] == 1


# ------------------------------------------------------------------ su (syslog_auth) and web line-label mode

SU_OK = "Jan 24 04:37:40 intranet-server su[27950]: Successful su for jhall by www-data"
SU_FAIL = "Jan 24 04:37:41 intranet-server su[27951]: FAILED su for root by jhall"


def test_su_becomes_a_privileged_process_execution():
    rec = syslog_auth.parse_syslog_line(SU_OK, 2022)
    kind, match = syslog_auth.classify(rec)
    assert kind == "su_success"
    event = syslog_auth.to_event(kind, match, rec, "t", "auth.log", 1, "ait-h", "ds")
    assert C.validate_event(event) == []
    assert event["payload"] == {"process_name": "su", "command_line": "su jhall", "run_as": "jhall"}
    resolved = resolve_event(event)
    assert resolved.actor_user.identifier == "www-data" and resolved.target.identifier == "intranet-server"
    vec = next(v for v in extract([event])["vectors"] if v["entity_id"] == entity_id("user", "t", "www-data"))
    assert vec["features"]["privilege.privileged_ops"] == 1
    assert syslog_auth.classify(syslog_auth.parse_syslog_line(SU_FAIL, 2022)) == ("skip", "su_failed")


def test_web_adapter_line_label_mode(tmp_path):
    line = '10.0.0.9 - - [24/Jan/2022:03:57:26 +0000] "GET /admin HTTP/1.1" 404 10 "-" "DirBuster"'
    write(tmp_path / "gather" / "srv" / "logs" / "apache2" / "site-access.log", [line, line.replace("/admin", "/")])
    write(tmp_path / "labels" / "srv" / "logs" / "apache2" / "site-access.log", [label_line(1, "dirb", "foothold")])
    report = web.convert(str(tmp_path), str(tmp_path / "out"), "t", access_glob="gather/*/logs/apache2/*-access.log*",
                         app_regex=r"apache2/(.+?)-access\.log", line_labels=True, id_prefix="ait", dataset_name="ds")
    assert report["label_source"] == "line-labels" and report["rules_file"] is None
    assert report["labelled_events_moderate"] == 1 and report["label_counts_moderate"] == {"dirb": 1, "foothold": 1}
    events = [json.loads(x) for x in (tmp_path / "out" / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert events[0]["event_id"] == "ait-site-access.log-0000001"
    assert events[0]["entities"][0] == {"entity_type": "application", "identifier": "site"}


# ------------------------------------------------------------------ real AIT data (skipped if absent)

SCENARIO = REPO / "data" / "external" / "ait" / "russellmitchell"
DERIVED = REPO / "data" / "external" / "ait" / "derived" / "russellmitchell"


def _labelled_raw_lines(rel):
    raw = (SCENARIO / "gather" / rel).read_text(encoding="utf-8", errors="replace").splitlines()
    labels = [json.loads(x) for x in (SCENARIO / "labels" / rel).read_text(encoding="utf-8").splitlines() if x.strip()]
    return [raw[rec["line"] - 1] for rec in labels]


@pytest.mark.skipif(not (DERIVED / "summary.json").exists(), reason="AIT slice not converted")
def test_ait_conversion_accounts_for_every_line_and_every_label():
    summary = json.loads((DERIVED / "summary.json").read_text(encoding="utf-8"))
    for name, source in summary["sources"].items():
        assert source["accounting_ok"], name
        assert source["contract_problems"] == {}, name

    # Independent recount from AIT's own label files: every labelled line that is an event
    # kind we convert must come out as a labelled event.
    web_rel = "intranet_server/logs/apache2/intranet.smith.russellmitchell.com-access.log.2"
    assert summary["sources"]["web"]["labelled_events"] == len(_labelled_raw_lines(web_rel))
    dns = [l for l in _labelled_raw_lines("inet-firewall/logs/dnsmasq.log") if re.search(r"dnsmasq\[\d+\]: query\[", l)]
    assert summary["sources"]["dns-inet-firewall"]["labelled_events"] == len(dns)
    vpn = [l for l in _labelled_raw_lines("vpn/logs/openvpn.log") if "primary virtual IP for" in l]
    assert summary["sources"]["vpn-vpn"]["labelled_events"] == len(vpn) == 1
    auth = [l for l in _labelled_raw_lines("intranet_server/logs/auth.log")
            if "Successful su for" in l or ("sudo:" in l and "COMMAND=" in l)]
    assert summary["sources"]["auth-intranet_server"]["labelled_events"] == len(auth)
