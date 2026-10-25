"""Offline tests for the AIT slice selection in scripts/fetch_remote_zip.py (no network)."""
import importlib.util
import io
import sys
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location("fetch_remote_zip", REPO / "scripts" / "fetch_remote_zip.py")
fetch = importlib.util.module_from_spec(_spec)
sys.modules["fetch_remote_zip"] = fetch
_spec.loader.exec_module(fetch)

SERVERS_YAML = """\
attacker_0:
  hostname: attacker-0
  default_ipv4_address: 192.168.230.122
  ipv4_addresses:
vpn:
  hostname: vpn
  default_ipv4_address: 172.19.131.174
intranet_server:
  hostname: intranet-server
  default_ipv4_address: 10.143.2.4
  ipv4_addresses:
    - default_ipv4_address: 1.2.3.4
inet-dns:
  hostname: inet-dns
  default_ipv4_address: 192.168.231.254
inet-firewall:
  hostname: inet-firewall
  default_ipv4_address: 172.19.128.1
"""

NAMES = [
    "dataset.yaml",
    "gather/attacker_0/logs/attacks.log",
    "gather/attacker_0/logs/auth.log",
    "processing/config/servers.yaml",
    "processing/config/logs.yaml",
    "processing/process.yaml",
    "gather/intranet_server/logs/apache2/intranet.example.com-access.log.2",
    "gather/intranet_server/logs/apache2/intranet.example.com-error.log.2",
    "gather/intranet_server/logs/auth.log",
    "gather/intranet_server/logs/auth.log.1",
    "gather/intranet_server/logs/audit/audit.log",
    "gather/inet-firewall/logs/dnsmasq.log",
    "gather/inet-dns/logs/dnsmasq.log",
    "gather/vpn/logs/openvpn.log",
    "labels/intranet_server/logs/apache2/intranet.example.com-access.log.2",
    "labels/intranet_server/logs/apache2/intranet.example.com-error.log.2",
    "labels/inet-firewall/logs/dnsmasq.log",
    "labels/inet-dns/logs/dnsmasq.log",
]


def test_host_addresses_read_only_the_top_level_default():
    assert fetch.ait_host_addresses(SERVERS_YAML) == {
        "attacker_0": "192.168.230.122", "vpn": "172.19.131.174", "intranet_server": "10.143.2.4",
        "inet-dns": "192.168.231.254", "inet-firewall": "172.19.128.1",
    }


def test_company_hosts_exclude_the_simulated_internet():
    hosts = fetch.company_hosts(fetch.ait_host_addresses(SERVERS_YAML))
    assert hosts == ["inet-firewall", "intranet_server", "vpn"]          # attacker and internet DNS excluded


@pytest.mark.parametrize("host, company", [
    ("mail", True), ("davey_mail", False), ("rogersturnbull_mail", False),   # company mail vs external providers
    ("remote_employee_3", False), ("ext_user_12", False), ("attacker_0", False), ("inet-dns", False),
    ("inet-firewall", True), ("internal_employee_4", True), ("internal_share", True), ("cloud_share", True),
    ("monitoring", True), ("webserver", True),
])
def test_company_host_rule_is_by_role_name_not_address(host, company):
    # AIT randomises addresses per scenario (the internet is 192.168.x in one, 10.229.x in another)
    assert (fetch.company_hosts([host]) == [host]) is company


def test_ait_company_hosts_reads_an_extracted_scenario(tmp_path):
    (tmp_path / "processing" / "config").mkdir(parents=True)
    (tmp_path / "processing" / "config" / "servers.yaml").write_text(SERVERS_YAML, encoding="utf-8")
    assert fetch.ait_company_hosts(str(tmp_path)) == ["inet-firewall", "intranet_server", "vpn"]


def test_metadata_selection():
    assert fetch.select_ait_metadata(NAMES) == [
        "dataset.yaml", "gather/attacker_0/logs/attacks.log",
        "processing/config/logs.yaml", "processing/config/servers.yaml",
    ]


def test_log_selection_keeps_company_access_auth_dns_vpn_and_their_labels():
    chosen = fetch.select_ait_logs(NAMES, ["inet-firewall", "intranet_server", "vpn"])
    assert chosen == [
        "gather/inet-firewall/logs/dnsmasq.log",
        "gather/intranet_server/logs/apache2/intranet.example.com-access.log.2",
        "gather/intranet_server/logs/auth.log",
        "gather/intranet_server/logs/auth.log.1",
        "gather/vpn/logs/openvpn.log",
        "labels/inet-firewall/logs/dnsmasq.log",
        "labels/intranet_server/logs/apache2/intranet.example.com-access.log.2",
    ]   # no error logs, no audit logs, nothing from internet hosts or the attacker


@pytest.mark.parametrize("name, safe", [
    ("gather/a/logs/auth.log", True), ("../evil", False), ("/etc/passwd", False),
    ("a\\..\\b", False), ("C:/x", False),
])
def test_unsafe_member_names_are_detected(name, safe):
    assert fetch.is_safe(name) is safe


def test_extract_refuses_a_non_empty_destination_and_resumes(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("gather/h/logs/auth.log", "line\n")
    zf = zipfile.ZipFile(io.BytesIO(buffer.getvalue()))
    dest = tmp_path / "out"
    fetch.extract(zf, str(dest), ["gather/h/logs/auth.log"], resume=False)
    assert (dest / "gather" / "h" / "logs" / "auth.log").read_text() == "line\n"
    with pytest.raises(SystemExit, match="not empty"):
        fetch.extract(zf, str(dest), ["gather/h/logs/auth.log"], resume=False)
    fetch.extract(zf, str(dest), ["gather/h/logs/auth.log"], resume=True)   # already present: skipped


def test_extract_refuses_path_traversal(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("../escape.txt", "x")
    zf = zipfile.ZipFile(io.BytesIO(buffer.getvalue()))
    with pytest.raises(SystemExit, match="unsafe"):
        fetch.extract(zf, str(tmp_path / "out"), ["../escape.txt"], resume=False)
    assert not (tmp_path / "escape.txt").exists()
