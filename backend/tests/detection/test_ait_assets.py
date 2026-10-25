"""scripts/adapters/ait_assets.py: AIT servers.yaml -> company asset inventory."""
import importlib.util
import sys
from pathlib import Path

import pytest

from app.services.detection.resolve import entity_id

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "scripts"))
_spec = importlib.util.spec_from_file_location("ait_assets", REPO / "scripts" / "adapters" / "ait_assets.py")
assets = importlib.util.module_from_spec(_spec)
sys.modules["ait_assets"] = assets
_spec.loader.exec_module(assets)

SERVERS = """\
vpn:
  hostname: vpn
  groups:
    - dmz
    - servers
  default_ipv4_address: 172.19.131.174
  ipv4_addresses:
    - 172.19.131.174
  fqdns:
    - vpn.dmz.example.com
  logs:
    - path: openvpn.log*
      type: openvpn
inet-firewall:
  hostname: inet-firewall
  groups:
    - firewall
    - servers
  default_ipv4_address: 172.19.128.1
  ipv4_addresses:
    - 10.143.0.1
    - 172.19.128.1
  fqdns: []
internal_employee_0:
  hostname: internal-employee-0
  groups:
    - employee
  default_ipv4_address: 10.143.1.78
  ipv4_addresses:
    - 10.143.1.78
  fqdns:
    - Employee00.Intranet.example.com
attacker_0:
  hostname: attacker-0
  default_ipv4_address: 192.168.230.122
  ipv4_addresses:
    - 192.168.230.122
"""


def test_parser_reads_lists_and_scalars_and_ignores_nested_blocks():
    parsed = assets.parse_servers(SERVERS)
    assert parsed["vpn"]["groups"] == ["dmz", "servers"]
    assert parsed["vpn"]["ipv4_addresses"] == ["172.19.131.174"] and parsed["vpn"]["fqdns"] == ["vpn.dmz.example.com"]
    assert parsed["inet-firewall"]["ipv4_addresses"] == ["10.143.0.1", "172.19.128.1"]
    assert parsed["inet-firewall"]["fqdns"] == []                  # inline empty list stays empty
    assert "path" not in parsed["vpn"]                             # the nested logs block is not read


def test_inventory_keeps_company_hosts_maps_addresses_and_rates_criticality():
    inv = assets.inventory(SERVERS, "t1")
    names = [h["hostname"] for h in inv["hosts"]]
    assert names == ["inet-firewall", "internal-employee-0", "vpn"]          # the attacker is not an asset
    assert inv["ip_to_host"] == {"10.143.0.1": "inet-firewall", "172.19.128.1": "inet-firewall",
                                 "10.143.1.78": "internal-employee-0", "172.19.131.174": "vpn"}
    assert inv["fqdn_to_host"]["employee00.intranet.example.com"] == "internal-employee-0"   # lower-cased
    by_name = {h["hostname"]: h for h in inv["hosts"]}
    assert by_name["vpn"]["criticality"] == 4 and by_name["internal-employee-0"]["criticality"] == 2
    assert by_name["vpn"]["entity_id"] == entity_id("host", "t1", "vpn")
    assert by_name["vpn"]["ip_entity_ids"] == [entity_id("ip", "t1", "172.19.131.174")]


def test_an_address_claimed_by_two_hosts_is_refused():
    clash = SERVERS.replace("    - 10.143.1.78", "    - 172.19.131.174")
    with pytest.raises(ValueError, match="claimed by"):
        assets.inventory(clash, "t1")


def test_real_scenario_inventory():
    path = REPO / "data" / "external" / "ait" / "scenarios" / "russellmitchell" / "processing" / "config" / "servers.yaml"
    if not path.exists():
        pytest.skip("russellmitchell slice not downloaded")
    inv = assets.inventory(path.read_text(encoding="utf-8"), "ait-russellmitchell")
    assert inv["ip_to_host"]["172.19.131.174"] == "vpn"
    assert inv["ip_to_host"]["10.143.2.4"] == "intranet-server"
    assert inv["fqdn_to_host"]["intranet.smith.russellmitchell.com"] == "intranet-server"
    assert not any(h["hostname"].startswith(("attacker", "ext-user", "remote-employee")) for h in inv["hosts"])
