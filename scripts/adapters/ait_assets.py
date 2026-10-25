"""Adapter: AIT-LDS `processing/config/servers.yaml` -> asset inventory of the COMPANY's hosts.

    python -I scripts/adapters/ait_assets.py <scenario dir> <out json> --tenant ait-russellmitchell

A defender knows its own servers: hostnames, addresses, DNS names and roles (a CMDB). This is
the input that lets correlation and attribution connect layers - e.g. web and DNS activity seen
from an address to the host that owns it. Internet hosts (attacker, external users, remote
employees, internet DNS, external mail) are excluded with the same rule as the slice
(fetch_remote_zip.company_hosts).

Output:
    {"tenant_id", "source", "hosts": [{"key", "hostname", "entity_id", "ipv4": [...], "ip_entity_ids": [...],
      "fqdns": [...], "groups": [...], "criticality"}], "ip_to_host": {ip: hostname},
     "fqdn_to_host": {fqdn: hostname}}       # web vhosts (application entities) are FQDNs

Criticality (1-5) from the host's groups: servers 4, everything else (workstations, monitoring
clients) 2. No host is marked 5 - nothing in the metadata says which data matters most.

Only the fields used are parsed (top-level host keys, two-space scalar fields, four-space
"- item" lists), so no YAML library is needed.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.detection.resolve import entity_id  # noqa: E402
from fetch_remote_zip import company_hosts  # noqa: E402

LIST_FIELDS = ("groups", "ipv4_addresses", "fqdns")
SCALAR_FIELDS = ("hostname", "default_ipv4_address")


def parse_servers(text: str) -> Dict[str, Dict[str, Any]]:
    hosts: Dict[str, Dict[str, Any]] = {}
    current, current_list = None, None
    for raw in text.splitlines():
        line = raw.rstrip()
        top = re.match(r"^([A-Za-z0-9_.-]+):\s*$", line)
        if top:
            current, current_list = top.group(1), None
            hosts[current] = {f: [] for f in LIST_FIELDS}
            continue
        if current is None:
            continue
        field = re.match(r"^  ([a-z0-9_]+):\s*(.*)$", line)
        if field:
            name, value = field.groups()
            current_list = name if name in LIST_FIELDS and value == "" else None
            if name in SCALAR_FIELDS:
                hosts[current][name] = value.strip().strip("'\"")
            continue
        item = re.match(r"^ {4}- (.+)$", line)
        if item and current_list:
            hosts[current][current_list].append(item.group(1).strip().strip("'\""))
        elif not line.startswith("    "):
            current_list = None
    return hosts


def inventory(servers_yaml: str, tenant: str) -> Dict[str, Any]:
    parsed = parse_servers(servers_yaml)
    rows: List[Dict[str, Any]] = []
    ip_to_host: Dict[str, str] = {}
    fqdn_to_host: Dict[str, str] = {}
    for key in company_hosts(parsed):
        info = parsed[key]
        hostname = info.get("hostname") or key
        ips = sorted(set(info["ipv4_addresses"]) | ({info["default_ipv4_address"]} if info.get("default_ipv4_address") else set()))
        groups = sorted(info["groups"])
        rows.append({
            "key": key, "hostname": hostname, "entity_id": entity_id("host", tenant, hostname),
            "ipv4": ips, "ip_entity_ids": [entity_id("ip", tenant, ip) for ip in ips],
            "fqdns": sorted(info["fqdns"]), "groups": groups,
            "criticality": 4 if "servers" in groups else 2,
        })
        for ip in ips:
            if ip in ip_to_host and ip_to_host[ip] != hostname:
                raise ValueError(f"address {ip} claimed by {ip_to_host[ip]} and {hostname}")
            ip_to_host[ip] = hostname
        for fqdn in info["fqdns"]:
            fqdn_to_host.setdefault(fqdn.lower(), hostname)
    return {"tenant_id": tenant, "source": "processing/config/servers.yaml (company hosts only)",
            "hosts": rows, "ip_to_host": dict(sorted(ip_to_host.items())),
            "fqdn_to_host": dict(sorted(fqdn_to_host.items()))}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("scenario_dir")
    parser.add_argument("out")
    parser.add_argument("--tenant", required=True)
    args = parser.parse_args()
    text = Path(args.scenario_dir, "processing", "config", "servers.yaml").read_text(encoding="utf-8")
    result = inventory(text, args.tenant)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"hosts": len(result["hosts"]), "addresses": len(result["ip_to_host"])}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
