"""Convert one AIT-LDS v2.0 scenario slice into canonical events + label sidecars.

    python -I scripts/convert_ait_scenario.py <scenario dir> <out dir> --scenario russellmitchell --year 2022

Runs every adapter that has input in the slice, one output directory per source and host so
event IDs can never collide between hosts:
    web-<host>/             Apache access logs (file names include the vhost)
    auth-<host>/            auth.log*      (sshd, su, sudo)
    dns-<host>/             dnsmasq.log*
    vpn-<host>/             openvpn.log*
and writes summary.json with the per-source accounting check (lines == events + skipped + unparsed).

Only COMPANY hosts are converted (fetch_remote_zip.company_hosts: AIT's simulated internet -
attacker, external users, remote employees' machines, internet DNS, external mail - is left out
even if its files are present). `--legacy-web` keeps the Phase 1d layout (one `web/` directory
over every host) for the original russellmitchell slice.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "adapters"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import dnsmasq  # noqa: E402
import openvpn  # noqa: E402
import syslog_auth  # noqa: E402
import web_server_logs  # noqa: E402
from fetch_remote_zip import ait_company_hosts  # noqa: E402


def hosts_with(scenario_dir: str, pattern: str, allowed=None):
    found = sorted(glob.glob(os.path.join(scenario_dir, "gather", "*", "logs", pattern)))
    hosts = {Path(p).relative_to(scenario_dir).parts[1] for p in found}
    return sorted(hosts if allowed is None else hosts & set(allowed))


def summarise(report):
    skipped = report.get("skipped_lines", 0)
    return {
        "lines": report["lines"], "events": report["events"], "skipped": skipped,
        "unparsed": report["unparsed_lines"],
        "accounting_ok": report["lines"] == report["events"] + skipped + report["unparsed_lines"],
        "contract_problems": report["contract_problems"],
        "labelled_events": report["labelled_events_moderate"],
        "first_event": report["first_event"], "last_event": report["last_event"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("scenario_dir")
    parser.add_argument("out_dir")
    parser.add_argument("--scenario", required=True, help="e.g. russellmitchell")
    parser.add_argument("--year", type=int, required=True)
    parser.add_argument("--legacy-web", action="store_true", help="Phase 1d layout: one web/ dir, all hosts")
    args = parser.parse_args()

    tenant = f"ait-{args.scenario}"
    dataset = f"ait-lds-v2/{args.scenario}"
    company = ait_company_hosts(args.scenario_dir)
    summary = {"scenario": args.scenario, "tenant_id": tenant, "company_hosts": company, "sources": {}}

    if args.legacy_web:
        report = web_server_logs.convert(
            args.scenario_dir, os.path.join(args.out_dir, "web"), tenant,
            access_glob="gather/*/logs/apache2/*-access.log*", app_regex=r"apache2/(.+?)-access\.log",
            line_labels=True, id_prefix="ait", dataset_name=dataset)
        summary["sources"]["web"] = summarise(report)
    else:
        for host in hosts_with(args.scenario_dir, os.path.join("apache2", "*-access.log*"), company):
            report = web_server_logs.convert(
                args.scenario_dir, os.path.join(args.out_dir, f"web-{host}"), tenant,
                access_glob=f"gather/{host}/logs/apache2/*-access.log*", app_regex=r"apache2/(.+?)-access\.log",
                line_labels=True, id_prefix=f"ait-{host}", dataset_name=dataset)
            summary["sources"][f"web-{host}"] = summarise(report)

    for host in hosts_with(args.scenario_dir, "auth.log*", company):
        report = syslog_auth.convert(
            args.scenario_dir, os.path.join(args.out_dir, f"auth-{host}"), tenant, args.year,
            auth_glob=f"gather/{host}/logs/auth.log*", line_labels=True, id_prefix=f"ait-{host}", dataset_name=dataset)
        summary["sources"][f"auth-{host}"] = summarise(report) | {"events_by_kind": report["events_by_kind"]}

    for host in hosts_with(args.scenario_dir, "dnsmasq.log*", company):
        report = dnsmasq.convert(
            args.scenario_dir, os.path.join(args.out_dir, f"dns-{host}"), tenant, args.year,
            f"gather/{host}/logs/dnsmasq.log*", id_prefix=f"ait-{host}", dataset_name=dataset)
        summary["sources"][f"dns-{host}"] = summarise(report)

    for host in hosts_with(args.scenario_dir, "openvpn.log*", company):
        report = openvpn.convert(
            args.scenario_dir, os.path.join(args.out_dir, f"vpn-{host}"), tenant, f"gather/{host}/logs/openvpn.log*",
            host=host, id_prefix=f"ait-{host}", dataset_name=dataset)
        summary["sources"][f"vpn-{host}"] = summarise(report) | {"connections_by_user": report["connections_by_user"]}

    with open(os.path.join(args.out_dir, "summary.json"), "w", encoding="utf-8", newline="\n") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
