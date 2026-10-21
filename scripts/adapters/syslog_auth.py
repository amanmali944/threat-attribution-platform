"""Adapter: Linux auth.log (sshd + sudo) + ground-truth rules -> canonical events + label sidecar.

Built for Organization Y of the "Web Server Log Dataset" (Zenodo 10.5281/zenodo.20001206,
MIT licence): the server's `var/log/auth.log`.

    python -I scripts/adapters/syslog_auth.py <organization-y dir> <out dir> --tenant org-y --year 2025

Emitted events:
    sshd "Failed <method> for [invalid user] U from IP"  -> identity / user_login  (FAILURE)
    sshd "Accepted <method> for U from IP"               -> identity / user_login  (SUCCESS)
    sudo "U : ... USER=R ; COMMAND=C"                    -> endpoint / process_execution (process_name "sudo")
Skipped but COUNTED (never silently dropped): sshd "Invalid user" lines (they duplicate the
"Failed ... invalid user" line), PAM session open/close, cron, connection close/disconnect,
logind, other sudo lines, everything else.

Assumptions you must keep in mind (also written into report.json):
  * syslog lines carry no year and no time zone. The year is a command-line argument and the
    clock is assumed to be UTC (`--utc-offset` to change it). The dataset's description of
    the incident window (05:28-07:07 on Apr 29) lines up with the first successful root
    logins at 05:34 under this assumption, but the zone is not proven.
  * Labels are rule-derived, not reviewed (see `web_server_logs.py` for the caveats). In this
    data the rules that name the intruder's IP can never match, because the published logs
    were re-anonymised after the rules were written: success-after-brute-force labels are
    therefore absent.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import label_line, load_rules, open_text  # noqa: E402
from app.services.detection import contract as C  # noqa: E402
from app.services.detection.resolve import iso_utc  # noqa: E402

DATASET = "wsld"

SYSLOG_RE = re.compile(
    r"^([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\S+) ([^\s:\[]+)(?:\[(\d+)\])?: ?(.*)$"
)
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

# Usernames come from scanners: they can be empty or contain spaces, so match lazily up to " from ".
FAILED_RE = re.compile(r"^Failed (\S+) for (invalid user )?(.*?) from (\S+) port (\d+)")
ACCEPTED_RE = re.compile(r"^Accepted (\S+) for (.*?) from (\S+) port (\d+)")
EMPTY_USER = "<empty>"  # the contract needs a non-empty identifier
SUDO_RE = re.compile(
    r"^\s*(\S+)\s*:\s*(?:TTY=(\S+)\s*;\s*)?PWD=(\S+)\s*;\s*USER=(\S+)\s*;\s*(?:GROUP=(\S+)\s*;\s*)?COMMAND=(.*)$"
)


def parse_syslog_line(line: str, year: int, utc_offset_hours: float = 0.0) -> Optional[Dict[str, Any]]:
    match = SYSLOG_RE.match(line.rstrip("\r\n"))
    if not match:
        return None
    mon, day, hh, mm, ss, host, process, pid, message = match.groups()
    month = MONTHS.get(mon)
    if month is None:
        return None
    try:
        local = datetime(year, month, int(day), int(hh), int(mm), int(ss),
                         tzinfo=timezone(timedelta(hours=utc_offset_hours)))
    except ValueError:
        return None
    return {
        "observed_at": local.astimezone(timezone.utc),
        "host": host,
        "process": process,
        "pid": int(pid) if pid else None,
        "message": message,
    }


def classify(rec: Dict[str, Any]) -> Tuple[str, Any]:
    """('ssh_failed' | 'ssh_accepted' | 'sudo_command', match) or ('skip', reason)."""
    proc, msg = rec["process"], rec["message"]
    if proc == "sshd":
        m = FAILED_RE.match(msg)
        if m:
            return "ssh_failed", m
        m = ACCEPTED_RE.match(msg)
        if m:
            return "ssh_accepted", m
        if msg.startswith("Invalid user"):
            return "skip", "ssh_invalid_user_duplicate"
        if msg.startswith(("Connection closed", "Disconnected", "Received disconnect", "Connection reset")):
            return "skip", "ssh_connection_noise"
        return "skip", "ssh_other"
    if proc == "sudo":
        m = SUDO_RE.match(msg)
        if m:
            return "sudo_command", m
        return "skip", "sudo_other"
    if proc.startswith("CRON"):
        return "skip", "cron"
    if "pam_unix" in msg:
        return "skip", "pam_session"
    if proc.startswith("systemd-logind"):
        return "skip", "logind"
    return "skip", "other"


def to_event(kind: str, match: "re.Match[str]", rec: Dict[str, Any], tenant: str, source_file: str, lineno: int) -> Dict[str, Any]:
    host = rec["host"]
    base = {
        "event_id": f"{DATASET}-{source_file}-{lineno:07d}",
        "tenant_id": tenant,
        "observed_at": iso_utc(rec["observed_at"]),
        "severity": "info",
        "metadata": {"dataset": "web-server-log-dataset", "source_file": source_file, "line": lineno, "pid": rec["pid"]},
    }
    if kind == "ssh_failed":
        method, invalid, user, ip, port = match.groups()
        user = user.strip() or EMPTY_USER
        return dict(base, source_layer="identity", event_type="user_login",
                    entities=[{"entity_type": "user", "identifier": user}, {"entity_type": "host", "identifier": host}],
                    payload={"result": "FAILURE", "source_ip": ip, "auth_method": method,
                             "invalid_user": bool(invalid), "source_port": int(port), "service": "sshd"})
    if kind == "ssh_accepted":
        method, user, ip, port = match.groups()
        user = user.strip() or EMPTY_USER
        return dict(base, source_layer="identity", event_type="user_login",
                    entities=[{"entity_type": "user", "identifier": user}, {"entity_type": "host", "identifier": host}],
                    payload={"result": "SUCCESS", "source_ip": ip, "auth_method": method,
                             "invalid_user": False, "source_port": int(port), "service": "sshd"})
    invoker, tty, pwd, run_as, run_as_group, command = match.groups()
    payload = {"process_name": "sudo", "command_line": command.strip(), "run_as": run_as, "pwd": pwd}
    if tty:
        payload["tty"] = tty
    if run_as_group:
        payload["run_as_group"] = run_as_group
    return dict(base, source_layer="endpoint", event_type="process_execution",
                entities=[{"entity_type": "host", "identifier": host}, {"entity_type": "user", "identifier": invoker}],
                payload=payload)


def auth_log_files(org_dir: str, auth_glob: str) -> List[str]:
    return sorted(glob.glob(os.path.join(org_dir, auth_glob)))


def convert(
    org_dir: str,
    out_dir: str,
    tenant: str,
    year: int,
    utc_offset_hours: float = 0.0,
    rules_path: Optional[str] = None,
    auth_glob: str = "log/var/log/auth.log",
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    if rules_path is None:
        found = sorted(glob.glob(os.path.join(org_dir, "ground-truth", "*.yaml")))
        if not found:
            raise FileNotFoundError(f"no ground-truth *.yaml under {org_dir}")
        rules_path = found[0]
    rules = load_rules(rules_path)
    files = auth_log_files(org_dir, auth_glob)
    os.makedirs(out_dir, exist_ok=True)

    totals, kinds, skipped = Counter(), Counter(), Counter()
    problems: Counter = Counter()
    labels_moderate: Counter = Counter()
    labels_strict: Counter = Counter()
    failed_ips, failed_users, accepted_ips = set(), set(), set()
    unparsed_samples: List[str] = []
    first = last = None
    per_file: List[Dict[str, Any]] = []

    with open(os.path.join(out_dir, "events.jsonl"), "w", encoding="utf-8", newline="\n") as events_out, \
         open(os.path.join(out_dir, "labels.jsonl"), "w", encoding="utf-8", newline="\n") as labels_out:
        for path in files:
            source_file = os.path.basename(path)
            file_lines = file_events = 0
            with open_text(path) as handle:
                for lineno, line in enumerate(handle, start=1):
                    if limit is not None and totals["events"] >= limit:
                        break
                    file_lines += 1
                    totals["lines"] += 1
                    rec = parse_syslog_line(line, year, utc_offset_hours)
                    if rec is None:
                        totals["unparsed"] += 1
                        if len(unparsed_samples) < 5:
                            unparsed_samples.append(f"{source_file}:{lineno}: {line.strip()[:120]!r}")
                        continue
                    kind, detail = classify(rec)
                    if kind == "skip":
                        skipped[detail] += 1
                        totals["skipped"] += 1
                        continue

                    event = to_event(kind, detail, rec, tenant, source_file, lineno)
                    for problem in C.validate_event(event):
                        problems[problem] += 1
                    events_out.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
                    totals["events"] += 1
                    file_events += 1
                    kinds[kind] += 1
                    if kind == "ssh_failed":
                        failed_ips.add(event["payload"]["source_ip"])
                        failed_users.add(event["entities"][0]["identifier"])
                    elif kind == "ssh_accepted":
                        accepted_ips.add(event["payload"]["source_ip"])

                    hits = label_line(line, None, rules)
                    if hits["moderate"] or hits["strict"]:
                        labels_out.write(json.dumps(
                            {"event_id": event["event_id"], "labels": hits["moderate"], "labels_strict": hits["strict"]},
                            sort_keys=True, separators=(",", ":")) + "\n")
                    if hits["moderate"]:
                        totals["labelled_moderate"] += 1
                        for label in {h["label"] for h in hits["moderate"]}:   # per event, not per rule hit
                            labels_moderate[label] += 1
                    if hits["strict"]:
                        totals["labelled_strict"] += 1
                        for label in {h["label"] for h in hits["strict"]}:
                            labels_strict[label] += 1
                    moment = rec["observed_at"]
                    first = moment if first is None or moment < first else first
                    last = moment if last is None or moment > last else last
            per_file.append({"file": source_file, "lines": file_lines, "events": file_events})

    with open(rules_path, "rb") as handle:
        rules_sha = hashlib.sha256(handle.read()).hexdigest()
    report = {
        "dataset": "web-server-log-dataset",
        "source": "auth.log (sshd, sudo)",
        "tenant_id": tenant,
        "timestamp_assumptions": {"year": year, "utc_offset_hours": utc_offset_hours,
                                  "note": "syslog has no year or zone; both are assumed"},
        "rules_file": os.path.basename(rules_path),
        "rules_sha256": rules_sha,
        "rules_loaded": len(rules),
        "files": per_file,
        "lines": totals["lines"],
        "events": totals["events"],
        "events_by_kind": dict(sorted(kinds.items())),
        "skipped_lines": totals["skipped"],
        "skipped_by_reason": dict(sorted(skipped.items())),
        "unparsed_lines": totals["unparsed"],
        "unparsed_samples": unparsed_samples,
        "accounting": "lines == events + skipped_lines + unparsed_lines",
        "contract_problems": dict(problems),
        "first_event": iso_utc(first) if first else None,
        "last_event": iso_utc(last) if last else None,
        "ssh_failed_distinct_source_ips": len(failed_ips),
        "ssh_failed_distinct_usernames": len(failed_users),
        "ssh_accepted_distinct_source_ips": len(accepted_ips),
        "labelled_events_moderate": totals["labelled_moderate"],
        "labelled_events_strict": totals["labelled_strict"],
        "label_counts_moderate": dict(sorted(labels_moderate.items())),
        "label_counts_strict": dict(sorted(labels_strict.items())),
        "label_semantics": "rule-derived, approximate; intruder-IP rules cannot match anonymised data",
    }
    with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return report


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("org_dir")
    parser.add_argument("out_dir")
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--year", type=int, required=True, help="syslog lines have no year")
    parser.add_argument("--utc-offset", type=float, default=0.0, help="hours; syslog clock assumed UTC by default")
    parser.add_argument("--rules", default=None)
    parser.add_argument("--auth-glob", default="log/var/log/auth.log", help="relative to org_dir")
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args(argv)
    report = convert(args.org_dir, args.out_dir, args.tenant, args.year, args.utc_offset,
                     args.rules, args.auth_glob, args.limit)
    print(json.dumps({k: v for k, v in report.items() if k != "files"}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
