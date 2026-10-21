"""Adapter: Apache / OpenLiteSpeed access logs + ground-truth rules -> canonical events + label sidecar.

Built for the "Web Server Log Dataset" (Zenodo 10.5281/zenodo.20001206, MIT licence):
real web-server logs from two public-sector organisations, with ground truth given as
text-pattern rules rather than per-line labels.

    # Organization X (one rotated log set)
    python -I scripts/adapters/web_server_logs.py <organization-x dir> <out dir> --tenant org-x

    # Organization Y (one access log per virtual host; application = the vhost name)
    python -I scripts/adapters/web_server_logs.py <organization-y dir> <out dir> --tenant org-y \\
        --access-glob "log/home/*/logs/*.access_log*" --app-regex "home/([^/]+)/logs/"

Outputs (all inside <out dir>):
    events.jsonl   canonical events (docs/EVENT_SCHEMA.md), one per access-log line
    labels.jsonl   one record per labelled event; kept OUT of the events so a detector
                   never sees them
    report.json    counts, skipped lines, contract problems, label distribution

Label semantics - read before trusting any number computed from these labels:
  * Labels come from the dataset authors' rules (text patterns, ALL must match, case
    insensitive), not from human review of each line.
  * The authors matched against log2timeline-processed events; here the rules are applied
    to the raw log line, with `code: NNN` patterns matched against the HTTP status. This is
    an approximate re-implementation, not their exact pipeline.
  * `%` in a pattern is treated as a wildcard (so `SELECT%` means "contains select").
  * Rules marked `strict` are reported separately from `moderate` ones.
  * Many rules key on the user-agent or URL, so a model can learn the rules themselves.
    Evaluation on these labels measures agreement with the rules, not independent truth.
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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import Rule, label_line, load_rules, open_text  # noqa: E402,F401
from app.services.detection import contract as C  # noqa: E402
from app.services.detection.resolve import iso_utc  # noqa: E402

_open_text = open_text  # kept for callers that used the old private name

DATASET = "wsld"  # prefix for event IDs
APPLICATION = "web-application"

_FIELD = r'"((?:[^"\\]|\\.)*)"'  # a quoted field; Apache escapes inner quotes as \"
ACCESS_RE = re.compile(
    r"^(\S+) (\S+) (\S+) \[([^\]]+)\] " + _FIELD + r" (\d{3}) (\S+) " + _FIELD + " " + _FIELD
)


# --------------------------------------------------------------------------- parsing


def parse_access_line(line: str) -> Optional[Dict[str, Any]]:
    """Apache combined-format line -> dict, or None if it does not parse."""
    match = ACCESS_RE.match(line.rstrip("\r\n"))
    if not match:
        return None
    ip, _ident, user, stamp, request, status, size, referer, agent = match.groups()
    try:
        moment = datetime.strptime(stamp, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    except ValueError:
        return None

    parts = request.split(" ")
    if len(parts) >= 3 and parts[-1].startswith("HTTP/"):
        method, target, protocol = parts[0], " ".join(parts[1:-1]), parts[-1]
    elif len(parts) >= 2:
        method, target, protocol = parts[0], " ".join(parts[1:]), ""
    else:
        method, target, protocol = (parts[0] or "-"), "-", ""

    return {
        "ip": ip,
        "user": None if user == "-" else user,
        "observed_at": moment,
        "method": method or "-",
        "path": target or "-",
        "protocol": protocol,
        "status_code": int(status),
        "bytes_out": int(size) if size.isdigit() else 0,
        "referer": None if referer == "-" else referer,
        "user_agent": None if agent == "-" else agent,
    }


def canonical_file_name(path: str) -> str:
    name = os.path.basename(path)
    return name[:-3] if name.endswith(".gz") else name


def to_event(
    record: Dict[str, Any],
    tenant: str,
    source_file: str,
    lineno: int,
    application: str = APPLICATION,
) -> Dict[str, Any]:
    entities = [{"entity_type": "application", "identifier": application}]
    if record["user"]:
        entities.insert(0, {"entity_type": "user", "identifier": record["user"]})
    payload = {
        "method": record["method"],
        "path": record["path"],
        "status_code": record["status_code"],
        "bytes_out": record["bytes_out"],
        "source_ip": record["ip"],
    }
    for key in ("protocol", "referer", "user_agent"):
        if record[key]:
            payload[key] = record[key]
    return {
        "event_id": f"{DATASET}-{source_file}-{lineno:07d}",
        "tenant_id": tenant,
        "source_layer": "application",
        "event_type": "http_request",
        "observed_at": iso_utc(record["observed_at"]),
        "severity": "info",
        "entities": entities,
        "payload": payload,
        "metadata": {"dataset": "web-server-log-dataset", "source_file": source_file, "line": lineno},
    }


# --------------------------------------------------------------------------- conversion


def _rotation_index(path: str) -> int:
    """web-access.log -> 0 (newest), web-access.log.1 -> 1, web-access.log.14.gz -> 14."""
    match = re.search(r"\.log(?:\.(\d+))?(?:\.gz)?$", os.path.basename(path))
    return int(match.group(1)) if match and match.group(1) else 0


def access_log_files(org_dir: str, access_glob: Optional[str] = None) -> List[str]:
    """Access logs to convert. Default: Org X layout, oldest rotation first.

    With ``access_glob`` (relative to ``org_dir``) the files are returned sorted by path.
    """
    if access_glob:
        return sorted(glob.glob(os.path.join(org_dir, access_glob)))
    found = glob.glob(os.path.join(org_dir, "log", "apache2", "web-access.log*"))
    return sorted(found, key=lambda p: (-_rotation_index(p), p))  # oldest first


def find_rules_file(org_dir: str) -> str:
    found = sorted(glob.glob(os.path.join(org_dir, "ground-truth", "*.yaml")))
    if not found:
        raise FileNotFoundError(f"no ground-truth *.yaml under {org_dir}")
    return found[0]


def convert(
    org_dir: str,
    out_dir: str,
    tenant: str,
    rules_path: Optional[str] = None,
    limit: Optional[int] = None,
    access_glob: Optional[str] = None,
    app_regex: Optional[str] = None,
) -> Dict[str, Any]:
    rules_path = rules_path or find_rules_file(org_dir)
    rules = load_rules(rules_path)
    files = access_log_files(org_dir, access_glob)
    app_pattern = re.compile(app_regex) if app_regex else None
    os.makedirs(out_dir, exist_ok=True)

    totals = Counter()
    unparsed_samples: List[str] = []
    problems: Counter = Counter()
    labels_moderate: Counter = Counter()
    labels_strict: Counter = Counter()
    statuses: Counter = Counter()
    ips: Counter = Counter()
    applications: Counter = Counter()
    first = last = None
    per_file: List[Dict[str, Any]] = []

    with open(os.path.join(out_dir, "events.jsonl"), "w", encoding="utf-8", newline="\n") as events_out, \
         open(os.path.join(out_dir, "labels.jsonl"), "w", encoding="utf-8", newline="\n") as labels_out:
        for path in files:
            source_file = canonical_file_name(path)
            application = APPLICATION
            if app_pattern is not None:
                found = app_pattern.search(os.path.relpath(path, org_dir).replace(os.sep, "/"))
                if found:
                    application = found.group(1)
            file_lines = file_events = 0
            with open_text(path) as handle:
                for lineno, line in enumerate(handle, start=1):
                    if limit is not None and totals["events"] >= limit:
                        break
                    file_lines += 1
                    totals["lines"] += 1
                    record = parse_access_line(line)
                    if record is None:
                        totals["unparsed"] += 1
                        if len(unparsed_samples) < 5:
                            unparsed_samples.append(f"{source_file}:{lineno}: {line.strip()[:200]}")
                        continue

                    event = to_event(record, tenant, source_file, lineno, application)
                    for problem in C.validate_event(event):
                        problems[problem] += 1
                    events_out.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
                    totals["events"] += 1
                    file_events += 1

                    hits = label_line(line, record["status_code"], rules)
                    if hits["moderate"] or hits["strict"]:
                        labels_out.write(
                            json.dumps(
                                {"event_id": event["event_id"], "labels": hits["moderate"], "labels_strict": hits["strict"]},
                                sort_keys=True,
                                separators=(",", ":"),
                            )
                            + "\n"
                        )
                    if hits["moderate"]:
                        totals["labelled_moderate"] += 1
                        for label in {h["label"] for h in hits["moderate"]}:   # per event, not per rule hit
                            labels_moderate[label] += 1
                    if hits["strict"]:
                        totals["labelled_strict"] += 1
                        for label in {h["label"] for h in hits["strict"]}:
                            labels_strict[label] += 1

                    statuses[str(record["status_code"])] += 1
                    ips[record["ip"]] += 1
                    applications[application] += 1
                    moment = record["observed_at"]
                    first = moment if first is None or moment < first else first
                    last = moment if last is None or moment > last else last
            per_file.append({"file": source_file, "application": application, "lines": file_lines, "events": file_events})

    with open(rules_path, "rb") as handle:
        rules_sha = hashlib.sha256(handle.read()).hexdigest()
    report = {
        "dataset": "web-server-log-dataset",
        "tenant_id": tenant,
        "rules_file": os.path.basename(rules_path),
        "rules_sha256": rules_sha,
        "rules_loaded": len(rules),
        "files": per_file,
        "lines": totals["lines"],
        "events": totals["events"],
        "unparsed_lines": totals["unparsed"],
        "unparsed_samples": unparsed_samples,
        "contract_problems": dict(problems),
        "first_event": iso_utc(first) if first else None,
        "last_event": iso_utc(last) if last else None,
        "distinct_client_ips": len(ips),
        "top_client_ips": ips.most_common(5),
        "events_per_application": dict(sorted(applications.items())),
        "status_codes": dict(sorted(statuses.items())),
        "labelled_events_moderate": totals["labelled_moderate"],
        "labelled_events_strict": totals["labelled_strict"],
        "label_counts_moderate": dict(sorted(labels_moderate.items())),
        "label_counts_strict": dict(sorted(labels_strict.items())),
        "label_semantics": "rule-derived, approximate re-implementation; see module docstring",
    }
    with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return report


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("org_dir", help="extracted organization directory (contains log/ and ground-truth/)")
    parser.add_argument("out_dir", help="where to write events.jsonl, labels.jsonl, report.json")
    parser.add_argument("--tenant", required=True, help="tenant_id to stamp on every event, e.g. org-x")
    parser.add_argument("--rules", default=None, help="ground-truth yaml (default: first under ground-truth/)")
    parser.add_argument("--limit", type=int, default=None, help="stop after N events (smoke tests)")
    parser.add_argument("--access-glob", default=None, help="access-log glob relative to org_dir (default: Org X layout)")
    parser.add_argument("--app-regex", default=None, help="regex over the relative log path; group 1 = application name")
    args = parser.parse_args(argv)

    report = convert(args.org_dir, args.out_dir, args.tenant, args.rules, args.limit, args.access_glob, args.app_regex)
    print(json.dumps({k: v for k, v in report.items() if k not in ("files",)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
