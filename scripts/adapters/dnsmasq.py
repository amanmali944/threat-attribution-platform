"""Adapter: dnsmasq query log -> canonical network / dns_query events + label sidecar.

Built for AIT-LDS v2.0 (`gather/<host>/logs/dnsmasq.log`, per-line labels under `labels/`).

    python -I scripts/adapters/dnsmasq.py <scenario dir> <out dir> --tenant ait-russellmitchell \\
        --year 2022 --glob "gather/inet-firewall/logs/dnsmasq.log*" --line-labels --id-prefix ait-inet-firewall

One event per "query[TYPE] NAME from IP" line. "forwarded", "reply", "cached", "config" and
other lines repeat or describe the same query; they are skipped and COUNTED.

Entities: the querying IP (actor) and the *registered domain* (target) - the last two labels of
the name (approximation: `example.co.uk` becomes `co.uk`). Using the full name as the target would
turn every exfiltration query (a unique encoded subdomain each time) into a new entity. The full
name is kept in `payload.query_name`, with its length and label count.

Timestamps: syslog style, no year or zone - both are arguments (UTC by default) and are recorded
in report.json.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import LineLabeller, open_text  # noqa: E402
from app.services.detection import contract as C  # noqa: E402
from app.services.detection.resolve import iso_utc  # noqa: E402

LINE_RE = re.compile(r"^([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) dnsmasq\[(\d+)\]: (.*)$")
QUERY_RE = re.compile(r"^query\[(\w+)\] (\S+) from (\S+)$")
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


def parse_line(line: str, year: int, utc_offset_hours: float = 0.0) -> Optional[Dict[str, Any]]:
    match = LINE_RE.match(line.rstrip("\r\n"))
    if not match:
        return None
    mon, day, hh, mm, ss, pid, message = match.groups()
    month = MONTHS.get(mon)
    if month is None:
        return None
    try:
        local = datetime(year, month, int(day), int(hh), int(mm), int(ss),
                         tzinfo=timezone(timedelta(hours=utc_offset_hours)))
    except ValueError:
        return None
    return {"observed_at": local.astimezone(timezone.utc), "pid": int(pid), "message": message}


def classify(message: str):
    match = QUERY_RE.match(message)
    if match:
        return "query", match
    for prefix in ("forwarded", "reply", "cached", "config", "query"):
        if message.startswith(prefix):
            return "skip", prefix
    return "skip", "other"


def base_domain(name: str) -> str:
    labels = [label for label in name.rstrip(".").split(".") if label]
    return ".".join(labels[-2:]) if len(labels) >= 2 else (name.rstrip(".") or name)


def to_event(match: "re.Match[str]", rec: Dict[str, Any], tenant: str, source_file: str, lineno: int,
             id_prefix: str, dataset_name: str) -> Dict[str, Any]:
    qtype, name, source = match.groups()
    domain = base_domain(name)
    return {
        "event_id": f"{id_prefix}-{source_file}-{lineno:07d}",
        "tenant_id": tenant,
        "source_layer": "network",
        "event_type": "dns_query",
        "observed_at": iso_utc(rec["observed_at"]),
        "severity": "info",
        "entities": [{"entity_type": "ip", "identifier": source}, {"entity_type": "domain", "identifier": domain}],
        "payload": {"query_name": name, "query_type": qtype, "base_domain": domain,
                    "query_length": len(name), "label_count": name.rstrip(".").count(".") + 1},
        "metadata": {"dataset": dataset_name, "source_file": source_file, "line": lineno, "pid": rec["pid"]},
    }


def convert(org_dir: str, out_dir: str, tenant: str, year: int, glob_pattern: str,
            utc_offset_hours: float = 0.0, line_labels: bool = True,
            id_prefix: str = "ait", dataset_name: str = "ait-lds-v2") -> Dict[str, Any]:
    if not line_labels:
        raise ValueError("dnsmasq adapter only supports per-line labels (AIT)")
    labeller = LineLabeller(org_dir)
    files = sorted(glob.glob(os.path.join(org_dir, glob_pattern)))
    os.makedirs(out_dir, exist_ok=True)
    totals, skipped, problems, labels_count = Counter(), Counter(), Counter(), Counter()
    sources, domains = Counter(), Counter()
    unparsed_samples: List[str] = []
    first = last = None
    per_file = []

    with open(os.path.join(out_dir, "events.jsonl"), "w", encoding="utf-8", newline="\n") as events_out, \
         open(os.path.join(out_dir, "labels.jsonl"), "w", encoding="utf-8", newline="\n") as labels_out:
        for path in files:
            source_file = os.path.basename(path)
            n_lines = n_events = 0
            with open_text(path) as handle:
                for lineno, line in enumerate(handle, start=1):
                    n_lines += 1
                    totals["lines"] += 1
                    rec = parse_line(line, year, utc_offset_hours)
                    if rec is None:
                        totals["unparsed"] += 1
                        if len(unparsed_samples) < 5:
                            unparsed_samples.append(f"{source_file}:{lineno}: {line.strip()[:120]!r}")
                        continue
                    kind, detail = classify(rec["message"])
                    if kind == "skip":
                        skipped[detail] += 1
                        totals["skipped"] += 1
                        continue
                    event = to_event(detail, rec, tenant, source_file, lineno, id_prefix, dataset_name)
                    for problem in C.validate_event(event):
                        problems[problem] += 1
                    events_out.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
                    totals["events"] += 1
                    n_events += 1
                    sources[event["entities"][0]["identifier"]] += 1
                    domains[event["payload"]["base_domain"]] += 1
                    hits = labeller.hits(path, lineno, line)
                    if hits["moderate"]:
                        labels_out.write(json.dumps({"event_id": event["event_id"], "labels": hits["moderate"],
                                                     "labels_strict": []}, sort_keys=True, separators=(",", ":")) + "\n")
                        totals["labelled"] += 1
                        for label in {h["label"] for h in hits["moderate"]}:
                            labels_count[label] += 1
                    moment = rec["observed_at"]
                    first = moment if first is None or moment < first else first
                    last = moment if last is None or moment > last else last
            per_file.append({"file": source_file, "lines": n_lines, "events": n_events})

    report = {
        "dataset": dataset_name, "source": "dnsmasq", "tenant_id": tenant, "label_source": labeller.source,
        "timestamp_assumptions": {"year": year, "utc_offset_hours": utc_offset_hours},
        "files": per_file, "lines": totals["lines"], "events": totals["events"],
        "skipped_lines": totals["skipped"], "skipped_by_reason": dict(sorted(skipped.items())),
        "unparsed_lines": totals["unparsed"], "unparsed_samples": unparsed_samples,
        "accounting": "lines == events + skipped_lines + unparsed_lines",
        "contract_problems": dict(problems),
        "first_event": iso_utc(first) if first else None, "last_event": iso_utc(last) if last else None,
        "distinct_query_sources": len(sources), "distinct_base_domains": len(domains),
        "top_base_domains": domains.most_common(8),
        "labelled_events_moderate": totals["labelled"], "label_counts_moderate": dict(sorted(labels_count.items())),
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
    parser.add_argument("--year", type=int, required=True)
    parser.add_argument("--glob", required=True, help="dnsmasq log glob relative to org_dir")
    parser.add_argument("--utc-offset", type=float, default=0.0)
    parser.add_argument("--id-prefix", default="ait")
    parser.add_argument("--dataset-name", default="ait-lds-v2")
    args = parser.parse_args(argv)
    report = convert(args.org_dir, args.out_dir, args.tenant, args.year, args.glob, args.utc_offset,
                     True, args.id_prefix, args.dataset_name)
    print(json.dumps({k: v for k, v in report.items() if k != "files"}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
