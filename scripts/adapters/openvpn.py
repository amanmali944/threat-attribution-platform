"""Adapter: OpenVPN server log -> canonical identity / user_login events + label sidecar.

Built for AIT-LDS v2.0 (`gather/vpn/logs/openvpn.log`, per-line labels under `labels/`).

    python -I scripts/adapters/openvpn.py <scenario dir> <out dir> --tenant ait-russellmitchell \\
        --glob "gather/vpn/logs/openvpn.log*" --host vpn --id-prefix ait-vpn

One SUCCESS login per completed connection, emitted on the line
"MULTI: primary virtual IP for USER/IP:PORT: VPN_IP" (the certificate CN is the user, IP is where
the client connected from, VPN_IP is the address it received inside the network). That line comes
once per connection; the handshake, TLS soft resets (periodic re-keying of an existing session),
peer info and data-channel lines are skipped and COUNTED. TLS / verification errors are counted
as `tls_error` / `verify_error` (no user is known for them, so no login event is emitted).

Timestamps carry date and time without a zone; UTC is assumed (AIT records attacks in UTC).
"""
from __future__ import annotations

import argparse
import glob
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

from _common import LineLabeller, open_text  # noqa: E402
from app.services.detection import contract as C  # noqa: E402
from app.services.detection.resolve import iso_utc  # noqa: E402

LINE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\S+) (.*)$")
VIRTUAL_IP_RE = re.compile(r"^MULTI: primary virtual IP for ([^/\s]+)/([^:\s]+):(\d+): (\S+)$")


def parse_line(line: str) -> Optional[Dict[str, Any]]:
    match = LINE_RE.match(line.rstrip("\r\n"))
    if not match:
        return None
    stamp, peer, message = match.groups()
    try:
        moment = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return {"observed_at": moment, "peer": peer, "message": message}


def classify(message: str):
    match = VIRTUAL_IP_RE.match(message)
    if match:
        return "connected", match
    if "TLS Error" in message or "TLS handshake failed" in message:
        return "skip", "tls_error"
    if "VERIFY ERROR" in message:
        return "skip", "verify_error"
    if message.startswith("TLS: soft reset"):
        return "skip", "tls_soft_reset"
    if "client-instance exiting" in message or "Inactivity timeout" in message:
        return "skip", "disconnect"
    return "skip", "session_detail"


def to_event(match: "re.Match[str]", rec: Dict[str, Any], tenant: str, source_file: str, lineno: int,
             host: str, id_prefix: str, dataset_name: str) -> Dict[str, Any]:
    user, ip, port, vpn_ip = match.groups()
    return {
        "event_id": f"{id_prefix}-{source_file}-{lineno:07d}",
        "tenant_id": tenant,
        "source_layer": "identity",
        "event_type": "user_login",
        "observed_at": iso_utc(rec["observed_at"]),
        "severity": "info",
        "entities": [{"entity_type": "user", "identifier": user}, {"entity_type": "host", "identifier": host}],
        "payload": {"result": "SUCCESS", "source_ip": ip, "source_port": int(port), "auth_method": "certificate",
                    "service": "openvpn", "vpn_ip": vpn_ip},
        "metadata": {"dataset": dataset_name, "source_file": source_file, "line": lineno},
    }


def convert(org_dir: str, out_dir: str, tenant: str, glob_pattern: str, host: str = "vpn",
            line_labels: bool = True, id_prefix: str = "ait", dataset_name: str = "ait-lds-v2") -> Dict[str, Any]:
    if not line_labels:
        raise ValueError("openvpn adapter only supports per-line labels (AIT)")
    labeller = LineLabeller(org_dir)
    files = sorted(glob.glob(os.path.join(org_dir, glob_pattern)))
    os.makedirs(out_dir, exist_ok=True)
    totals, skipped, problems, labels_count = Counter(), Counter(), Counter(), Counter()
    users, sources = Counter(), Counter()
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
                    rec = parse_line(line)
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
                    event = to_event(detail, rec, tenant, source_file, lineno, host, id_prefix, dataset_name)
                    for problem in C.validate_event(event):
                        problems[problem] += 1
                    events_out.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
                    totals["events"] += 1
                    n_events += 1
                    users[event["entities"][0]["identifier"]] += 1
                    sources[event["payload"]["source_ip"]] += 1
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
        "dataset": dataset_name, "source": "openvpn", "tenant_id": tenant, "label_source": labeller.source,
        "timestamp_assumptions": {"zone": "UTC assumed"},
        "files": per_file, "lines": totals["lines"], "events": totals["events"],
        "skipped_lines": totals["skipped"], "skipped_by_reason": dict(sorted(skipped.items())),
        "unparsed_lines": totals["unparsed"], "unparsed_samples": unparsed_samples,
        "accounting": "lines == events + skipped_lines + unparsed_lines",
        "contract_problems": dict(problems),
        "first_event": iso_utc(first) if first else None, "last_event": iso_utc(last) if last else None,
        "connections_by_user": dict(sorted(users.items())), "distinct_source_ips": len(sources),
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
    parser.add_argument("--glob", required=True, help="openvpn log glob relative to org_dir")
    parser.add_argument("--host", default="vpn", help="host entity for the VPN server")
    parser.add_argument("--id-prefix", default="ait")
    parser.add_argument("--dataset-name", default="ait-lds-v2")
    args = parser.parse_args(argv)
    report = convert(args.org_dir, args.out_dir, args.tenant, args.glob, args.host, True, args.id_prefix, args.dataset_name)
    print(json.dumps({k: v for k, v in report.items() if k != "files"}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
