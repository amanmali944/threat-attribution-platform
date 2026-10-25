"""Write the Phase 1b spec of an AIT-LDS v2.0 scenario from its own metadata (one rule for all).

    python -I scripts/make_ait_spec.py <scenario dir> <spec json> --scenario fox

Inputs: `dataset.yaml` (start / end of the data) and `gather/attacker_0/logs/attacks.log` (the
attacker's step timeline). No detector output and no log content is read.

Rule (identical for every scenario, so no scenario gets a hand-tuned split):
  * incident = first VPN connect -> last VPN disconnect of the intrusion, widened outwards to
    window boundaries (start floored, end raised to the next boundary strictly after the
    disconnect). An intrusion may use several VPN sessions (wheeler: two, ten hours apart while a
    password was cracked offline); they must alternate connect / disconnect. Windows inside the
    interval stay background unless they hold a labelled event;
  * splits, with S = first day of the data and D = the incident's day:
      baseline [S, S+1d) · train [S+1d, D-1d) · validation [D-1d, D-1h) · gap [D-1h, D) · test [D, end)
    which needs at least three full days before the incident day;
  * label classes: one shared mapping (below). The window builder stops on any label it does
    not know, so a new label name is a deliberate spec change, never silently background.
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

WINDOW_SECONDS = 300
LABEL_CLASSES = {
    "incident": [
        "foothold", "escalate",
        "attacker_vpn", "dns_scan", "traceroute", "network_scan", "service_scan",
        "dirb", "wpscan", "attacker_http", "webshell_upload", "webshell_cmd",
        "attacker_change_user", "escalated_command", "escalated_sudo_command", "escalated_sudo_session",
    ],
    "exfiltration": ["dnsteal", "dnsteal-received", "dnsteal-dropped"],
}
IGNORED_LABELS = ["attacker"]
STEP_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\+00:00 (\S+)\s*$")


def read_dataset_yaml(text: str) -> Tuple[datetime, datetime]:
    values = dict(re.findall(r"^(start|end):\s*'?([0-9T:-]+)'?\s*$", text, flags=re.M))
    start, end = (datetime.fromisoformat(values[k]).replace(tzinfo=timezone.utc) for k in ("start", "end"))
    return start, end


def read_steps(text: str) -> List[Tuple[datetime, str]]:
    steps = []
    for line in text.splitlines():
        match = STEP_RE.match(line.strip())
        if match:
            stamp, step = match.groups()
            steps.append((datetime.fromisoformat(stamp).replace(tzinfo=timezone.utc), step))
    return steps


def _floor(moment: datetime) -> datetime:
    epoch = int(moment.timestamp())
    return datetime.fromtimestamp(epoch - epoch % WINDOW_SECONDS, tz=timezone.utc)


def _ceil_after(moment: datetime) -> datetime:
    return _floor(moment) + timedelta(seconds=WINDOW_SECONDS)


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_spec(scenario: str, dataset_yaml: str, attacks_log: str) -> Dict[str, Any]:
    data_start, data_end = read_dataset_yaml(dataset_yaml)
    steps = read_steps(attacks_log)
    vpn = sorted((t, s) for t, s in steps if s in ("vpn_connect", "vpn_disconnect"))
    expected = ["vpn_connect", "vpn_disconnect"] * (len(vpn) // 2)
    if not vpn or [s for _, s in vpn] != expected:
        raise ValueError("expected VPN sessions as alternating vpn_connect / vpn_disconnect steps, got "
                         + (", ".join(s for _, s in vpn) or "none"))
    sessions = [(vpn[i][0], vpn[i + 1][0]) for i in range(0, len(vpn), 2)]
    connects, disconnects = [a for a, _ in sessions], [b for _, b in sessions]
    incident_start, incident_end = _floor(connects[0]), _ceil_after(disconnects[-1])

    first_day = data_start.replace(hour=0, minute=0, second=0, microsecond=0)
    incident_day = incident_start.replace(hour=0, minute=0, second=0, microsecond=0)
    if (incident_day - first_day).days < 3:
        raise ValueError("need at least three full days before the incident day (baseline, train, validation)")
    day, hour = timedelta(days=1), timedelta(hours=1)
    splits = {
        "baseline": [first_day, first_day + day],
        "train": [first_day + day, incident_day - day],
        "validation": [incident_day - day, incident_day - hour],
        "gap": [incident_day - hour, incident_day],
        "test": [incident_day, data_end],
    }
    exfil_stop = [t for t, s in steps if s == "dnsteal_stop"]
    return {
        "dataset": f"ait-lds-v2/{scenario}",
        "window_seconds": WINDOW_SECONDS,
        "incident": {"start": _iso(incident_start), "end": _iso(incident_end)},
        "label_classes": LABEL_CLASSES,
        "ignored_labels": IGNORED_LABELS,
        "splits": {name: [_iso(a), _iso(b)] for name, (a, b) in splits.items()},
        "provenance": {
            "source": f"AIT Log Data Set V2.0 (Zenodo 10.5281/zenodo.5789064, CC BY-NC-SA 4.0), scenario {scenario}; "
                      "per-line labels from the dataset's labels/ directory.",
            "generated_by": "scripts/make_ait_spec.py (same rule for every scenario)",
            "incident_window": f"attacks.log vpn_connect {connects[0].isoformat()} -> vpn_disconnect "
                               f"{disconnects[-1].isoformat()}, widened to window boundaries"
                               + (f" ({len(sessions)} VPN sessions: "
                                  + "; ".join(f"{a.strftime('%H:%M:%S')}-{b.strftime('%H:%M:%S')}" for a, b in sessions)
                                  + ")." if len(sessions) > 1 else "."),
            "exfiltration": ("attacks.log dnsteal_stop " + exfil_stop[0].isoformat()) if exfil_stop else
                            "no dnsteal_stop step in attacks.log",
            "splits": "baseline = first day; train = following days up to the day before the incident; "
                      "validation = that day until 23:00; gap = its last hour; test = incident day to the end of the data.",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("scenario_dir")
    parser.add_argument("spec")
    parser.add_argument("--scenario", required=True)
    args = parser.parse_args()
    root = Path(args.scenario_dir)
    spec = make_spec(args.scenario, (root / "dataset.yaml").read_text(encoding="utf-8"),
                     (root / "gather" / "attacker_0" / "logs" / "attacks.log").read_text(encoding="utf-8"))
    Path(args.spec).write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: spec[k] for k in ("incident", "splits")}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
