"""Build the multi-scenario AIT corpus: convert -> spec -> windows (as-is, clean) per scenario.

    python -I scripts/build_ait_corpus.py <scenarios dir> <out dir> [--scenarios fox harrison ...]

For every scenario folder (an `ait-slice` extraction from fetch_remote_zip.py):
    <out>/derived/<scenario>/              convert_ait_scenario.py (+ assets.json from adapters/ait_assets.py)
    data/specs/ait/<scenario>.json         make_ait_spec.py (committed; same rule for all)
    <out>/windows/<scenario>-asis/         build_ait_windows.py
    <out>/windows/<scenario>-clean/        build_ait_windows.py --clean-baseline
and <out>/corpus_report.json with the integrity checks only: line accounting, contract problems,
label classes, label-to-window coverage and window counts per split. NO detector is run here,
so building the corpus never exposes a held-out scenario's detector output.

Each step runs in its own `python -I` process (memory is released between scenarios).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

SCRIPTS = Path(__file__).resolve().parent
REPO = SCRIPTS.parent


def run(args: List[str]) -> None:
    proc = subprocess.run([sys.executable, "-I", *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"failed: {' '.join(args)}\n{proc.stderr[-2000:]}")


def scenario_report(out: Path, name: str) -> Dict[str, Any]:
    summary = json.loads((out / "derived" / name / "summary.json").read_text(encoding="utf-8"))
    sources = summary["sources"]
    row: Dict[str, Any] = {
        "company_hosts": summary["company_hosts"],
        "sources": {k: {"events": v["events"], "labelled": v["labelled_events"]} for k, v in sources.items()},
        "events": sum(v["events"] for v in sources.values()),
        "accounting_ok": all(v["accounting_ok"] for v in sources.values()),
        "contract_problems": sum(sum(v["contract_problems"].values()) for v in sources.values()),
    }
    for variant in ("asis", "clean"):
        report = json.loads((out / "windows" / f"{name}-{variant}" / "dataset_report.json").read_text(encoding="utf-8"))
        row[variant] = {
            "events_by_class": report["events_by_class"],
            "events_by_class_and_split": report["events_by_class_and_split"],
            "coverage_complete": all(c["in_a_window_with_that_label"] == c["events_after_baseline"]
                                     for c in report["window_label_coverage"].values()),
            "windows_by_split": report["windows_by_split"],
            "incident_windows_by_entity_type": report["windows_by_split_label_entity_type"].get("test:incident", {}),
            "baseline_events": report["baseline"]["events"],
            "seconds": report["seconds"],
        }
    return row


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("scenarios_dir")
    parser.add_argument("out_dir")
    parser.add_argument("--scenarios", nargs="*", default=None)
    parser.add_argument("--year", type=int, default=2022)
    args = parser.parse_args()

    root, out = Path(args.scenarios_dir), Path(args.out_dir)
    names = args.scenarios or sorted(p.name for p in root.iterdir() if (p / "dataset.yaml").exists())
    report_path = out / "corpus_report.json"
    corpus = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {}
    for name in names:
        started = time.perf_counter()
        derived = out / "derived" / name
        spec = REPO / "data" / "specs" / "ait" / f"{name}.json"     # never the hand-written Phase 1b spec
        spec.parent.mkdir(parents=True, exist_ok=True)
        print(f"== {name}", flush=True)
        run([str(SCRIPTS / "convert_ait_scenario.py"), str(root / name), str(derived), "--scenario", name,
             "--year", str(args.year)])
        run([str(SCRIPTS / "adapters" / "ait_assets.py"), str(root / name), str(derived / "assets.json"),
             "--tenant", f"ait-{name}"])
        run([str(SCRIPTS / "make_ait_spec.py"), str(root / name), str(spec), "--scenario", name])
        for variant, extra in (("asis", []), ("clean", ["--clean-baseline"])):
            run([str(SCRIPTS / "build_ait_windows.py"), str(derived), str(spec),
                 str(out / "windows" / f"{name}-{variant}"), *extra])
        corpus[name] = scenario_report(out, name) | {"build_seconds": round(time.perf_counter() - started, 1)}
        out.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(corpus, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        row = corpus[name]
        print(f"   events {row['events']:,}  accounting {row['accounting_ok']}  contract problems "
              f"{row['contract_problems']}  test windows {row['asis']['windows_by_split'].get('test')}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
