"""scripts/make_ait_spec.py: one rule for every AIT scenario's incident window and splits."""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from app.services.detection.labeling import load_spec

REPO = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location("make_ait_spec", REPO / "scripts" / "make_ait_spec.py")
make = importlib.util.module_from_spec(_spec)
sys.modules["make_ait_spec"] = make
_spec.loader.exec_module(make)

DATASET = "name: processed_x_scenario\nstart: '2022-01-21T00:00:00'\nend: '2022-01-25T00:00:00'\n"
ATTACKS = """\
2022-01-24 03:01:00.075089+00:00 vpn_connect
2022-01-24 03:01:21.200000+00:00 dns_brute_force
2022-01-24 04:38:11.400000+00:00 vpn_disconnect
2022-01-24 13:52:00.000000+00:00 dnsteal_stop
"""


def test_incident_is_widened_to_window_boundaries():
    spec = make.make_spec("x", DATASET, ATTACKS)
    assert spec["incident"] == {"start": "2022-01-24T03:00:00Z", "end": "2022-01-24T04:40:00Z"}


def test_disconnect_on_a_boundary_still_gets_a_full_window_after_it():
    attacks = ATTACKS.replace("04:38:11.400000", "04:40:00.000000")
    assert make.make_spec("x", DATASET, attacks)["incident"]["end"] == "2022-01-24T04:45:00Z"


def test_splits_follow_the_rule():
    splits = make.make_spec("x", DATASET, ATTACKS)["splits"]
    assert splits == {
        "baseline": ["2022-01-21T00:00:00Z", "2022-01-22T00:00:00Z"],
        "train": ["2022-01-22T00:00:00Z", "2022-01-23T00:00:00Z"],
        "validation": ["2022-01-23T00:00:00Z", "2022-01-23T23:00:00Z"],
        "gap": ["2022-01-23T23:00:00Z", "2022-01-24T00:00:00Z"],
        "test": ["2022-01-24T00:00:00Z", "2022-01-25T00:00:00Z"],
    }


def test_generated_spec_loads_and_matches_the_hand_written_russellmitchell_spec(tmp_path):
    root = REPO / "data" / "external" / "ait" / "russellmitchell"
    if not (root / "dataset.yaml").exists():
        pytest.skip("russellmitchell slice not downloaded")
    generated = make.make_spec("russellmitchell", (root / "dataset.yaml").read_text(encoding="utf-8"),
                               (root / "gather" / "attacker_0" / "logs" / "attacks.log").read_text(encoding="utf-8"))
    committed = json.loads((REPO / "data" / "specs" / "ait_russellmitchell.json").read_text(encoding="utf-8"))
    for key in ("dataset", "window_seconds", "incident", "splits", "label_classes", "ignored_labels"):
        assert generated[key] == committed[key], key
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(generated), encoding="utf-8")
    assert load_spec(str(path)).uses_event_labels


def test_an_intrusion_over_two_vpn_sessions_spans_both():
    # wheeler: recon and upload in one session, offline cracking, then the privilege step 10 h later
    attacks = ATTACKS + "2022-01-24 17:51:00+00:00 vpn_connect\n2022-01-24 17:52:19+00:00 vpn_disconnect\n"
    spec = make.make_spec("x", DATASET, attacks)
    assert spec["incident"] == {"start": "2022-01-24T03:00:00Z", "end": "2022-01-24T17:55:00Z"}
    assert "2 VPN sessions" in spec["provenance"]["incident_window"]


@pytest.mark.parametrize("attacks, message", [
    ("2022-01-24 03:01:00+00:00 dns_brute_force\n", "alternating"),
    (ATTACKS + "2022-01-24 05:00:00+00:00 vpn_connect\n", "alternating"),           # a session never closed
    ("2022-01-24 04:00:00+00:00 vpn_disconnect\n2022-01-24 05:00:00+00:00 vpn_connect\n", "alternating"),
    (ATTACKS.replace("2022-01-24", "2022-01-23"), "three full days"),
])
def test_bad_timelines_are_refused(attacks, message):
    with pytest.raises(ValueError, match=message):
        make.make_spec("x", DATASET, attacks)


def test_committed_generated_specs_are_valid():
    specs = sorted((REPO / "data" / "specs" / "ait").glob("*.json"))
    assert specs, "no generated AIT specs committed"
    for path in specs:
        spec = load_spec(str(path))
        assert spec.uses_event_labels and spec.incident.start_us >= spec.splits["test"].start_us, path.name
