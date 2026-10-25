import json
from pathlib import Path

import pytest

from app.services.detection.features import FEATURE_NAMES, FeatureConfig, compute_features
from app.services.detection.labeling import (
    Interval,
    classify_by_event_labels,
    classify_events,
    label_windows,
    load_event_labels,
    load_spec,
    normalize_command,
    routine_commands,
    split_of,
    to_us,
)
from app.services.detection.resolve import entity_id, resolve_events

from .helpers import TENANT, iso, login

H = 3600  # offsets below are seconds from BASE = 2026-10-05T10:00:00Z

SPEC = {
    "dataset": "unit-test",
    "window_seconds": 300,
    "routine_command_min_hours": 2,
    "incident": {"start": iso(1 * H), "end": iso(1 * H + 20 * 60)},             # 11:00 - 11:20
    "splits": {
        "baseline": [iso(-2 * H), iso(-1 * H)],                                 # 08:00 - 09:00
        "train": [iso(-1 * H), iso(0)],                                         # 09:00 - 10:00
        "validation": [iso(0), iso(30 * 60)],                                   # 10:00 - 10:30
        "gap": [iso(30 * 60), iso(35 * 60)],                                    # 10:30 - 10:35
        "test": [iso(35 * 60), iso(2 * H)],                                     # 10:35 - 12:00
    },
    "provenance": {"note": "unit test"},
}


def write_spec(tmp_path, **changes):
    spec = json.loads(json.dumps(SPEC))
    for key, value in changes.items():
        if key in spec["splits"]:
            spec["splits"][key] = value
        else:
            spec[key] = value
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return str(path)


def sudo(eid, offset, invoker, command, run_as="root", host="srv-1"):
    return {
        "event_id": eid, "tenant_id": TENANT, "source_layer": "endpoint", "event_type": "process_execution",
        "observed_at": iso(offset), "severity": "info",
        "entities": [{"entity_type": "host", "identifier": host}, {"entity_type": "user", "identifier": invoker}],
        "payload": {"process_name": "sudo", "command_line": command, "run_as": run_as},
    }


def resolved(raw):
    return resolve_events(raw)[0]


# ------------------------------------------------------------------ spec


def test_valid_spec_loads(tmp_path):
    spec = load_spec(write_spec(tmp_path))
    assert spec.window_seconds == 300 and spec.routine_command_min_hours == 2
    assert list(spec.splits) == ["baseline", "train", "validation", "gap", "test"]
    assert spec.incident == Interval(to_us(iso(H)), to_us(iso(H + 1200)))


@pytest.mark.parametrize("changes, message", [
    ({"incident": {"start": iso(-30 * 60), "end": iso(-10 * 60)}}, "train split"),       # leakage into train
    ({"incident": {"start": iso(5 * 60), "end": iso(10 * 60)}}, "validation split"),     # leakage into validation
    ({"incident": {"start": iso(H), "end": iso(3 * H)}}, "wholly inside the test"),      # runs past the test end
    ({"incident": {"start": iso(H), "end": iso(H)}}, "before its end"),
    ({"validation": [iso(0), iso(31 * 60)]}, "multiples of the window"),                 # 10:31 not aligned
    ({"gap": [iso(25 * 60), iso(35 * 60)]}, "overlaps the previous"),                    # gap starts inside validation
])
def test_spec_rejects_leakage_and_bad_boundaries(tmp_path, changes, message):
    with pytest.raises(ValueError, match=message):
        load_spec(write_spec(tmp_path, **changes))


def test_spec_requires_every_split(tmp_path):
    spec = json.loads(json.dumps(SPEC))
    del spec["splits"]["gap"]
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    with pytest.raises(ValueError, match="missing split: gap"):
        load_spec(str(path))


def test_split_of_is_half_open(tmp_path):
    spec = load_spec(write_spec(tmp_path))
    assert split_of(iso(35 * 60), iso(40 * 60), spec) == "test"          # starts exactly at the test start
    assert split_of(iso(30 * 60), iso(35 * 60), spec) == "gap"           # ends exactly at the gap end
    assert split_of(iso(0), iso(5 * 60), spec) == "validation"
    assert split_of(iso(2 * H), iso(2 * H + 300), spec) is None          # after the data
    assert split_of(iso(28 * 60), iso(33 * 60), spec) is None            # straddles validation | gap


# ------------------------------------------------------------------ routine commands


def test_routine_needs_enough_distinct_hours_and_ignores_digits():
    events = resolved([
        sudo("r1", -2 * H + 600, "root", "/usr/bin/cat /logs/1.log"),        # 08:10
        sudo("r2", -1 * H + 600, "root", "/usr/bin/cat /logs/2.log"),        # 09:10, same once digits collapse
        sudo("o1", -1 * H + 1200, "root", "/usr/bin/rm /x"),                 # only one hour
        sudo("late", 600, "root", "/usr/bin/rm /x"),                         # 10:10, outside the period
    ])
    period = Interval(to_us(iso(-2 * H)), to_us(iso(0)))
    assert routine_commands(events, period, 2) == frozenset({"/usr/bin/cat /logs/N.log"})
    assert normalize_command("  /tmp/123 x9 ") == "/tmp/N xN"


# ------------------------------------------------------------------ event classes and window labels


def test_classify_events(tmp_path):
    spec = load_spec(write_spec(tmp_path))
    routine = frozenset({"/usr/bin/chown -R a:a /srv"})
    events = resolved([
        login("fail", H + 60, "root", "203.0.113.1", "FAILURE"),               # noise: ordinary
        login("ok_in", H + 120, "root", "203.0.113.2", "SUCCESS"),            # inside the incident
        login("ok_out", 40 * 60, "root", "203.0.113.2", "SUCCESS"),           # 10:40, outside
        sudo("routine_in", H + 180, "root", "/usr/bin/chown -R a:a /srv"),    # routine: ordinary
        sudo("odd_in", H + 240, "root", "/usr/bin/mkdir /srv/new1"),          # not routine, inside
        sudo("odd_out", 50 * 60, "root", "/usr/bin/mkdir /srv/new2"),         # not routine, outside
    ])
    assert classify_events(events, spec, routine) == {
        "ok_in": "incident", "ok_out": "unknown", "odd_in": "incident", "odd_out": "unknown",
    }


def test_label_precedence():
    vectors = [{"event_ids": ["a", "b"]}, {"event_ids": ["b", "c"]}, {"event_ids": ["c"]}, {"event_ids": []}]
    classes = {"a": "incident", "b": "unknown"}
    assert label_windows(vectors, classes) == ["incident", "unknown", "background", "background"]


def test_end_to_end_labels_follow_entities(tmp_path):
    spec = load_spec(write_spec(tmp_path))
    raw = [login(f"noise{i}", H + 10 * i, "admin", "203.0.113.50", "FAILURE") for i in range(5)]    # 11:00 noise
    raw += [login("entry", H + 300, "root", "203.0.113.60", "SUCCESS"),                             # 11:05 entry
            sudo("act", H + 360, "root", "/usr/bin/mkdir /srv/site"),                               # 11:06 action
            login("later", 1.5 * H, "ops", "203.0.113.70", "SUCCESS")]                              # 11:30 unknown
    events = resolved(raw)
    vectors = compute_features(events, None, FeatureConfig(window_seconds=300))
    labels = dict(zip(((v["entity_id"], v["window_start"]) for v in vectors),
                      label_windows(vectors, classify_events(events, spec, frozenset()))))

    def w(offset):  # window_start as compute_features writes it (no milliseconds)
        return iso(offset).replace(".000Z", "Z")

    assert labels[(entity_id("ip", TENANT, "203.0.113.60"), w(H + 300))] == "incident"
    assert labels[(entity_id("user", TENANT, "root"), w(H + 300))] == "incident"
    assert labels[(entity_id("host", TENANT, "srv-1"), w(H + 300))] == "incident"
    assert labels[(entity_id("ip", TENANT, "203.0.113.50"), w(H))] == "background"       # noise during the incident
    assert labels[(entity_id("user", TENANT, "admin"), w(H))] == "background"
    assert labels[(entity_id("user", TENANT, "ops"), w(1.5 * H))] == "unknown"


# ------------------------------------------------------------------ event-label datasets (AIT)

LABEL_CLASSES = {"incident": ["foothold", "escalate"], "exfiltration": ["dnsteal"]}


def event_label_spec(tmp_path, **changes):
    changes.setdefault("label_classes", LABEL_CLASSES)
    changes.setdefault("ignored_labels", ["attacker"])
    path = write_spec(tmp_path, **changes)
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    raw.pop("routine_command_min_hours")
    Path(path).write_text(json.dumps(raw), encoding="utf-8")
    return path


def test_event_label_spec_loads_without_routine_hours(tmp_path):
    spec = load_spec(event_label_spec(tmp_path))
    assert spec.uses_event_labels and spec.routine_command_min_hours is None
    assert list(spec.label_classes) == ["incident", "exfiltration"]
    assert spec.ignored_labels == frozenset({"attacker"})


def test_heuristic_spec_needs_routine_hours(tmp_path):
    path = write_spec(tmp_path)
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    raw.pop("routine_command_min_hours")
    Path(path).write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="routine_command_min_hours or label_classes"):
        load_spec(path)


@pytest.mark.parametrize("changes, message", [
    ({"label_classes": {"exfiltration": ["dnsteal"], "incident": ["foothold"]}}, "start with 'incident'"),
    ({"label_classes": {"incident": ["foothold"], "exfiltration": ["foothold"]}}, "share labels"),
    ({"label_classes": {"incident": ["foothold"], "unknown": ["x"]}}, "window labels"),
    ({"label_classes": {"incident": []}}, "lists no labels"),
    ({"ignored_labels": ["foothold"]}, "both ignored and mapped"),
])
def test_event_label_spec_rejects_bad_classes(tmp_path, changes, message):
    with pytest.raises(ValueError, match=message):
        load_spec(event_label_spec(tmp_path, **changes))


def test_classify_by_event_labels_precedence_ignore_and_unmapped(tmp_path):
    spec = load_spec(event_label_spec(tmp_path))
    events = resolved([login(eid, H + 60 * i, "u", "203.0.113.9", "SUCCESS")
                       for i, eid in enumerate(["both", "exfil", "umbrella", "new", "plain"])])
    sidecar = {"both": ["dnsteal", "foothold"], "exfil": ["dnsteal", "attacker"], "umbrella": ["attacker"],
               "new": ["mystery"]}
    classes, unmapped = classify_by_event_labels(events, sidecar, spec)
    assert classes == {"both": "incident", "exfil": "exfiltration"}   # incident wins; ignored-only is unlabelled
    assert unmapped == {"mystery": 1}                                   # surfaced, never silently dropped


def test_classify_by_event_labels_needs_label_classes(tmp_path):
    with pytest.raises(ValueError, match="no label_classes"):
        classify_by_event_labels([], {}, load_spec(write_spec(tmp_path)))


def test_label_precedence_custom_classes():
    vectors = [{"event_ids": ["a", "b"]}, {"event_ids": ["b"]}, {"event_ids": ["c"]}]
    classes = {"a": "incident", "b": "exfiltration", "c": "unknown"}
    assert label_windows(vectors, classes, ("incident", "exfiltration")) == ["incident", "exfiltration", "background"]


def test_load_event_labels(tmp_path):
    path = tmp_path / "labels.jsonl"
    path.write_text(
        json.dumps({"event_id": "e1", "labels": [{"rule_id": "r", "label": "x"}], "labels_strict": []}) + "\n"
        + json.dumps({"event_id": "e2", "labels": [], "labels_strict": [{"rule_id": "s", "label": "y"}]}) + "\n",
        encoding="utf-8",
    )
    assert load_event_labels(str(path)) == {"e1": ["x"], "e2": []}


# ------------------------------------------------------------------ real data (skipped if absent)

REPO = Path(__file__).resolve().parents[3]
WINDOWS = REPO / "data" / "external" / "web_server_logs" / "derived" / "org-y" / "windows"
SPEC_FILE = REPO / "data" / "specs" / "org_y_incident.json"


def test_committed_org_y_spec_is_valid():
    spec = load_spec(str(SPEC_FILE))
    assert spec.incident.start_us >= spec.splits["test"].start_us
    assert "timezone_assumption" in spec.provenance and "single_incident" in spec.provenance


@pytest.mark.skipif(not (WINDOWS / "dataset_report.json").exists(), reason="Org Y windows not built")
def test_org_y_windows_have_no_leakage_and_match_the_report():
    spec = load_spec(str(SPEC_FILE))
    report = json.loads((WINDOWS / "dataset_report.json").read_text(encoding="utf-8"))

    post = report["post_compromise_labelled_events"]
    assert post["seen_after_baseline"] > 0
    assert post["classified_incident"] == post["seen_after_baseline"]   # every rule-labelled step is in the incident

    for split, counts in report["windows_by_split"].items():
        if split != "test":
            assert "incident" not in counts, f"incident window in {split}"

    for split in ("train", "validation", "test"):
        found = {"background": 0, "incident": 0, "unknown": 0}
        with open(WINDOWS / f"{split}.jsonl", "rt", encoding="utf-8") as handle:
            for line in handle:
                record = json.loads(line)
                assert record["split"] == split
                assert split_of(record["window_start"], record["window_end"], spec) == split
                assert sorted(record["features"]) == sorted(FEATURE_NAMES)   # labels never inside features
                found[record["label"]] += 1
        expected = {k: report["windows_by_split"][split].get(k, 0) for k in found}
        assert found == expected, split


AIT_SPEC_FILE = REPO / "data" / "specs" / "ait_russellmitchell.json"
AIT_WINDOWS = REPO / "data" / "external" / "ait" / "windows"


def test_committed_ait_spec_is_valid():
    spec = load_spec(str(AIT_SPEC_FILE))
    assert spec.uses_event_labels and list(spec.label_classes) == ["incident", "exfiltration"]
    assert "exfiltration_overlaps_training" in spec.provenance and "seen_before_evaluation" in spec.provenance


@pytest.mark.parametrize("variant", ["russellmitchell-asis", "russellmitchell-clean"])
def test_ait_windows_have_no_leakage_and_match_the_report(variant):
    folder = AIT_WINDOWS / variant
    if not (folder / "dataset_report.json").exists():
        pytest.skip(f"AIT windows {variant} not built")
    spec = load_spec(str(AIT_SPEC_FILE))
    report = json.loads((folder / "dataset_report.json").read_text(encoding="utf-8"))

    assert report["variant"] == ("clean-baseline" if variant.endswith("clean") else "as-is")
    assert (report["baseline"]["exfiltration_events_removed"] > 0) == variant.endswith("clean")
    assert report["events_by_class_and_split"]["incident"] == {"test": report["events_by_class"]["incident"]}
    for cls, cover in report["window_label_coverage"].items():
        assert cover["in_a_window_with_that_label"] == cover["events_after_baseline"] > 0, cls

    for split in ("train", "validation", "test"):
        found = {"background": 0, "incident": 0, "exfiltration": 0}
        with open(folder / f"{split}.jsonl", "rt", encoding="utf-8") as handle:
            for line in handle:
                record = json.loads(line)
                assert record["split"] == split
                assert split_of(record["window_start"], record["window_end"], spec) == split
                assert sorted(record["features"]) == sorted(FEATURE_NAMES)
                if record["label"] == "incident":
                    assert split == "test"
                    assert spec.incident.start_us <= to_us(record["window_start"]) < spec.incident.end_us
                found[record["label"]] += 1
        expected = {k: report["windows_by_split"][split].get(k, 0) for k in found}
        assert found == expected, split
