import glob
import gzip
import hashlib
import importlib.util
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.services.detection import contract as C
from app.services.detection.resolve import resolve_event

REPO = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location("web_server_logs", REPO / "scripts" / "adapters" / "web_server_logs.py")
adapter = importlib.util.module_from_spec(_spec)
sys.modules["web_server_logs"] = adapter   # dataclasses need the module registered before it executes
_spec.loader.exec_module(adapter)

LINE_OK = ('255.102.154.224 - - [07/Oct/2025:07:35:03 +0700] "HEAD / HTTP/1.0" 302 6521 "-" '
           '"HetrixTools Uptime Monitoring Bot. https://hetrix.tools/uptime-monitoring-bot.html"')
LINE_ESCAPED = r'10.0.0.1 - - [07/Oct/2025:07:35:04 +0700] "GET /a?b=\"x HTTP/1.1" 404 - "-" "Agent \"quoted\" 1.0"'
LINE_TIMEOUT = '1.2.3.4 - - [07/Oct/2025:07:35:05 +0700] "-" 408 - "-" "-"'

RULES_YAML = """
- id: and_rule
  ground_truth_label: lbl_and
  sensitivity: moderate
  filter:
    - "code: 404"
    - "MSIE"
- id: wild_rule
  ground_truth_label: lbl_wild
  sensitivity: moderate
  filter:
    - "marker%xyz"
- id: strict_rule
  ground_truth_label: lbl_strict
  sensitivity: strict
  filter:
    - "special-agent"
"""


@pytest.fixture
def rules(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(RULES_YAML, encoding="utf-8")
    return adapter.load_rules(str(path))


# ------------------------------------------------------------------ parsing


def test_parse_standard_line_converts_timezone_to_utc():
    rec = adapter.parse_access_line(LINE_OK)
    assert rec["ip"] == "255.102.154.224" and rec["user"] is None
    assert rec["method"] == "HEAD" and rec["path"] == "/" and rec["protocol"] == "HTTP/1.0"
    assert rec["status_code"] == 302 and rec["bytes_out"] == 6521
    assert rec["observed_at"] == datetime(2025, 10, 7, 0, 35, 3, tzinfo=timezone.utc)   # 07:35 +07:00
    assert rec["referer"] is None and rec["user_agent"].startswith("HetrixTools")


def test_escaped_quotes_inside_fields_still_parse():
    rec = adapter.parse_access_line(LINE_ESCAPED)
    assert rec is not None
    assert rec["status_code"] == 404 and rec["bytes_out"] == 0          # "-" bytes
    assert rec["user_agent"] == r'Agent \"quoted\" 1.0'
    assert rec["path"] == r'/a?b=\"x'


def test_timeout_style_request_line_is_kept_not_dropped():
    rec = adapter.parse_access_line(LINE_TIMEOUT)
    assert rec["method"] == "-" and rec["path"] == "-" and rec["status_code"] == 408
    assert rec["user_agent"] is None


def test_garbage_line_returns_none():
    assert adapter.parse_access_line("not a log line") is None
    assert adapter.parse_access_line("") is None


def test_to_event_is_contract_valid_and_resolves():
    event = adapter.to_event(adapter.parse_access_line(LINE_OK), "org-x", "web-access.log.14", 42)
    assert C.validate_event(event) == []
    assert event["event_id"] == "wsld-web-access.log.14-0000042"
    assert event["observed_at"] == "2025-10-07T00:35:03Z"
    resolved = resolve_event(event)
    assert resolved.actor_ip.identifier == "255.102.154.224"
    assert resolved.target.identifier == "web-application" and resolved.actor_user is None

    failed = adapter.to_event(adapter.parse_access_line(LINE_ESCAPED), "org-x", "web-access.log", 1)
    assert resolve_event(failed).outcome == "failure"          # 404


def test_authenticated_user_becomes_an_entity():
    line = LINE_OK.replace(" - - [", " - alice [")
    event = adapter.to_event(adapter.parse_access_line(line), "org-x", "web-access.log", 1)
    assert resolve_event(event).actor_user.identifier == "alice"


# ------------------------------------------------------------------ labels


def test_rule_needs_all_patterns_case_insensitively_and_status_via_code(rules):
    line = '1.1.1.1 - - [07/Oct/2025:07:35:03 +0700] "GET /x HTTP/1.1" 404 10 "-" "Mozilla msie 8"'
    assert [h["label"] for h in adapter.label_line(line, 404, rules)["moderate"]] == ["lbl_and"]
    assert adapter.label_line(line, 200, rules)["moderate"] == []                      # status differs
    assert adapter.label_line(line.replace("msie", "firefox"), 404, rules)["moderate"] == []  # 2nd pattern missing


def test_percent_is_a_wildcard(rules):
    line = '1.1.1.1 - - [07/Oct/2025:07:35:03 +0700] "GET /MARKER-anything-XYZ HTTP/1.1" 200 10 "-" "ua"'
    assert [h["label"] for h in adapter.label_line(line, 200, rules)["moderate"]] == ["lbl_wild"]


def test_strict_rules_are_reported_separately(rules):
    line = '1.1.1.1 - - [07/Oct/2025:07:35:03 +0700] "GET /x HTTP/1.1" 200 10 "-" "Special-Agent"'
    hits = adapter.label_line(line, 200, rules)
    assert hits["moderate"] == [] and [h["label"] for h in hits["strict"]] == ["lbl_strict"]


def test_load_rules_reads_the_real_ground_truth_file_if_present():
    path = REPO / "data" / "external" / "web_server_logs" / "org-x" / "organization-x" / "ground-truth" / "organization-x.yaml"
    if not path.exists():
        pytest.skip("Org X not downloaded")
    loaded = adapter.load_rules(str(path))
    assert len(loaded) == 39
    assert {r.sensitivity for r in loaded} == {"moderate", "strict"}


# ------------------------------------------------------------------ conversion


def _make_org(tmp_path):
    org = tmp_path / "org"
    (org / "log" / "apache2").mkdir(parents=True)
    (org / "ground-truth").mkdir()
    (org / "ground-truth" / "rules.yaml").write_text(RULES_YAML, encoding="utf-8")
    newest = [LINE_OK, 'x - - [07/Oct/2025:08:00:00 +0700] "GET /marker-1-xyz HTTP/1.1" 200 5 "-" "ua"', "garbage"]
    (org / "log" / "apache2" / "web-access.log").write_text("\n".join(newest) + "\n", encoding="utf-8")
    (org / "log" / "apache2" / "web-access.log.1").write_text(LINE_ESCAPED + "\n", encoding="utf-8")
    with gzip.open(org / "log" / "apache2" / "web-access.log.2.gz", "wt", encoding="utf-8") as fh:
        fh.write(LINE_TIMEOUT + "\n")
    with gzip.open(org / "log" / "apache2" / "web-access.log.10.gz", "wt", encoding="utf-8") as fh:
        fh.write(LINE_OK.replace("07/Oct", "01/Oct") + "\n")
    return org


def test_files_are_read_oldest_first_with_numeric_rotation_order(tmp_path):
    org = _make_org(tmp_path)
    names = [os.path.basename(p) for p in adapter.access_log_files(str(org))]
    assert names == ["web-access.log.10.gz", "web-access.log.2.gz", "web-access.log.1", "web-access.log"]


def test_convert_counts_labels_and_skips(tmp_path):
    org = _make_org(tmp_path)
    out = tmp_path / "out"
    report = adapter.convert(str(org), str(out), "org-t")

    assert report["lines"] == 6 and report["events"] == 5 and report["unparsed_lines"] == 1
    assert report["unparsed_samples"] == ["web-access.log:3: garbage"]
    assert report["contract_problems"] == {}
    assert report["labelled_events_moderate"] == 1   # only the "marker-1-xyz" line matches a rule
    events = [json.loads(line) for line in (out / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [e["event_id"].split("-", 1)[1].rsplit("-", 1)[0] for e in events] == [
        "web-access.log.10", "web-access.log.2", "web-access.log.1", "web-access.log", "web-access.log"]
    assert {e["tenant_id"] for e in events} == {"org-t"}
    labels = [json.loads(line) for line in (out / "labels.jsonl").read_text(encoding="utf-8").splitlines()]
    by_id = {rec["event_id"]: [h["label"] for h in rec["labels"]] for rec in labels}
    assert by_id["wsld-web-access.log-0000002"] == ["lbl_wild"]
    assert all(e["payload"].get("source_ip") for e in events)
    for e in events:                                       # labels live only in the sidecar file
        assert "labels" not in e and "lbl_" not in json.dumps(e)


def test_conversion_is_byte_for_byte_deterministic(tmp_path):
    org = _make_org(tmp_path)
    adapter.convert(str(org), str(tmp_path / "a"), "org-t")
    adapter.convert(str(org), str(tmp_path / "b"), "org-t")
    for name in ("events.jsonl", "labels.jsonl"):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()


# ------------------------------------------------------------------ real data (skipped if absent)

ORG_X = REPO / "data" / "external" / "web_server_logs" / "org-x" / "organization-x"
ORG_X_REPORT = REPO / "data" / "external" / "web_server_logs" / "derived" / "org-x" / "report.json"


@pytest.mark.skipif(not (ORG_X.exists() and ORG_X_REPORT.exists()), reason="Org X not downloaded/converted")
def test_org_x_conversion_accounts_for_every_line_and_is_contract_valid():
    report = json.loads(ORG_X_REPORT.read_text(encoding="utf-8"))
    raw_lines = 0
    for path in glob.glob(str(ORG_X / "log" / "apache2" / "web-access.log*")):
        opener = gzip.open if path.endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
            raw_lines += sum(1 for _ in fh)
    assert report["lines"] == raw_lines                                  # nothing silently lost
    assert report["events"] + report["unparsed_lines"] == raw_lines
    assert report["contract_problems"] == {}
    assert report["tenant_id"] == "org-x"
    with open(ORG_X / "ground-truth" / "organization-x.yaml", "rb") as fh:
        assert report["rules_sha256"] == hashlib.sha256(fh.read()).hexdigest()
