import importlib.util
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.services.detection import contract as C
from app.services.detection.features import extract
from app.services.detection.resolve import entity_id, resolve_event

REPO = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location("syslog_auth", REPO / "scripts" / "adapters" / "syslog_auth.py")
adapter = importlib.util.module_from_spec(_spec)
sys.modules["syslog_auth"] = adapter
_spec.loader.exec_module(adapter)

L_FAIL = "Apr 27 00:02:17 localhost sshd[214388]: Failed password for root from 203.0.113.10 port 51728 ssh2"
L_FAIL_INVALID = "Apr 27 00:02:20 localhost sshd[1]: Failed password for invalid user hua from 203.0.113.11 port 50036 ssh2"
L_INVALID = "Apr 27 00:02:18 localhost sshd[2]: Invalid user hua from 203.0.113.11 port 50036"
L_PAM_DUP = "Apr 27 00:02:19 localhost sshd[3]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.11  user=root"
L_ACCEPT = "Apr 29 05:34:30 localhost sshd[943296]: Accepted password for root from 203.0.113.10 port 35210 ssh2"
L_SUDO = "Apr 27 01:00:01 localhost sudo:     root : PWD=/root ; USER=nobody ; COMMAND=/usr/bin/cat /var/log/x.log"
L_SUDO_TTY = "Apr 29 06:00:00 localhost sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/ls /etc"
L_SUDO_GROUP = "Apr 29 06:10:00 localhost sudo:     root : PWD=/tmp/work ; USER=svc ; GROUP=nogroup ; COMMAND=/usr/bin/chown svc /srv/site"
L_CRON = "Apr 27 01:00:01 localhost CRON[1]: pam_unix(cron:session): session opened for user root by (uid=0)"
L_CLOSED = "Apr 27 00:03:00 localhost sshd[4]: Connection closed by authenticating user root 203.0.113.10 port 51728 [preauth]"
L_SPACE_DAY = "May  1 00:21:04 localhost sshd[5]: Failed password for root from 203.0.113.10 port 1 ssh2"
L_NUL = "\x00\x00\x00\x00 not a syslog line"

RULES_YAML = """
- id: bf
  ground_truth_label: bruteforce_login_server_attempt
  sensitivity: moderate
  filter:
    - "Failed password for"
- id: bf_invalid
  ground_truth_label: bruteforce_login_server_attempt
  sensitivity: moderate
  filter:
    - "invalid user"
- id: chown_demo
  ground_truth_label: change_ownership_demo
  sensitivity: moderate
  filter:
    - "chown"
    - "/srv/site"
"""


# ------------------------------------------------------------------ parsing


def test_parse_syslog_fields_and_default_utc():
    rec = adapter.parse_syslog_line(L_FAIL, 2025)
    assert rec["observed_at"] == datetime(2025, 4, 27, 0, 2, 17, tzinfo=timezone.utc)
    assert (rec["host"], rec["process"], rec["pid"]) == ("localhost", "sshd", 214388)
    assert rec["message"].startswith("Failed password for root")


def test_utc_offset_shifts_to_utc():
    rec = adapter.parse_syslog_line(L_FAIL, 2025, utc_offset_hours=7)
    assert rec["observed_at"] == datetime(2025, 4, 26, 17, 2, 17, tzinfo=timezone.utc)


def test_single_digit_day_is_space_padded():
    rec = adapter.parse_syslog_line(L_SPACE_DAY, 2025)
    assert rec["observed_at"] == datetime(2025, 5, 1, 0, 21, 4, tzinfo=timezone.utc)


def test_process_without_pid_and_garbage():
    assert adapter.parse_syslog_line(L_SUDO, 2025)["pid"] is None
    assert adapter.parse_syslog_line(L_NUL, 2025) is None
    assert adapter.parse_syslog_line("", 2025) is None
    assert adapter.parse_syslog_line("Foo 99 99:99:99 h p: m", 2025) is None   # impossible date


# ------------------------------------------------------------------ classification


def _kind(line):
    return adapter.classify(adapter.parse_syslog_line(line, 2025))[0:2]


def test_classification():
    assert _kind(L_FAIL)[0] == "ssh_failed" and _kind(L_FAIL_INVALID)[0] == "ssh_failed"
    assert _kind(L_ACCEPT)[0] == "ssh_accepted"
    for sudo_line in (L_SUDO, L_SUDO_TTY, L_SUDO_GROUP):
        assert _kind(sudo_line)[0] == "sudo_command", sudo_line
    assert _kind(L_INVALID) == ("skip", "ssh_invalid_user_duplicate")
    assert _kind(L_PAM_DUP) == ("skip", "ssh_other")
    assert _kind(L_CLOSED) == ("skip", "ssh_connection_noise")
    assert _kind(L_CRON) == ("skip", "cron")


# ------------------------------------------------------------------ events


def _event(line, lineno=1):
    rec = adapter.parse_syslog_line(line, 2025)
    kind, match = adapter.classify(rec)
    return adapter.to_event(kind, match, rec, "org-t", "auth.log", lineno)


def test_failed_login_event_is_valid_and_resolves():
    event = _event(L_FAIL_INVALID, 42)
    assert C.validate_event(event) == []
    assert event["event_id"] == "wsld-auth.log-0000042"
    assert event["payload"]["invalid_user"] is True and event["payload"]["auth_method"] == "password"
    resolved = resolve_event(event)
    assert resolved.actor_user.identifier == "hua" and resolved.actor_ip.identifier == "203.0.113.11"
    assert resolved.target.identifier == "localhost" and resolved.outcome == "failure"


def test_accepted_login_event_is_success():
    resolved = resolve_event(_event(L_ACCEPT))
    assert resolved.outcome == "success" and resolved.actor_user.identifier == "root"
    assert resolve_event(_event(L_FAIL)).payload["invalid_user"] is False


def test_sudo_event_is_endpoint_process_execution_and_counts_as_privileged():
    event = _event(L_SUDO_TTY)
    assert C.validate_event(event) == []
    assert event["source_layer"] == "endpoint" and event["payload"]["process_name"] == "sudo"
    assert event["payload"]["command_line"] == "/usr/bin/ls /etc" and event["payload"]["tty"] == "pts/0"
    resolved = resolve_event(event)
    assert resolved.actor_user.identifier == "alice" and resolved.actor_host.identifier == "localhost"
    vec = next(v for v in extract([event])["vectors"] if v["entity_id"] == entity_id("user", "org-t", "alice"))
    assert vec["features"]["privilege.privileged_ops"] == 1


def test_sudo_with_group_field_is_captured():
    event = _event(L_SUDO_GROUP)
    assert event["payload"]["run_as"] == "svc" and event["payload"]["run_as_group"] == "nogroup"
    assert event["payload"]["command_line"] == "/usr/bin/chown svc /srv/site"


# ------------------------------------------------------------------ conversion


def _make_org(tmp_path):
    org = tmp_path / "org"
    (org / "log" / "var" / "log").mkdir(parents=True)
    (org / "ground-truth").mkdir()
    (org / "ground-truth" / "rules.yaml").write_text(RULES_YAML, encoding="utf-8")
    lines = [L_FAIL, L_INVALID, L_FAIL_INVALID, L_PAM_DUP, L_ACCEPT, L_SUDO, L_SUDO_TTY, L_SUDO_GROUP,
             L_CRON, L_CLOSED, L_SPACE_DAY, L_NUL, "garbage"]
    (org / "log" / "var" / "log" / "auth.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return org


def test_convert_accounts_for_every_line(tmp_path):
    out = tmp_path / "out"
    report = adapter.convert(str(_make_org(tmp_path)), str(out), "org-t", 2025)
    assert report["lines"] == 13
    assert report["events"] == 7                         # 3 failed + 1 accepted + 3 sudo
    assert report["events_by_kind"] == {"ssh_accepted": 1, "ssh_failed": 3, "sudo_command": 3}
    assert report["skipped_by_reason"] == {"cron": 1, "ssh_connection_noise": 1,
                                           "ssh_invalid_user_duplicate": 1, "ssh_other": 1}
    assert report["unparsed_lines"] == 2
    assert report["events"] + report["skipped_lines"] + report["unparsed_lines"] == report["lines"]
    assert report["contract_problems"] == {}
    assert report["ssh_failed_distinct_source_ips"] == 2 and report["ssh_failed_distinct_usernames"] == 2
    assert report["timestamp_assumptions"] == {"year": 2025, "utc_offset_hours": 0.0,
                                               "note": "syslog has no year or zone; both are assumed"}


def test_labels_in_sidecar_only(tmp_path):
    out = tmp_path / "out"
    adapter.convert(str(_make_org(tmp_path)), str(out), "org-t", 2025)
    labels = [json.loads(x) for x in (out / "labels.jsonl").read_text(encoding="utf-8").splitlines()]
    by_label = {}
    for rec in labels:
        for hit in rec["labels"]:
            by_label.setdefault(hit["label"], set()).add(rec["event_id"])
    assert len(by_label["bruteforce_login_server_attempt"]) == 3          # all three failed-login events
    assert len(by_label["change_ownership_demo"]) == 1                    # only the GROUP= sudo line
    for line in (out / "events.jsonl").read_text(encoding="utf-8").splitlines():
        assert "bruteforce" not in line and "labels" not in json.loads(line)


def test_label_counts_are_per_event_not_per_rule_hit(tmp_path):
    """L_FAIL_INVALID matches two rules with the same label; it must still count once."""
    report = adapter.convert(str(_make_org(tmp_path)), str(tmp_path / "out"), "org-t", 2025)
    assert report["label_counts_moderate"]["bruteforce_login_server_attempt"] == 3


def test_scanner_usernames_with_spaces_or_empty_are_still_failed_logins():
    trailing = "Apr 27 08:48:36 localhost sshd[9]: Failed password for invalid user Administrator  from 203.0.113.9 port 1 ssh2"
    empty = "Apr 27 08:48:36 localhost sshd[9]: Failed none for invalid user  from 203.0.113.9 port 2 ssh2"
    spaced = "Apr 27 08:48:36 localhost sshd[9]: Failed password for invalid user a b from 203.0.113.9 port 3 ssh2"
    users = []
    for line in (trailing, empty, spaced):
        event = _event(line)
        assert C.validate_event(event) == []
        users.append(event["entities"][0]["identifier"])
        assert event["payload"]["source_ip"] == "203.0.113.9"
    assert users == ["Administrator", "<empty>", "a b"]
    assert _kind("Apr 27 08:48:36 localhost sshd[9]: Failed to release session: Interrupted system call")[0] == "skip"


def test_conversion_is_byte_for_byte_deterministic(tmp_path):
    org = _make_org(tmp_path)
    adapter.convert(str(org), str(tmp_path / "a"), "org-t", 2025)
    adapter.convert(str(org), str(tmp_path / "b"), "org-t", 2025)
    for name in ("events.jsonl", "labels.jsonl"):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()


# ------------------------------------------------------------------ real data (skipped if absent)

ORG_Y_AUTH = REPO / "data" / "external" / "web_server_logs" / "org-y" / "organization-y" / "log" / "var" / "log" / "auth.log"
ORG_Y_REPORT = REPO / "data" / "external" / "web_server_logs" / "derived" / "org-y" / "auth" / "report.json"


@pytest.mark.skipif(not (ORG_Y_AUTH.exists() and ORG_Y_REPORT.exists()), reason="Org Y auth.log not downloaded/converted")
def test_org_y_counts_match_an_independent_count_of_the_raw_file():
    report = json.loads(ORG_Y_REPORT.read_text(encoding="utf-8"))
    # Deliberately different from the adapter's regexes (greedy, substring based) so a format
    # variant the adapter misses shows up as a count mismatch instead of vanishing silently.
    failed_shape = re.compile(r"sshd\[\d+\]: Failed \S+ for .* from \S+ port \d+")
    accepted_shape = re.compile(r"sshd\[\d+\]: Accepted \S+ for .* from \S+ port \d+")
    lines = failed = accepted = sudo_cmd = 0
    with open(ORG_Y_AUTH, "rt", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            lines += 1
            if failed_shape.search(line):
                failed += 1
            elif accepted_shape.search(line):
                accepted += 1
            elif "sudo:" in line and "COMMAND=" in line:
                sudo_cmd += 1
    assert report["lines"] == lines
    assert report["events"] + report["skipped_lines"] + report["unparsed_lines"] == lines   # nothing lost
    assert report["events_by_kind"] == {"ssh_accepted": accepted, "ssh_failed": failed, "sudo_command": sudo_cmd}
    assert report["contract_problems"] == {}
