"""Helpers shared by the dataset adapters: ground-truth rule loading and labelling.

Ground truth in the Web Server Log Dataset is a list of text-pattern rules (all patterns of
a rule must match, case-insensitive). See the module docstring of `web_server_logs.py` for
the caveats that apply to every label produced here.
"""
from __future__ import annotations

import gzip
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

import yaml


@dataclass(frozen=True)
class Rule:
    rule_id: str
    label: str
    sensitivity: str
    patterns: Tuple["re.Pattern[str]", ...]


def _compile(pattern: Any) -> "re.Pattern[str]":
    pieces = [re.escape(piece) for piece in str(pattern).split("%")]
    return re.compile(".*".join(pieces), re.IGNORECASE | re.DOTALL)


def load_rules(path: str) -> List[Rule]:
    with open(path, "rt", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or []
    return [
        Rule(
            rule_id=str(item["id"]),
            label=str(item["ground_truth_label"]),
            sensitivity=str(item.get("sensitivity", "moderate")),
            patterns=tuple(_compile(p) for p in item["filter"]),
        )
        for item in data
    ]


def label_line(
    line: str, status_code: Optional[int], rules: Sequence[Rule]
) -> Dict[str, List[Dict[str, str]]]:
    """Rule hits for one log line, split by sensitivity.

    ``status_code`` (web logs) is appended as ``code: NNN`` so the dataset's
    ``code: 404``-style patterns can match; pass None for logs without one.
    """
    text = line.rstrip("\r\n")
    if status_code is not None:
        text += f" code: {status_code}"
    hits: Dict[str, List[Dict[str, str]]] = {"moderate": [], "strict": []}
    for rule in rules:
        if all(p.search(text) for p in rule.patterns):
            bucket = "strict" if rule.sensitivity == "strict" else "moderate"
            entry = {"rule_id": rule.rule_id, "label": rule.label}
            if entry not in hits[bucket]:
                hits[bucket].append(entry)
    return hits


def open_text(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "rt", encoding="utf-8", errors="replace")


# --------------------------------------------------------------------------- AIT per-line labels
#
# AIT-LDS v2.0 ships ground truth as one JSON object per labelled log line,
# {"line": N, "labels": [...], "rules": {label: [rule, ...]}}, in labels/<same path as gather/>.
# A log file without a label file has no attack lines.


def load_line_labels(path: str) -> Dict[int, List[Dict[str, str]]]:
    """line number (1-based) -> [{rule_id, label}] from an AIT label file (empty if absent)."""
    out: Dict[int, List[Dict[str, str]]] = {}
    if not os.path.exists(path):
        return out
    with open(path, "rt", encoding="utf-8") as handle:
        for raw in handle:
            if not raw.strip():
                continue
            record = json.loads(raw)
            rules = record.get("rules", {})
            out[int(record["line"])] = [
                {"rule_id": (rules.get(label) or ["ait"])[0], "label": label} for label in record["labels"]
            ]
    return out


def ait_label_path(org_dir: str, raw_path: str) -> str:
    """gather/<host>/logs/x  ->  labels/<host>/logs/x"""
    rel = os.path.relpath(raw_path, os.path.join(org_dir, "gather"))
    return os.path.join(org_dir, "labels", rel)


class RuleLabeller:
    """Labels from text-pattern rules (Web Server Log Dataset)."""

    source = "rules"

    def __init__(self, rules: Sequence[Rule]):
        self.rules = list(rules)

    def hits(self, raw_path: str, lineno: int, line: str, status_code: Optional[int] = None):
        return label_line(line, status_code, self.rules)


class LineLabeller:
    """Labels from AIT per-line ground truth files."""

    source = "line-labels"

    def __init__(self, org_dir: str):
        self.org_dir = org_dir
        self._cache: Dict[str, Dict[int, List[Dict[str, str]]]] = {}

    def hits(self, raw_path: str, lineno: int, line: str, status_code: Optional[int] = None):
        if raw_path not in self._cache:
            self._cache[raw_path] = load_line_labels(ait_label_path(self.org_dir, raw_path))
        return {"moderate": list(self._cache[raw_path].get(lineno, [])), "strict": []}
