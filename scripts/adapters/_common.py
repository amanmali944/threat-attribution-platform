"""Helpers shared by the dataset adapters: ground-truth rule loading and labelling.

Ground truth in the Web Server Log Dataset is a list of text-pattern rules (all patterns of
a rule must match, case-insensitive). See the module docstring of `web_server_logs.py` for
the caveats that apply to every label produced here.
"""
from __future__ import annotations

import gzip
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
