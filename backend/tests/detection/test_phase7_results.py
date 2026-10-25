"""The committed Phase 7 risk results must be consistent, explained and free of identifiers."""
import json
import re
from pathlib import Path

PATH = Path(__file__).resolve().parents[3] / "data" / "evaluation" / "phase7_risk.json"
RESULTS = json.loads(PATH.read_text(encoding="utf-8"))
LEVELS = ((75.0, "critical"), (50.0, "high"), (25.0, "medium"), (0.0, "low"))


def test_ranks_levels_and_explanations_are_consistent():
    assert len(RESULTS["scenarios"]) == 8
    for name, s in RESULTS["scenarios"].items():
        scores = [r["score"] for r in s["ranked"]]
        assert scores == sorted(scores, reverse=True), name
        assert s["intrusion_rank"] == 1 + sum(1 for x in scores if x > s["intrusion_score"]), name
        assert s["every_nonzero_score_explained"], name
        for r in s["ranked"]:
            assert r["level"] == next(l for floor, l in LEVELS if r["score"] >= floor), name
            assert 0 <= r["score"] <= 100


def test_pooled_counts_and_no_identifiers():
    for group in ("development", "held-out"):
        rows = [s for s in RESULTS["scenarios"].values() if s["role"] == group]
        assert RESULTS["pooled"][group]["intrusion_ranked_first"] == \
               f"{sum(1 for s in rows if s['intrusion_rank'] == 1)}/{len(rows)}"
    text = PATH.read_text(encoding="utf-8")
    assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text) and "ent-" not in text
