"""Evaluation helpers shared by the dataset evaluators (Phase 3 now, the Phase 8 harness later).

Window-level metrics for one *task*: a positive window label, ``background`` as the negative,
and every other label excluded from precision / recall (alerts on excluded windows are counted
separately - an alert on another attack class is not a false alarm). Never accuracy.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Mapping, Optional, Sequence

from sklearn.metrics import average_precision_score, roc_auc_score

from app.services.detection.labeling import to_us

NEGATIVE = "background"


def task_subset(records: Sequence[Mapping[str, Any]], positive: str) -> List[int]:
    """Indices of the windows scored for a task: its positives and the background."""
    return [i for i, r in enumerate(records) if r["label"] in (positive, NEGATIVE)]


def ranking_metrics(labels: Sequence[int], scores: Sequence[float]) -> Dict[str, Optional[float]]:
    """ROC-AUC and average precision; None when only one class is present."""
    if not labels or len(set(labels)) < 2:
        return {"roc_auc": None, "average_precision": None, "positives": sum(labels), "n": len(labels)}
    return {"roc_auc": round(float(roc_auc_score(labels, scores)), 4),
            "average_precision": round(float(average_precision_score(labels, scores)), 4),
            "positives": int(sum(labels)), "n": len(labels)}


def task_ranking(records: Sequence[Mapping[str, Any]], scores: Sequence[float], positive: str) -> Dict[str, Any]:
    idx = task_subset(records, positive)
    return ranking_metrics([1 if records[i]["label"] == positive else 0 for i in idx], [scores[i] for i in idx])


def operating_point(records: Sequence[Mapping[str, Any]], flags: Sequence[bool], days: float,
                    positive: str) -> Dict[str, Any]:
    """Counts and rates for one binary decision per window."""
    if len(records) != len(flags):
        raise ValueError("one flag per record")
    flagged = Counter(r["label"] for r, f in zip(records, flags) if f)
    total = sum(1 for r in records if r["label"] == positive)
    tp, fp = flagged.get(positive, 0), flagged.get(NEGATIVE, 0)
    other = {k: v for k, v in sorted(flagged.items()) if k not in (positive, NEGATIVE)}
    first = sorted(r["window_start"] for r, f in zip(records, flags) if f and r["label"] == positive)
    return {
        "positive_windows_flagged": tp, "positive_windows_total": total,
        "recall": round(tp / total, 4) if total else None,
        "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "false_alarm_windows": fp, "alerts_on_excluded_windows": other,
        "alerts_per_day": round(sum(flagged.values()) / days, 1),
        "false_alarms_per_day": round(fp / days, 1),
        "detected": tp > 0,
        "first_flagged_positive_window": first[0] if first else None,
    }


def latency_minutes(first_positive_window: str, first_flagged_window: Optional[str], window_seconds: int) -> Optional[float]:
    """Minutes from the start of the first positive window to the END of the first flagged one."""
    if first_flagged_window is None:
        return None
    return round((to_us(first_flagged_window) - to_us(first_positive_window)) / 60e6 + window_seconds / 60, 1)
