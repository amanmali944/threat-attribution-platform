"""Fusion, calibration and alert-fatigue controls (Phase 4, contract section 5).

Input: *scored windows* - one per (entity, window) - carrying the detector outputs:
    {"entity_id", "entity_type", "window_start", "window_end", "features": {...fs features},
     "rules": {rule_id: severity}, "iforest_score": float | None, "label": ... (training only)}

1. ``fusion_inputs`` turns a scored window into a short, fixed list of numbers: rule hits by
   severity, the Isolation Forest score (and whether there was a model at all - "no model" is
   missing, never "normal"), and a few key features.
2. ``FusionModel`` - logistic regression (interpretable, C = 0.1; HistGradientBoosting as
   challenger) over those inputs, trained on labelled windows from OTHER scenario runs.
   p(hostile), hostile = incident or exfiltration. Training weights give every (scenario, label)
   group the same total weight (``group_weights``) - on the development pair an unweighted model
   learnt mostly one scenario's 167-window exfiltration stream.
3. Calibration - isotonic regression on out-of-fold predictions (leave-one-scenario-out inside
   the training scenarios), so ``confidence`` means what it says.
4. Thresholds - tau_alert = lowest confidence whose out-of-fold precision reaches the target;
   tau_review = highest confidence that still keeps the target recall. Decisions: alert /
   review (abstain: an analyst decides) / suppress.
5. ``fuse_alerts`` - consecutive alert / review windows of the same entity inside the
   suppression window become ONE Fused Alert; the folded repeats are counted.

Deterministic: fixed random_state, inputs sorted, single thread.
"""
from __future__ import annotations

import hashlib
import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from app.services.detection import contract as C
from app.services.detection.envelope import alert_id
from app.services.detection.labeling import to_us
from app.services.detection.rules import RULESETS

FUSION_VERSION = "fusion-1.0.0"
CALIBRATION_VERSION = "cal-1.0.0"
HOSTILE = frozenset({"incident", "exfiltration"})
DECISIONS = ("alert", "review", "suppress")
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

FUSION_INPUTS: Tuple[str, ...] = (
    "rules.high",               # a high / critical rule fired
    "rules.medium",             # a medium rule fired
    "rules.count",              # distinct rules fired
    "iforest.score",            # ECDF score (0 when there is no model)
    "iforest.missing",          # 1 when the entity type had no model
    "log.event_count",
    "peer.volume_z",            # signed log of the peer z-score
    "novelty.new_source_ip",
    "log.new_target",
    "log.privileged_ops",
    "failure.http_error_rate",
    "timing.off_hours",
    "log.dns_long_names",
    "type.user",
    "type.host",
    "type.ip",
)


def _slog(value: float) -> float:
    return math.copysign(math.log1p(abs(value)), value)


def fusion_inputs(window: Mapping[str, Any]) -> List[float]:
    """Scored window -> fusion input row (order of FUSION_INPUTS)."""
    f = window["features"]
    severities = [SEVERITY_RANK[s] for s in window.get("rules", {}).values()]
    score = window.get("iforest_score")
    etype = window["entity_type"]
    return [
        float(any(s >= SEVERITY_RANK["high"] for s in severities)),
        float(any(s == SEVERITY_RANK["medium"] for s in severities)),
        float(len(severities)),
        float(score) if score is not None else 0.0,
        float(score is None),
        math.log1p(f["volume.event_count"]),
        _slog(f["peer.volume_zscore"]),
        float(f["novelty.new_source_ip"]),
        math.log1p(f["novelty.new_target"]),
        math.log1p(f["privilege.privileged_ops"]),
        float(f["failure.http_error_rate"]),
        float(f["timing.off_hours"]),
        math.log1p(f["dns.long_names"]),
        float(etype == "user"),
        float(etype == "host"),
        float(etype == "ip"),
    ]


def is_hostile(window: Mapping[str, Any]) -> int:
    return int(window["label"] in HOSTILE)


def _order(windows: Sequence[Mapping[str, Any]]) -> List[int]:
    return sorted(range(len(windows)), key=lambda i: (windows[i].get("scenario", ""), windows[i]["window_start"],
                                                       windows[i]["entity_id"]))


# --------------------------------------------------------------------------- calibration metrics


def reliability(y: Sequence[int], p: Sequence[float], bins: int = 10) -> Dict[str, Any]:
    """Expected calibration error, Brier score and equal-width reliability bins."""
    y_arr, p_arr = np.asarray(y, dtype=float), np.asarray(p, dtype=float)
    if len(y_arr) == 0:
        return {"n": 0, "ece": None, "brier": None, "bins": []}
    edges = np.linspace(0.0, 1.0, bins + 1)
    rows, ece = [], 0.0
    for k in range(bins):
        lo, hi = edges[k], edges[k + 1]
        mask = (p_arr >= lo) & ((p_arr < hi) if k < bins - 1 else (p_arr <= hi))
        n = int(mask.sum())
        if n == 0:
            continue
        mean_p, frac = float(p_arr[mask].mean()), float(y_arr[mask].mean())
        ece += n / len(y_arr) * abs(mean_p - frac)
        rows.append({"lo": round(float(lo), 2), "hi": round(float(hi), 2), "n": n,
                     "mean_confidence": round(mean_p, 4), "fraction_hostile": round(frac, 4)})
    return {"n": int(len(y_arr)), "ece": round(float(ece), 4),
            "brier": round(float(np.mean((p_arr - y_arr) ** 2)), 6), "bins": rows}


def choose_thresholds(y: Sequence[int], p: Sequence[float], target_precision: float,
                      review_recall: float) -> Dict[str, Any]:
    """tau_alert: lowest threshold whose precision >= target; tau_review: highest keeping the recall.

    Candidates are the distinct confidences. If no threshold reaches the target precision,
    tau_alert is above 1 (nothing is auto-alerted; everything plausible goes to review).
    """
    y_arr, p_arr = np.asarray(y, dtype=int), np.asarray(p, dtype=float)
    positives = int(y_arr.sum())
    candidates = sorted(set(p_arr.tolist()))
    tau_alert = None
    for t in candidates:
        flagged = p_arr >= t
        if flagged.sum() and y_arr[flagged].sum() / flagged.sum() >= target_precision and y_arr[flagged].sum() > 0:
            tau_alert = t
            break
    tau_review = 0.0
    for t in reversed(candidates):
        if positives and y_arr[p_arr >= t].sum() / positives >= review_recall:
            tau_review = t
            break
    if tau_alert is None:
        tau_alert = 1.0 + 1e-9
    tau_review = min(tau_review, tau_alert)
    return {"tau_alert": float(tau_alert), "tau_review": float(tau_review),
            "target_precision": target_precision, "review_recall": review_recall,
            "alert_reachable": tau_alert <= 1.0}


# --------------------------------------------------------------------------- model


def _make(model: str, random_state: int):
    if model == "logreg":
        return Pipeline([("scale", StandardScaler()),
                         ("lr", LogisticRegression(C=0.1, max_iter=5000, random_state=random_state))])
    if model == "hgb":
        return HistGradientBoostingClassifier(max_depth=3, learning_rate=0.1, max_iter=200,
                                              random_state=random_state)
    raise ValueError(f"unknown fusion model: {model}")


def _fit(estimator, model: str, X: np.ndarray, y: np.ndarray, weight: np.ndarray):
    if model == "logreg":
        return estimator.fit(X, y, lr__sample_weight=weight)
    return estimator.fit(X, y, sample_weight=weight)


def group_weights(labels: Sequence[str], groups: Sequence[str]) -> np.ndarray:
    """Each (scenario, label) group gets the same total weight, whatever its window count.

    One long exfiltration stream (167 windows of one host) must not outweigh a whole intrusion
    (10 windows) or the scenario's background. Weights are normalised to mean 1.
    """
    counts = Counter(zip(groups, labels))
    raw = np.array([1.0 / counts[(g, l)] for g, l in zip(groups, labels)], dtype=float)
    return raw * (len(raw) / raw.sum())


@dataclass
class FusionModel:
    model: str = "logreg"
    target_precision: float = 0.8
    review_recall: float = 0.9
    random_state: int = 42
    estimator: Any = None
    calibrator: Optional[IsotonicRegression] = None
    thresholds: Dict[str, Any] = field(default_factory=dict)
    training: Dict[str, Any] = field(default_factory=dict)

    def fit(self, windows: Sequence[Mapping[str, Any]], groups: Sequence[str]) -> "FusionModel":
        """Fit on labelled windows; ``groups`` = scenario run of each window (calibration folds)."""
        if len(windows) != len(groups):
            raise ValueError("one group per window")
        order = _order(windows)
        windows = [windows[i] for i in order]
        groups = [groups[i] for i in order]
        X = np.array([fusion_inputs(w) for w in windows], dtype=float)
        y = np.array([is_hostile(w) for w in windows], dtype=int)
        if y.sum() == 0 or y.sum() == len(y):
            raise ValueError("fusion needs hostile and background windows")
        weight = group_weights([w["label"] for w in windows], groups)

        oof = np.zeros(len(y), dtype=float)
        distinct = sorted(set(groups))
        folds: List[Tuple[np.ndarray, np.ndarray]] = []
        if len(distinct) >= 2:
            garr = np.array(groups)
            for g in distinct:
                test_idx = np.where(garr == g)[0]
                train_idx = np.where(garr != g)[0]
                if y[train_idx].sum() and y[train_idx].sum() < len(train_idx):
                    folds.append((train_idx, test_idx))
            scheme = "leave-one-scenario-out"
        if len(distinct) < 2 or not folds:
            if y.sum() < 2:
                raise ValueError("calibration needs at least two hostile windows")
            splitter = StratifiedKFold(n_splits=min(5, int(y.sum())), shuffle=True, random_state=self.random_state)
            folds = list(splitter.split(X, y))
            scheme = "stratified k-fold (a single training scenario: windows are not independent - optimistic)"
        for train_idx, test_idx in folds:
            est = _fit(_make(self.model, self.random_state), self.model, X[train_idx], y[train_idx],
                       group_weights([windows[i]["label"] for i in train_idx], [groups[i] for i in train_idx]))
            oof[test_idx] = est.predict_proba(X[test_idx])[:, 1]

        # Calibration and thresholds are fitted UNWEIGHTED: confidence must match real frequencies.
        self.calibrator = IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip").fit(oof, y)
        calibrated_oof = self.calibrator.predict(oof)
        self.thresholds = choose_thresholds(y, calibrated_oof, self.target_precision, self.review_recall)
        self.estimator = _fit(_make(self.model, self.random_state), self.model, X, y, weight)
        self.training = {
            "windows": int(len(y)), "hostile_windows": int(y.sum()), "groups": distinct,
            "calibration_scheme": scheme, "folds": len(folds),
            "out_of_fold_reliability": reliability(y, calibrated_oof),
        }
        return self

    def raw_proba(self, windows: Sequence[Mapping[str, Any]]) -> List[float]:
        if self.estimator is None:
            raise RuntimeError("fit() first")
        X = np.array([fusion_inputs(w) for w in windows], dtype=float)
        return self.estimator.predict_proba(X)[:, 1].tolist() if len(X) else []

    def confidence(self, windows: Sequence[Mapping[str, Any]]) -> List[float]:
        raw = self.raw_proba(windows)
        return [round(float(c), 6) for c in self.calibrator.predict(raw)] if raw else []

    def decide(self, confidences: Iterable[float]) -> List[str]:
        tau_alert, tau_review = self.thresholds["tau_alert"], self.thresholds["tau_review"]
        return ["alert" if c >= tau_alert else "review" if c >= tau_review else "suppress" for c in confidences]

    def explain(self, window: Mapping[str, Any], k: int = 3) -> List[Dict[str, Any]]:
        """Logistic regression: top-k contributions = coefficient x standardised input."""
        if self.model != "logreg":
            return []
        scale, lr = self.estimator.named_steps["scale"], self.estimator.named_steps["lr"]
        row = np.array(fusion_inputs(window), dtype=float)
        z = (row - scale.mean_) / np.where(scale.scale_ > 0, scale.scale_, 1.0)
        contributions = lr.coef_[0] * z
        top = sorted(range(len(FUSION_INPUTS)), key=lambda j: (-abs(contributions[j]), FUSION_INPUTS[j]))[:k]
        return [{"input": FUSION_INPUTS[j], "value": round(float(row[j]), 6),
                 "contribution": round(float(contributions[j]), 4)} for j in top]

    def coefficients(self) -> Dict[str, float]:
        if self.model != "logreg":
            return {}
        lr = self.estimator.named_steps["lr"]
        return {name: round(float(c), 4) for name, c in zip(FUSION_INPUTS, lr.coef_[0])}

    def metadata(self) -> Dict[str, Any]:
        return {"fusion_version": FUSION_VERSION, "calibration_version": CALIBRATION_VERSION, "model": self.model,
                "inputs": list(FUSION_INPUTS), "thresholds": self.thresholds, "training": self.training,
                "coefficients": self.coefficients()}


# --------------------------------------------------------------------------- fused alerts


def _rule_meta(ruleset: str) -> Dict[str, Any]:
    return {r.rule_id: r for r in RULESETS[ruleset][1]}


def fused_alert_id(entity_id: str, window_start: str) -> str:
    return "fal-" + hashlib.sha256(f"{entity_id}|{window_start}".encode("utf-8")).hexdigest()[:8]


def fuse_alerts(windows: Sequence[Mapping[str, Any]], confidences: Sequence[float], decisions: Sequence[str],
                suppression_seconds: int = 1800, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fused Alerts (contract section 5) for windows decided alert / review.

    Windows of the same entity whose gap is at most ``suppression_seconds`` are folded into one
    Fused Alert: its window spans them, its confidence and decision are the strongest member's,
    and ``suppressed_duplicates`` counts the folded windows.
    """
    if not (len(windows) == len(confidences) == len(decisions)):
        raise ValueError("one confidence and one decision per window")
    rank = {"alert": 2, "review": 1, "suppress": 0}
    kept = sorted((i for i, d in enumerate(decisions) if d != "suppress"),
                  key=lambda i: (windows[i]["entity_id"], windows[i]["window_start"]))
    groups: List[List[int]] = []
    for i in kept:
        if groups and windows[groups[-1][-1]]["entity_id"] == windows[i]["entity_id"] and \
                to_us(windows[i]["window_start"]) - to_us(windows[groups[-1][-1]]["window_end"]) <= suppression_seconds * 1_000_000:
            groups[-1].append(i)
        else:
            groups.append([i])

    out = []
    for members in groups:
        lead = max(members, key=lambda i: (rank[decisions[i]], confidences[i], windows[i]["window_start"]))
        first, last = windows[members[0]], windows[members[-1]]
        rules: Dict[str, str] = {}
        for i in members:
            rules.update(windows[i].get("rules", {}))
        meta = _rule_meta(first.get("ruleset", "rules-1.2.0"))
        top_rule = max(rules, key=lambda r: (SEVERITY_RANK[rules[r]], r)) if rules else None
        detectors = (["rules"] if rules else []) + (
            ["isolation_forest"] if any(windows[i].get("iforest_score") is not None for i in members) else [])
        member_ids = sorted({alert_id("rules", r, w["entity_id"], w["window_start"])
                             for w in (windows[i] for i in members) for r in w.get("rules", {})})
        event_ids = sorted({e for i in members for e in windows[i].get("event_ids", [])})
        out.append({
            "schema_version": C.SCHEMA_VERSION,
            "fused_alert_id": fused_alert_id(first["entity_id"], first["window_start"]),
            "tenant_id": tenant_id or first.get("tenant_id"),
            "entity_id": first["entity_id"],
            "entity_type": first["entity_type"],
            "window_start": first["window_start"],
            "window_end": last["window_end"],
            "member_alert_ids": member_ids,
            "detectors": detectors,
            "technique": meta[top_rule].technique if top_rule else "unknown",
            "technique_id": meta[top_rule].technique_id if top_rule else None,
            "severity": rules[top_rule] if top_rule else "medium",
            "confidence": round(float(confidences[lead]), 6),
            "decision": decisions[lead],
            "suppressed_duplicates": len(members) - 1,
            "calibration_version": CALIBRATION_VERSION,
            "event_ids": event_ids,
            "evidence": [{"rule_id": r, "severity": s, "detector": "rules"} for r, s in sorted(rules.items())],
            "member_windows": len(members),
        })
    out.sort(key=lambda a: (a["window_start"], a["entity_id"]))
    return out


def rules_first(windows: Sequence[Mapping[str, Any]], fusion_decisions: Sequence[str]) -> List[str]:
    """The pipeline's decision (pre-registered before any held-out scenario was scored).

    A high / critical rule hit is an alert; any other rule hit is at least a review; everything
    else is the fusion model's decision. On the development scenarios the rules were precise
    (0.9-1.0) while fusion thresholds learnt on another scenario did not transfer reliably, so
    fusion may add alerts and reviews but never silence a rule.
    """
    out = []
    for window, decision in zip(windows, fusion_decisions):
        severities = [SEVERITY_RANK[s] for s in window.get("rules", {}).values()]
        if severities and max(severities) >= SEVERITY_RANK["high"]:
            out.append("alert")
        elif severities and decision == "suppress":
            out.append("review")
        else:
            out.append(decision)
    return out


def decision_counts(decisions: Iterable[str]) -> Dict[str, int]:
    counts = Counter(decisions)
    return {d: counts.get(d, 0) for d in DECISIONS}
