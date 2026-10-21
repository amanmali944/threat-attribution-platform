"""Isolation Forest anomaly detector (Phase 3b): Feature Vectors -> scores -> Alert Envelopes.

* One model per entity type (user / ip / host ...): their feature distributions differ.
  A type with fewer than ``min_train_windows`` training windows gets no model (score None),
  rather than a model fitted on a handful of points.
* Trained on background windows only - no attack labels are used.
* Score = ECDF rank of the raw anomaly score against a reference set of background windows:
  0.99 means "more anomalous than 99% of the reference windows". Scores are therefore
  comparable across entity types and easy to set an alert budget on.
* Inputs: the fs-1.1.0 features; count-like features are log1p-transformed so heavy tails
  (one window with 400 failures) do not dominate the split points.
* Deterministic: fixed random_state, single thread, inputs sorted.
"""
from __future__ import annotations

import bisect
import math
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

import numpy as np
from sklearn.ensemble import IsolationForest

from app.services.detection import contract as C
from app.services.detection.envelope import build_alert
from app.services.detection.features import FEATURE_KINDS, FEATURE_NAMES

MODEL_VERSION = "iforest-1.1.0"  # 1.1.0: inputs are the fs-1.2.0 features
RULE_ID = "ML-IFOREST-001"

_LOG_FEATURES = frozenset(
    name for name in FEATURE_NAMES
    if FEATURE_KINDS[name] == "int" or name in ("volume.bytes_out", "volume.rows_read", "timing.mean_interarrival_s")
)


def transform(features: Mapping[str, Any]) -> List[float]:
    """Feature dict -> model input row (fixed order; log1p on non-negative count-like features)."""
    row = []
    for name in FEATURE_NAMES:
        value = float(features[name])
        row.append(math.log1p(max(value, 0.0)) if name in _LOG_FEATURES else value)
    return row


@dataclass
class _TypeModel:
    model: IsolationForest
    reference: List[float]              # sorted raw scores of reference background windows
    mean: List[float]                   # per-feature mean of transformed training rows (for explanations)
    std: List[float]
    n_train: int


@dataclass
class IsolationForestDetector:
    n_estimators: int = 200
    max_samples: int = 256
    random_state: int = 42
    min_train_windows: int = 20
    models: Dict[str, _TypeModel] = field(default_factory=dict)

    def fit(
        self,
        train_vectors: Iterable[Mapping[str, Any]],
        reference_vectors: Optional[Iterable[Mapping[str, Any]]] = None,
    ) -> "IsolationForestDetector":
        train = _by_type(train_vectors)
        reference = _by_type(reference_vectors) if reference_vectors is not None else train
        self.models = {}
        for etype in sorted(train):
            rows = train[etype]
            if len(rows) < self.min_train_windows:
                continue
            X = np.array(rows, dtype=float)
            model = IsolationForest(
                n_estimators=self.n_estimators,
                max_samples=min(self.max_samples, len(rows)),
                contamination="auto",
                random_state=self.random_state,
                n_jobs=1,
            ).fit(X)
            ref_rows = reference.get(etype) or rows
            ref_scores = sorted((-model.score_samples(np.array(ref_rows, dtype=float))).tolist())
            self.models[etype] = _TypeModel(
                model=model,
                reference=ref_scores,
                mean=X.mean(axis=0).tolist(),
                std=X.std(axis=0).tolist(),
                n_train=len(rows),
            )
        return self

    def raw_scores(self, vectors: Sequence[Mapping[str, Any]]) -> List[Optional[float]]:
        out: List[Optional[float]] = [None] * len(vectors)
        groups: Dict[str, List[int]] = {}
        for i, vector in enumerate(vectors):
            groups.setdefault(vector["entity_type"], []).append(i)
        for etype, idxs in groups.items():
            tm = self.models.get(etype)
            if tm is None:
                continue
            X = np.array([transform(vectors[i]["features"]) for i in idxs], dtype=float)
            for i, s in zip(idxs, (-tm.model.score_samples(X)).tolist()):
                out[i] = float(s)
        return out

    def scores(self, vectors: Sequence[Mapping[str, Any]]) -> List[Optional[float]]:
        """ECDF scores in [0, 1] (None where the entity type has no model)."""
        raw = self.raw_scores(vectors)
        out: List[Optional[float]] = []
        for vector, s in zip(vectors, raw):
            if s is None:
                out.append(None)
                continue
            ref = self.models[vector["entity_type"]].reference
            out.append(round(bisect.bisect_left(ref, s) / len(ref), 6))
        return out

    def explain(self, vector: Mapping[str, Any], k: int = 3) -> List[Dict[str, Any]]:
        """Top-k features that deviate most from the training mean (in training std units)."""
        tm = self.models[vector["entity_type"]]
        row = transform(vector["features"])
        deviations = []
        for j, name in enumerate(FEATURE_NAMES):
            z = (row[j] - tm.mean[j]) / max(tm.std[j], 1e-9)
            deviations.append((abs(z), name, z))
        deviations.sort(key=lambda t: (-t[0], t[1]))
        return [
            {"feature": name, "value": vector["features"][name], "baseline_z": round(z, 3)}
            for _, name, z in deviations[:k]
        ]

    def alerts(self, vectors: Sequence[Mapping[str, Any]], threshold: float) -> List[Dict[str, Any]]:
        """Alert Envelopes for windows scoring at or above ``threshold``."""
        out = []
        for vector, score in zip(vectors, self.scores(vectors)):
            if score is None or score < threshold:
                continue
            evidence = self.explain(vector)
            out.append(build_alert(
                vector=vector, detector="isolation_forest", detector_version=MODEL_VERSION, rule_id=RULE_ID,
                title="Anomalous behaviour for this entity type",
                description=f"Isolation Forest score {score:.4f} (>= {threshold}); most unusual: "
                            + ", ".join(e["feature"] for e in evidence),
                technique="unknown", technique_id=None, severity="medium", score=score, evidence=evidence,
            ))
        return out

    def metadata(self) -> Dict[str, Any]:
        return {
            "model_version": MODEL_VERSION,
            "feature_set_version": C.FEATURE_SET_VERSION,
            "params": {"n_estimators": self.n_estimators, "max_samples": self.max_samples,
                       "random_state": self.random_state, "min_train_windows": self.min_train_windows},
            "types": {t: {"n_train": m.n_train, "n_reference": len(m.reference)} for t, m in sorted(self.models.items())},
        }


def _by_type(vectors: Optional[Iterable[Mapping[str, Any]]]) -> Dict[str, List[List[float]]]:
    grouped: Dict[str, List[Any]] = {}
    for vector in vectors or []:
        grouped.setdefault(vector["entity_type"], []).append(vector)
    out: Dict[str, List[List[float]]] = {}
    for etype, items in grouped.items():
        items.sort(key=lambda v: (v["window_start"], v["entity_id"]))  # input order never changes the model
        out[etype] = [transform(v["features"]) for v in items]
    return out
