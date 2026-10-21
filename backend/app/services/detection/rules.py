"""Rules engine (Phase 3a): Feature Vectors -> Alert Envelopes. Rule sets rules-1.0.0 / rules-1.1.0.

Every rule is a generic, documented behaviour (not tuned to one dataset). Conditions read
fs-1.1.0 features only. Two kinds of threshold:

* fixed      - a value with a meaning of its own (e.g. "at least one role change")
* calibrated - for volume-like features whose normal level depends on the environment,
               learned by ``calibrate()`` from BACKGROUND windows of the same entity type.

The rule definitions are shared; the rule-set version selects the calibration policy:

* rules-1.0.0 - threshold ``max(floor, quantile_q)``, fires at ``>=``. On Org Y the 0.999
                quantile equalled root's routine hourly sudo count, so every routine hour tied
                and fired (82 of 84 false alarms). Kept so the Org Y result stays reproducible.
* rules-1.1.0 - (decided on Org Y before AIT was opened) the learned bound is the background
                MAXIMUM times (1 + margin), and the window must be strictly ABOVE it; the floor
                still applies as an inclusive minimum. Plus a validation gate: ``gate()`` turns
                off any rule that fires on more than ``gate_max_fire_rate`` of validation
                background windows, before any test scoring.

Rule hits are binary, so a rule alert's ``score`` is 1.0; ``confidence`` is left to fusion.
"""
from __future__ import annotations

import math
import operator
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from app.services.detection import contract as C
from app.services.detection.envelope import build_alert
from app.services.detection.features import FEATURE_NAMES

RULESET_VERSION = "rules-1.1.0"  # the current default
CALIBRATED = "$calibrated"


@dataclass(frozen=True)
class CalibrationPolicy:
    quantile: Optional[float]               # None: each rule's own quantile
    strict: bool                            # calibrated bound must be exceeded, not met
    margin: float                           # relative headroom above the learned value
    gate_max_fire_rate: Optional[float]     # validation gate budget (None: no gate)


RULESETS: Dict[str, CalibrationPolicy] = {
    "rules-1.0.0": CalibrationPolicy(quantile=None, strict=False, margin=0.0, gate_max_fire_rate=None),
    "rules-1.1.0": CalibrationPolicy(quantile=1.0, strict=True, margin=0.25, gate_max_fire_rate=0.005),
}

_OPS: Dict[str, Callable[[float, float], bool]] = {
    ">=": operator.ge, ">": operator.gt, "==": operator.eq, "<=": operator.le, "<": operator.lt,
}


@dataclass(frozen=True)
class Condition:
    feature: str
    op: str
    value: Any  # a number, or CALIBRATED

    def __post_init__(self) -> None:
        if self.feature not in FEATURE_NAMES:
            raise ValueError(f"unknown feature: {self.feature}")
        if self.op not in _OPS:
            raise ValueError(f"unknown operator: {self.op}")


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    technique: str
    technique_id: Optional[str]
    severity: str
    entity_types: Tuple[str, ...]
    conditions: Tuple[Condition, ...]
    rationale: str
    quantile: float = 0.999   # only for CALIBRATED conditions
    floor: float = 0.0        # only for CALIBRATED conditions

    @property
    def calibrated_feature(self) -> Optional[str]:
        found = [c.feature for c in self.conditions if c.value == CALIBRATED]
        if len(found) > 1:
            raise ValueError(f"{self.rule_id}: at most one calibrated condition per rule")
        return found[0] if found else None


DEFAULT_RULES: Tuple[Rule, ...] = (
    Rule("RULE-IDN-001", "Brute-force login burst", "credential_access", "T1110", "low", ("user", "ip"),
         (Condition("volume.login_count", ">=", 10),
          Condition("failure.login_failure_rate", ">=", 0.9),
          Condition("failure.max_consecutive_failures", ">=", 10)),
         "Ten or more logins in one window, nearly all failing, ten or more in a row."),
    Rule("RULE-IDN-002", "Password spray from one source", "credential_access", "T1110.003", "medium", ("ip",),
         (Condition("diversity.distinct_accounts_from_ip", ">=", 5),
          Condition("volume.login_count", ">=", 5),
          Condition("failure.login_failure_rate", ">=", 0.9)),
         "One source trying five or more accounts in one window, nearly all failing."),
    Rule("RULE-IDN-003", "Successful login from a never-seen source", "initial_access", "T1078", "high", ("user",),
         (Condition("volume.login_success_count", ">=", 1),
          Condition("novelty.new_source_ip", "==", 1)),
         "An account with enough history logs in successfully from a source IP it has never used."),
    Rule("RULE-IDN-004", "Successful login after repeated failures", "credential_access", "T1110", "high", ("ip",),
         (Condition("volume.login_success_count", ">=", 1),
          Condition("failure.max_consecutive_failures", ">=", 5)),
         "The same source fails five or more times in a row and then gets in (classic brute-force success)."),
    Rule("RULE-PRIV-001", "Privileged command burst", "privilege_escalation", "T1548.003", "high", ("user", "host"),
         (Condition("privilege.privileged_ops", ">=", CALIBRATED),),
         "Far more privileged commands in one window than this kind of entity ever ran in the background period.",
         quantile=0.999, floor=5),
    Rule("RULE-PRIV-002", "Role or privilege change", "privilege_escalation", "T1098", "medium", ("user",),
         (Condition("privilege.role_changes", ">=", 1),),
         "Any change to an account's role."),
    Rule("RULE-PRIV-003", "Privileged activity at an unusual hour", "privilege_escalation", "T1078", "medium", ("user", "host"),
         (Condition("timing.off_hours", "==", 1),
          Condition("privilege.privileged_ops", ">=", 1)),
         "Privileged commands when this entity is normally inactive."),
    Rule("RULE-APP-001", "Web error burst (scanning)", "reconnaissance", "T1595", "low", ("ip",),
         (Condition("volume.event_count", ">=", 20),
          Condition("failure.http_error_rate", ">=", 0.5)),
         "Twenty or more requests in one window, at least half of them errors."),
    Rule("RULE-DB-001", "Bulk data read", "collection", "T1213", "high", ("user",),
         (Condition("volume.rows_read", ">=", CALIBRATED),),
         "Far more rows read in one window than this kind of entity read in the background period.",
         quantile=0.999, floor=10000),
)


def nearest_rank_quantile(values: Sequence[float], q: float) -> float:
    """Smallest value v with at least q of the data <= v (nearest-rank; deterministic)."""
    if not values:
        raise ValueError("no values")
    ordered = sorted(values)
    rank = max(1, math.ceil(q * len(ordered)))
    return float(ordered[rank - 1])


@dataclass
class RuleEngine:
    rules: Tuple[Rule, ...] = DEFAULT_RULES
    thresholds: Dict[str, Dict[str, float]] = field(default_factory=dict)  # rule_id -> entity_type -> value
    calibration: Dict[str, Any] = field(default_factory=dict)
    ruleset: str = RULESET_VERSION
    threshold_ops: Dict[str, Dict[str, str]] = field(default_factory=dict)  # rule_id -> entity_type -> op
    disabled: Dict[str, str] = field(default_factory=dict)                  # rule_id -> reason (validation gate)
    gate_report: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.ruleset not in RULESETS:
            raise ValueError(f"unknown rule set: {self.ruleset}")

    @property
    def policy(self) -> CalibrationPolicy:
        return RULESETS[self.ruleset]

    def calibrate(self, background_vectors: Iterable[Mapping[str, Any]]) -> "RuleEngine":
        """Learn calibrated thresholds from background windows (never from incident windows)."""
        by_type: Dict[str, List[Mapping[str, float]]] = {}
        for vector in background_vectors:
            by_type.setdefault(vector["entity_type"], []).append(vector["features"])
        policy = self.policy
        thresholds: Dict[str, Dict[str, float]] = {}
        ops: Dict[str, Dict[str, str]] = {}
        for rule in self.rules:
            feature = rule.calibrated_feature
            if feature is None:
                continue
            op = next(c.op for c in rule.conditions if c.value == CALIBRATED)
            thresholds[rule.rule_id], ops[rule.rule_id] = {}, {}
            for etype in rule.entity_types:
                values = [f[feature] for f in by_type.get(etype, [])]
                learned = nearest_rank_quantile(values, policy.quantile or rule.quantile) if values else None
                if not policy.strict:
                    value, used_op = max(rule.floor, learned if learned is not None else rule.floor), op
                elif learned is not None and learned * (1 + policy.margin) >= rule.floor:
                    value, used_op = learned * (1 + policy.margin), ">"   # strictly above all background
                else:
                    value, used_op = rule.floor, ">="                     # floor binds (or no background)
                thresholds[rule.rule_id][etype] = float(value)
                ops[rule.rule_id][etype] = used_op
        self.thresholds, self.threshold_ops = thresholds, ops
        self.disabled, self.gate_report = {}, {}
        self.calibration = {"background_windows_by_type": {k: len(v) for k, v in sorted(by_type.items())}}
        return self

    def gate(self, background_vectors: Iterable[Mapping[str, Any]],
             max_fire_rate: Optional[float] = None) -> "RuleEngine":
        """Validation gate: disable rules that fire on more than ``max_fire_rate`` of these windows.

        Run on held-out background (validation) after ``calibrate()`` and before any test scoring.
        The rate is per rule, over windows of the rule's entity types.
        """
        budget = max_fire_rate if max_fire_rate is not None else self.policy.gate_max_fire_rate
        if budget is None:
            raise ValueError(f"{self.ruleset} has no validation gate; pass max_fire_rate")
        windows = Counter()
        fires = Counter()
        for vector in background_vectors:
            for rule in self.rules:
                if vector["entity_type"] in rule.entity_types:
                    windows[rule.rule_id] += 1
            for alert in self.evaluate(vector, include_disabled=True):
                fires[alert["rule_id"]] += 1
        self.disabled, report = {}, {}
        for rule in self.rules:
            n, k = windows[rule.rule_id], fires[rule.rule_id]
            rate = k / n if n else 0.0
            passed = rate <= budget
            report[rule.rule_id] = {"windows": n, "fires": k, "fire_rate": round(rate, 6), "passed": passed}
            if not passed:
                self.disabled[rule.rule_id] = f"fired on {k}/{n} validation background windows ({rate:.2%} > {budget:.2%})"
        self.gate_report = {"max_fire_rate": budget, "rules": report}
        return self

    def _threshold(self, rule: Rule, condition: Condition, entity_type: str) -> Tuple[float, str]:
        if condition.value != CALIBRATED:
            return float(condition.value), condition.op
        try:
            value = self.thresholds[rule.rule_id][entity_type]
        except KeyError:
            raise RuntimeError(f"{rule.rule_id} needs calibrate() before use") from None
        return value, self.threshold_ops.get(rule.rule_id, {}).get(entity_type, condition.op)

    def evaluate(self, vector: Mapping[str, Any], include_disabled: bool = False) -> List[Dict[str, Any]]:
        """Alert Envelopes for every (enabled) rule that fires on this window."""
        alerts = []
        features = vector["features"]
        for rule in self.rules:
            if vector["entity_type"] not in rule.entity_types:
                continue
            if rule.rule_id in self.disabled and not include_disabled:
                continue
            evidence = []
            fired = True
            for condition in rule.conditions:
                threshold, op = self._threshold(rule, condition, vector["entity_type"])
                value = features[condition.feature]
                if not _OPS[op](value, threshold):
                    fired = False
                    break
                evidence.append({"feature": condition.feature, "value": value, "op": op, "threshold": threshold})
            if not fired:
                continue
            description = rule.title + ": " + ", ".join(
                f"{e['feature']}={e['value']} ({e['op']} {e['threshold']:g})" for e in evidence
            )
            alerts.append(build_alert(
                vector=vector, detector="rules", detector_version=self.ruleset, rule_id=rule.rule_id,
                title=rule.title, description=description, technique=rule.technique,
                technique_id=rule.technique_id, severity=rule.severity, score=1.0, evidence=evidence,
            ))
        return alerts

    def to_dict(self) -> Dict[str, Any]:
        out = {
            "ruleset_version": self.ruleset,
            "feature_set_version": C.FEATURE_SET_VERSION,
            "thresholds": self.thresholds,
            "calibration": self.calibration,
            "rules": [
                {"rule_id": r.rule_id, "title": r.title, "technique": r.technique, "technique_id": r.technique_id,
                 "severity": r.severity, "entity_types": list(r.entity_types), "rationale": r.rationale,
                 "conditions": [{"feature": c.feature, "op": c.op, "value": c.value} for c in r.conditions],
                 "quantile": r.quantile, "floor": r.floor}
                for r in self.rules
            ],
            "policy": dict(vars(self.policy)),
            "threshold_ops": self.threshold_ops,
            "disabled": self.disabled,
            "gate": self.gate_report,
        }
        return out

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RuleEngine":
        if data["ruleset_version"] not in RULESETS:
            raise ValueError(f"unknown rule set: {data['ruleset_version']}")
        if data["feature_set_version"] != C.FEATURE_SET_VERSION:
            raise ValueError("rules were calibrated on a different feature set; recalibrate")
        return cls(thresholds={k: dict(v) for k, v in data["thresholds"].items()},
                   calibration=dict(data.get("calibration", {})),
                   ruleset=data["ruleset_version"],
                   threshold_ops={k: dict(v) for k, v in data.get("threshold_ops", {}).items()},
                   disabled=dict(data.get("disabled", {})),
                   gate_report=dict(data.get("gate", {})))
