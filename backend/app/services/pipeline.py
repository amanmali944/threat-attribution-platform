"""Developer A pipeline (Phase 9): canonical events -> detections -> incidents -> attribution -> platform.

    result = run_pipeline(raw_events, baseline=(start, end), score=(start, end), assets=inventory)
    report = deliver(post, result)          # post(path, json) -> (status_code, body)

``run_pipeline`` chains the detection and attribution layers exactly as they were evaluated:
resolve -> baseline (fitted on the baseline period, history rolled forward) -> fs-1.2.0 features
-> rules-1.2.0 (calibrated on the baseline period's windows) [+ fusion when a trained
``FusionModel`` and Isolation Forest are given] -> rules-first decisions -> Fused Alerts ->
incidents (entity-time graph) -> attribution (graph root) -> risk.

Without a trained fusion model the pipeline runs RULES-ONLY: confidence comes from the highest
rule severity (high 0.95, medium 0.7, low 0.5) and windows without a rule hit are suppressed -
the precise part of the evaluated system, needing no training corpus.

``deliver`` posts to the platform API (contract section 11): events, then Fused Alerts decided
``alert`` / ``review`` (never ``suppress``), then incidents linked to the platform's alert IDs,
then attributions linked to the platform's incident IDs. Each call's status is recorded; a 404
on a whole endpoint is reported as ``endpoint_missing`` instead of failing the run.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from app.services.attribution.correlation import EMPTY_INVENTORY, AssetInventory, correlate
from app.services.attribution.graph import attribute, observed_graph
from app.services.attribution.risk import alert_criticality, incident_risk
from app.services.detection.features import FeatureConfig, compute_features, fit_baseline, update_history
from app.services.detection.fusion import FUSION_VERSION, fuse_alerts, rules_first
from app.services.detection.labeling import to_us
from app.services.detection.resolve import resolve_events
from app.services.detection.rules import RuleEngine

PIPELINE_VERSION = "pipeline-1.0.0"
RULES_ONLY_CONFIDENCE = {"critical": 0.95, "high": 0.95, "medium": 0.7, "low": 0.5}
MAX_EVENT_IDS = 200          # per platform alert; the full count stays in the evidence
Post = Callable[[str, Mapping[str, Any]], Tuple[int, Any]]


def _days(events, start_us: int, end_us: int):
    by_day: Dict[str, List[Any]] = {}
    for e in events:
        if start_us <= e.ts_us < end_us:
            by_day.setdefault(e.observed_at.strftime("%Y-%m-%d"), []).append(e)
    return [by_day[d] for d in sorted(by_day)]


def run_pipeline(raw_events: Iterable[Mapping[str, Any]], baseline: Tuple[str, str], score: Tuple[str, str],
                 assets: AssetInventory = EMPTY_INVENTORY, fusion: Any = None, iforest: Any = None,
                 config: FeatureConfig = FeatureConfig()) -> Dict[str, Any]:
    events, report = resolve_events(raw_events)
    b_start, b_end = (to_us(t) for t in baseline)
    s_start, s_end = (to_us(t) for t in score)
    baseline_events = [e for e in events if b_start <= e.ts_us < b_end]
    model = fit_baseline(baseline_events, config)
    engine = RuleEngine().calibrate(compute_features(baseline_events, model, config))

    windows: List[Dict[str, Any]] = []
    for day in _days(events, s_start, s_end):
        vectors = compute_features(day, model, config)
        update_history(model, day)
        for v in vectors:
            alerts = engine.evaluate(v)
            windows.append(dict(v, rules={a["rule_id"]: a["severity"] for a in alerts}, ruleset=engine.ruleset,
                                iforest_score=None))
    if iforest is not None:
        for w, s in zip(windows, iforest.scores(windows)):
            w["iforest_score"] = s
    if fusion is not None:
        confidence = fusion.confidence(windows)
        decisions = rules_first(windows, fusion.decide(confidence))
    else:
        confidence = [max((RULES_ONLY_CONFIDENCE[s] for s in w["rules"].values()), default=0.0) for w in windows]
        decisions = rules_first(windows, ["suppress"] * len(windows))
    fused = fuse_alerts(windows, confidence, decisions)
    by_id = {e.event_id: e for e in events}
    incidents = correlate(fused, by_id, assets)
    access = observed_graph(events, assets)
    criticality = {a["fused_alert_id"]: alert_criticality(a, by_id, assets) for a in fused}
    attributions, risks = [], []
    computed_at = score[1]
    for inc in incidents:
        members = [a for a in fused if a["fused_alert_id"] in set(inc["fused_alert_ids"])]
        if any(a["decision"] == "alert" for a in members):
            attributions.append(attribute(inc, fused, by_id, assets, access))
        risks.append(incident_risk(inc, fused, criticality, computed_at))
    return {"pipeline_version": PIPELINE_VERSION, "mode": "fusion" if fusion is not None else "rules-only",
            "resolve_report": {"events": len(events), "skipped": len(report["skipped_events"])},
            "windows": len(windows), "fused_alerts": fused, "incidents": incidents,
            "attributions": attributions, "risks": risks}


# --------------------------------------------------------------------------- platform payloads


def alert_payload(fused: Mapping[str, Any]) -> Dict[str, Any]:
    rules = [e["rule_id"] for e in fused.get("evidence", []) if e.get("rule_id")]
    title = (f"{fused['technique'].replace('_', ' ').capitalize()} on {fused['entity_type']}"
             + (f" ({', '.join(rules)})" if rules else ""))
    return {
        "tenant_id": fused["tenant_id"], "rule_id": rules[0] if rules else "ML-FUSION-001", "title": title,
        "description": f"{fused['member_windows']} window(s), {len(fused['event_ids'])} event(s); "
                       f"{fused['suppressed_duplicates']} repeat(s) folded",
        "severity": fused["severity"], "status": "open", "observed_at": fused["window_end"],
        "event_ids": fused["event_ids"][:MAX_EVENT_IDS],
        "detector": "fusion" if fused.get("detectors") != ["rules"] else "rules",
        "detector_version": FUSION_VERSION, "technique": fused["technique"], "technique_id": fused["technique_id"],
        "entity_id": fused["entity_id"], "score": fused["confidence"], "confidence": fused["confidence"],
        "decision": fused["decision"],
        "evidence": list(fused.get("evidence", [])) + [{"fused_alert_id": fused["fused_alert_id"],
                                                         "event_count": len(fused["event_ids"]),
                                                         "member_alert_ids": fused.get("member_alert_ids", [])}],
    }


def incident_payload(incident: Mapping[str, Any], risk: Optional[Mapping[str, Any]],
                     platform_alert_ids: Sequence[str]) -> Dict[str, Any]:
    return {
        "tenant_id": incident["tenant_id"], "title": incident["title"], "description": incident["description"],
        "severity": incident["severity"], "status": incident["status"], "alert_ids": list(platform_alert_ids),
        "risk_score": risk["score"] if risk else None, "risk_level": risk["level"] if risk else None,
        "layers": incident["layers"], "first_seen": incident["first_seen"], "last_seen": incident["last_seen"],
    }


def attribution_payload(attribution: Mapping[str, Any], platform_incident_id: str) -> Dict[str, Any]:
    return {
        "tenant_id": attribution["tenant_id"], "incident_id": platform_incident_id,
        "attribution_id": attribution["attribution_id"], "confidence_score": attribution["confidence"],
        "confidence": attribution["confidence"], "tactics_techniques": attribution["techniques"],
        "entry_point": attribution["entry_point"], "attack_path": attribution["attack_path"],
        "reached_assets": attribution["reached_assets"], "blast_radius": attribution["blast_radius"],
        "dwell_time_seconds": attribution["dwell_time_seconds"], "explanation": attribution["explanation"],
        "graph": attribution["graph"], "method": attribution["method"], "schema_version": attribution["schema_version"],
    }


def deliver(post: Post, result: Mapping[str, Any], raw_events: Optional[Sequence[Mapping[str, Any]]] = None,
            prefix: str = "/api/v1") -> Dict[str, Any]:
    """Post everything to the platform; returns per-endpoint status counts and the ID mappings."""
    report: Dict[str, Any] = {"events": {}, "alerts": {}, "incidents": {}, "attributions": {}, "endpoint_missing": []}

    def send(kind: str, path: str, payload: Mapping[str, Any]):
        status, body = post(prefix + path, payload)
        report[kind][str(status)] = report[kind].get(str(status), 0) + 1
        if status == 404 and kind not in report["endpoint_missing"] and not (isinstance(body, dict) and body.get("id")):
            report["endpoint_missing"].append(kind)
        return status, body

    wanted = {e for a in result["fused_alerts"] if a["decision"] != "suppress" for e in a["event_ids"][:MAX_EVENT_IDS]}
    for raw in raw_events or []:
        if raw.get("event_id") in wanted:
            send("events", "/events", raw)

    alert_ids: Dict[str, str] = {}
    for fused in result["fused_alerts"]:
        if fused["decision"] == "suppress":
            continue
        status, body = send("alerts", "/alerts", alert_payload(fused))
        if status == 201:
            alert_ids[fused["fused_alert_id"]] = body["id"]
    risk_of = {r["subject_id"]: r for r in result["risks"]}
    incident_ids: Dict[str, str] = {}
    for inc in result["incidents"]:
        platform_alerts = [alert_ids[f] for f in inc["fused_alert_ids"] if f in alert_ids]
        if not platform_alerts:
            continue
        status, body = send("incidents", "/incidents", incident_payload(inc, risk_of.get(inc["incident_id"]), platform_alerts))
        if status == 201:
            incident_ids[inc["incident_id"]] = body["id"]
    for att in result["attributions"]:
        if att["incident_id"] in incident_ids:
            send("attributions", "/attributions", attribution_payload(att, incident_ids[att["incident_id"]]))
    report["alert_ids"], report["incident_ids"] = alert_ids, incident_ids
    return report
