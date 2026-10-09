# Detection & Intelligence Contract v1.0

**Owner:** Developer A (Detection & Intelligence)  
**Consumer:** Developer B (Platform & Presentation)  
**Status:** DRAFT — pending Developer B acknowledgement  
**Last Updated:** October 09, 2026

## Purpose

This document freezes every data shape produced by the detection and attribution pipeline. It is the only interface between Developer A's analytical modules (`backend/app/services/detection/`, `backend/app/services/attribution/`) and Developer B's platform (database, API, dashboard). The platform must be able to integrate these outputs using this contract and the fixtures alone, without reading the internal implementation.

The pipeline exists to serve one product sentence:

> Ingest security telemetry from every layer, decide which activity is hostile, and return a single causal account of each incident: where it entered, what path it took, what it reached, and how confident the system is in that account.

## Contract Chain

```
Canonical Event (EVENT_SCHEMA.md v1.0)
        |
        v
Enriched Event ........ resolved actor / target entities          (§2)
        |
        v
Feature Vector ........ per-entity, per-window features           (§3)
        |
        v
Alert Envelope ........ one per detector hit                      (§4)
        |
        v
Fused Alert ........... calibrated confidence + decision          (§5)
        |
        v
Incident Object ....... one per attack scenario                   (§6)
        |
        v
Attribution Result .... entry point, path, reach, confidence      (§7)
        |
        v
Risk Score ............ time-decayed, explainable                 (§8)
        |
        v
Evaluation Results .... reproducible metrics artifact             (§9)
```

All objects carry `schema_version` and `tenant_id`. All timestamps are ISO 8601 UTC. All scores and confidences are floats in `[0.0, 1.0]` unless stated otherwise.

---

## 1. Input Contract — Canonical Event

The pipeline consumes the Canonical Telemetry Event v1.0 defined in `docs/EVENT_SCHEMA.md` without modification. Fields used by detection: `event_id`, `tenant_id`, `source_layer`, `event_type`, `observed_at`, `entities`, `payload`.

### 1.1 Layer mapping

The product brief names four layers (identity, application, host, database). The current schema names `endpoint`, `network`, `cloud`, `identity`. Mapping:

| Brief Layer | `source_layer` value | Status |
| :--- | :--- | :--- |
| Identity | `identity` | Exists |
| Host | `endpoint` | Exists (no rename) |
| Application | `application` | **Requested — CR-01** |
| Database | `database` | **Requested — CR-01** |
| Network (supporting) | `network` | Exists |
| Cloud (supporting) | `cloud` | Exists |

### 1.2 Detection profile — required `payload` keys per `event_type`

`payload` is free-form JSONB in the database. Detection only relies on the keys below; events missing a required key are skipped by the feature engine and counted in `skipped_events`.

| `source_layer` | `event_type` | Required `payload` keys | Optional keys |
| :--- | :--- | :--- | :--- |
| `identity` | `user_login` | `result` (`SUCCESS` \| `FAILURE`), `source_ip` | `authentication_package`, `logon_type`, `country`, `device_id` |
| `identity` | `mfa_challenge` | `result` (`SUCCESS` \| `FAILURE`) | `method` |
| `identity` | `privilege_change` | `role_before`, `role_after` | `changed_by` |
| `identity` | `token_issued` | `token_type` | `scope`, `lifetime_seconds` |
| `application` | `http_request` | `method`, `path`, `status_code` | `bytes_out`, `session_id`, `user_agent`, `source_ip` |
| `database` | `db_query` | `operation` (`SELECT` \| `INSERT` \| `UPDATE` \| `DELETE` \| `DDL` \| `GRANT`), `object` | `rows_returned`, `bytes_out`, `privileged` (bool) |
| `endpoint` | `process_execution` | `process_name`, `command_line` | `parent_process`, `pid` |
| `endpoint` | `remote_session` | `protocol` (`rdp` \| `ssh` \| `smb` \| `winrm`), `result`, `source_host` | — |
| `network` | `network_connection` | `dst_ip`, `dst_port` | `bytes_out`, `protocol` |
| `network` | `dns_query` | `query_name` | `query_type`, `resolved_ip` |
| `cloud` | `cloud_api_call` | `event_name`, `service` | `user_agent`, `source_ip` |

### 1.3 Entity types

`user`, `host`, `ip`, `process`, `file`, `domain`, `cloud_identity` (already used in fixtures), plus `application`, `database`, `device` (**Requested — CR-02**).

---

## 2. Enriched Event (internal)

Produced by entity resolution (`detection/resolve.py`). Internal to Developer A, documented so fixtures are readable.

### 2.1 Entity ID scheme

Every entity is identified deterministically, matching the scheme already used by `backend/app/db/seed.py`:

```
entity_id = "ent-{entity_type}-{sha256(f'{tenant_id}:{identifier}').hexdigest()[:8]}"
```

All platform code paths must use this one scheme (**CR-06**).

### 2.2 Role derivation

| Role | Rule (first match wins) |
| :--- | :--- |
| `actor_user` | entity of type `user`, else `cloud_identity` |
| `actor_ip` | `payload.source_ip`, else entity of type `ip` |
| `actor_device` | `payload.device_id` / `payload.source_host`, else entity of type `device` |
| `target` | `database` layer → `database` entity; `application` layer → `application` entity; `endpoint` layer → `host` entity; `identity` layer → `application` or `host` entity; `cloud` layer → `payload.service` |
| `target_criticality` | `entities.properties.criticality` (1–5), default `1` |

```json
{
  "schema_version": "1.0",
  "event_id": "evt-1003",
  "tenant_id": "tenant-default-001",
  "source_layer": "identity",
  "event_type": "user_login",
  "observed_at": "2026-10-05T10:18:45Z",
  "actor_user": "ent-user-3f9a1c22",
  "actor_ip": "ent-ip-91b0d4e7",
  "actor_device": null,
  "target": "ent-host-0c7e55a1",
  "target_criticality": 5,
  "outcome": "success"
}
```

---

## 3. Feature Vector

Produced by `detection/features.py`. One vector per `(tenant_id, entity_id, window)`. The same function is used for training, evaluation and live inference; there is no second feature implementation.

```json
{
  "schema_version": "1.0",
  "feature_set_version": "fs-1.0.0",
  "tenant_id": "tenant-default-001",
  "entity_id": "ent-user-3f9a1c22",
  "entity_type": "user",
  "window_start": "2026-10-05T10:15:00Z",
  "window_end": "2026-10-05T10:20:00Z",
  "window_seconds": 300,
  "event_ids": ["evt-1001", "evt-1003"],
  "features": {
    "volume.event_count": 42,
    "failure.login_failure_rate": 0.94,
    "diversity.distinct_targets": 1,
    "novelty.new_source_ip": 1
  }
}
```

### 3.1 Feature catalogue (fs-1.0.0)

| Feature | Family | Definition |
| :--- | :--- | :--- |
| `volume.event_count` | Volume | Events by entity in window |
| `volume.bytes_out` | Volume | Sum of `payload.bytes_out` |
| `volume.rows_read` | Volume | Sum of `payload.rows_returned` for `SELECT` |
| `volume.distinct_sessions` | Volume | Distinct `payload.session_id` |
| `failure.login_failure_rate` | Failure | Failed / total `user_login` |
| `failure.max_consecutive_failures` | Failure | Longest run of failed logins |
| `failure.http_error_rate` | Failure | `status_code >= 400` / total `http_request` |
| `diversity.distinct_targets` | Diversity | Distinct `target` entities |
| `diversity.distinct_accounts_from_ip` | Diversity | Distinct users seen from same `actor_ip` (spray) |
| `diversity.endpoint_entropy` | Diversity | Shannon entropy of `payload.path` / `payload.object` |
| `timing.mean_interarrival_s` | Timing | Mean seconds between events |
| `timing.interarrival_cv` | Timing | Coefficient of variation (low = automation / beaconing) |
| `timing.off_hours` | Timing | 1 if window outside entity's usual hours, else 0 |
| `novelty.new_source_ip` | Novelty | 1 if `actor_ip` never seen for entity before |
| `novelty.new_device` | Novelty | 1 if `actor_device` never seen before |
| `novelty.new_country` | Novelty | 1 if `payload.country` never seen before |
| `novelty.new_target` | Novelty | Count of first-time targets |
| `privilege.privileged_ops` | Privilege | `privileged=true` queries, `GRANT`/`DDL`, admin processes |
| `privilege.role_changes` | Privilege | `privilege_change` events |
| `privilege.tokens_issued` | Privilege | `token_issued` events |
| `peer.volume_zscore` | Peer-relative | z-score of `volume.event_count` vs entity's role cohort |
| `peer.targets_zscore` | Peer-relative | z-score of `diversity.distinct_targets` vs cohort |

Adding or renaming a feature bumps `feature_set_version`. Window length is configurable (`window_seconds`, default 300).

---

## 4. Alert Envelope

Emitted by every detector (`detection/rules.py`, `detection/anomaly.py`, `detection/sequence.py`). Same shape regardless of detector.

```json
{
  "schema_version": "1.0",
  "alert_id": "alt-rules-7c1e9a03",
  "tenant_id": "tenant-default-001",
  "detector": "rules",
  "detector_version": "rules-1.0.0",
  "rule_id": "RULE-IDP-001",
  "title": "Brute-force login burst",
  "description": "42 failed logins for corp\\jdoe in 300s from 185.220.101.4",
  "technique": "credential_access",
  "technique_id": "T1110",
  "severity": "high",
  "entity_id": "ent-user-3f9a1c22",
  "event_ids": ["evt-2001", "evt-2002"],
  "observed_at": "2026-10-05T10:19:58Z",
  "window_start": "2026-10-05T10:15:00Z",
  "window_end": "2026-10-05T10:20:00Z",
  "score": 0.91,
  "confidence": null,
  "evidence": [
    {"feature": "failure.login_failure_rate", "value": 0.94, "baseline": 0.03},
    {"feature": "failure.max_consecutive_failures", "value": 38, "baseline": 2}
  ]
}
```

| Field | Type | Description |
| :--- | :--- | :--- |
| `detector` | Enum | `rules` \| `isolation_forest` \| `sequence` |
| `detector_version` | String | Rule-set or model version that produced the alert |
| `rule_id` | String \| null | Rule identifier (rules detector); `ML-IFOREST-001` / `ML-SEQ-001` for ML detectors so the existing `alerts.rule_id NOT NULL` column stays valid |
| `technique` | Enum | MITRE ATT&CK tactic slug: `initial_access`, `credential_access`, `privilege_escalation`, `lateral_movement`, `collection`, `exfiltration`, `persistence`, `execution`, `discovery` |
| `technique_id` | String \| null | MITRE ATT&CK technique ID |
| `score` | Float | Detector-native score normalised to `[0,1]` (higher = more anomalous) |
| `confidence` | Float \| null | Always `null` at this stage; set by fusion (§5) |
| `evidence` | Array | Features that drove the decision, with entity baseline where available |

---

## 5. Fused Alert

Produced by `detection/fusion.py`. Groups detector alerts for the same entity and overlapping window, removes duplicates, and assigns one calibrated confidence and one decision.

```json
{
  "schema_version": "1.0",
  "fused_alert_id": "fal-5b2d0e71",
  "tenant_id": "tenant-default-001",
  "entity_id": "ent-user-3f9a1c22",
  "window_start": "2026-10-05T10:15:00Z",
  "window_end": "2026-10-05T10:20:00Z",
  "member_alert_ids": ["alt-rules-7c1e9a03", "alt-iforest-1a90c4b2"],
  "detectors": ["rules", "isolation_forest"],
  "technique": "credential_access",
  "technique_id": "T1110",
  "severity": "high",
  "confidence": 0.87,
  "decision": "alert",
  "suppressed_duplicates": 3,
  "calibration_version": "cal-1.0.0",
  "event_ids": ["evt-2001", "evt-2002"],
  "evidence": [
    {"feature": "failure.login_failure_rate", "value": 0.94, "baseline": 0.03, "detector": "rules"}
  ]
}
```

| Field | Description |
| :--- | :--- |
| `confidence` | Calibrated probability that the activity is hostile |
| `decision` | `alert` (confidence ≥ τ_alert), `review` (τ_review ≤ confidence < τ_alert — abstain, send to analyst), `suppress` (confidence < τ_review) |
| `suppressed_duplicates` | Repeat hits on the same entity/technique inside the suppression window that were folded into this alert |
| `calibration_version` | Calibrator + thresholds used; τ values are recorded in the calibration artifact, not hard-coded |

Only `alert` and `review` decisions are sent to the platform.

---

## 6. Incident Object

Produced by `attribution/correlation.py`. Target: one incident per attack scenario.

```json
{
  "schema_version": "1.0",
  "incident_id": "inc-a41f7d20",
  "tenant_id": "tenant-default-001",
  "title": "Account takeover leading to bulk database read",
  "description": "Brute-force on corp\\jdoe, successful login from new IP, privileged SELECT on customers table",
  "severity": "critical",
  "status": "open",
  "fused_alert_ids": ["fal-5b2d0e71", "fal-9e03c1aa", "fal-c7d2b810"],
  "alert_ids": ["alt-rules-7c1e9a03", "alt-iforest-1a90c4b2", "alt-seq-44e1f0d9"],
  "entity_ids": ["ent-user-3f9a1c22", "ent-ip-91b0d4e7", "ent-application-2d4b6e11", "ent-database-8a1f3c07"],
  "layers": ["identity", "application", "database"],
  "stages": [
    {"technique": "credential_access", "first_seen": "2026-10-05T10:15:02Z"},
    {"technique": "initial_access", "first_seen": "2026-10-05T10:20:11Z"},
    {"technique": "collection", "first_seen": "2026-10-05T10:24:40Z"}
  ],
  "first_seen": "2026-10-05T10:15:02Z",
  "last_seen": "2026-10-05T10:26:13Z",
  "correlation": {
    "method": "entity-time-graph-1.0.0",
    "link_reasons": ["shared_entity:ent-user-3f9a1c22", "shared_entity:ent-ip-91b0d4e7", "stage_order"]
  }
}
```

**Mapping to existing `POST /api/v1/incidents`:** `title`, `description`, `severity`, `status`, `alert_ids` map directly. The remaining fields require **CR-04**.

---

## 7. Attribution Result

Produced by `attribution/graph.py`. The causal account of one incident — the centre of the product.

```json
{
  "schema_version": "1.0",
  "attribution_id": "att-a41f7d20",
  "tenant_id": "tenant-default-001",
  "incident_id": "inc-a41f7d20",
  "method": "graph-attribution-1.0.0",
  "entry_point": {
    "entity_id": "ent-user-3f9a1c22",
    "entity_type": "user",
    "identifier": "corp\\jdoe",
    "first_anomalous_event_id": "evt-2001",
    "observed_at": "2026-10-05T10:15:02Z",
    "confidence": 0.82
  },
  "attack_path": [
    {
      "step": 1,
      "source_entity_id": "ent-ip-91b0d4e7",
      "target_entity_id": "ent-user-3f9a1c22",
      "action": "user_login",
      "layer": "identity",
      "event_id": "evt-2044",
      "observed_at": "2026-10-05T10:20:11Z",
      "anomaly_score": 0.88
    },
    {
      "step": 2,
      "source_entity_id": "ent-user-3f9a1c22",
      "target_entity_id": "ent-database-8a1f3c07",
      "action": "db_query",
      "layer": "database",
      "event_id": "evt-2091",
      "observed_at": "2026-10-05T10:24:40Z",
      "anomaly_score": 0.93
    }
  ],
  "reached_assets": [
    {
      "entity_id": "ent-database-8a1f3c07",
      "entity_type": "database",
      "identifier": "prod-customers-db",
      "criticality": 5,
      "first_reached_at": "2026-10-05T10:24:40Z"
    }
  ],
  "blast_radius": {
    "reached_count": 3,
    "potential_reach_count": 7,
    "critical_assets_reached": 1
  },
  "dwell_time_seconds": 671,
  "confidence": 0.78,
  "techniques": [
    {"tactic": "Credential Access", "technique_id": "T1110", "technique_name": "Brute Force"},
    {"tactic": "Collection", "technique_id": "T1213", "technique_name": "Data from Information Repositories"}
  ],
  "graph": {
    "nodes": [
      {"id": "ent-user-3f9a1c22", "label": "corp\\jdoe", "type": "user", "properties": {"is_entry_point": true}}
    ],
    "edges": [
      {"source": "ent-user-3f9a1c22", "target": "ent-database-8a1f3c07", "relation": "DB_QUERY", "weight": 0.93}
    ]
  },
  "explanation": "Entry via brute-forced account corp\\jdoe from new IP 185.220.101.4; reached prod-customers-db 11m11s later with a privileged bulk SELECT."
}
```

| Field | Definition |
| :--- | :--- |
| `entry_point` | Earliest anomalous root node of the incident graph (no anomalous in-edge preceding it) |
| `attack_path` | Ordered, time-respecting edges from entry point to each reached asset; each edge cites the event that proves it |
| `reached_assets` | Assets the attacker actually touched after entry |
| `blast_radius.reached_count` | Distinct entities touched after entry |
| `blast_radius.potential_reach_count` | Entities forward-reachable from reached nodes in the tenant's observed access graph (what they could reach next) |
| `dwell_time_seconds` | `last_seen − entry_point.observed_at` |
| `confidence` | Confidence in the whole causal account; v1 method = `min(entry_point.confidence, mean(attack_path[].anomaly_score))`, recorded in `method` |
| `techniques` | Same shape as existing `attributions.tactics_techniques` |
| `graph` | Same node/edge shape as existing `backend/app/schemas/graph.py` (`GraphNode`, `GraphEdge`) |

Attribution in this contract means **causal reconstruction** (entry, path, reach). Naming a threat actor (`actor_name`, `campaign`) is out of scope for v1; see **CR-05**.

---

## 8. Risk Score

Produced by `attribution/risk.py`, per entity and per incident.

```json
{
  "schema_version": "1.0",
  "tenant_id": "tenant-default-001",
  "subject_type": "incident",
  "subject_id": "inc-a41f7d20",
  "score": 91.4,
  "level": "critical",
  "computed_at": "2026-10-05T10:30:00Z",
  "half_life_seconds": 86400,
  "contributors": [
    {
      "source_id": "fal-c7d2b810",
      "kind": "fused_alert",
      "reason": "Privileged bulk SELECT on criticality-5 asset",
      "confidence": 0.93,
      "weight": 1.0,
      "age_seconds": 320,
      "decayed_contribution": 0.927
    }
  ]
}
```

- Formula: `score = 100 × (1 − Π(1 − confidence_i × weight_i × 2^(−age_i / half_life)))`, where `weight_i` scales with target criticality.
- `level`: `low` < 25 ≤ `medium` < 50 ≤ `high` < 75 ≤ `critical`.
- `contributors` is never empty for a non-zero score — the UI must be able to explain *why*.

---

## 9. Evaluation Results Artifact

Produced by `scripts/evaluate.py` into `data/evaluation/evaluation_results.json`. Key names reuse the existing `GET /api/v1/evaluation/summary` response where possible so the endpoint can read this file instead of hard-coded values (**CR-03**).

```json
{
  "schema_version": "1.0",
  "model_version": "pipeline-1.0.0",
  "corpus_seed": 42,
  "evaluation_timestamp": "2026-10-20T12:00:00Z",
  "overall_precision": 0.0,
  "overall_recall": 0.0,
  "overall_f1": 0.0,
  "per_class_metrics": {
    "bruteforce": {"precision": 0.0, "recall": 0.0, "f1": 0.0, "support": 0}
  },
  "per_detector_metrics": {
    "rules": {"precision": 0.0, "recall": 0.0, "f1": 0.0, "support": 0}
  },
  "calibration": {
    "brier_score": 0.0,
    "expected_calibration_error": 0.0,
    "max_calibration_error": 0.0,
    "auc_roc": 0.0,
    "reliability_bins": [{"bin_lower": 0.0, "bin_upper": 0.1, "mean_confidence": 0.0, "observed_rate": 0.0, "count": 0}]
  },
  "abstention_rate": 0.0,
  "alerts_per_analyst_day": {"raw_detector_alerts": 0.0, "after_fusion": 0.0, "incidents": 0.0},
  "incident_consolidation_ratio": 0.0,
  "attribution": {
    "entry_point_accuracy": 0.0,
    "path_precision": 0.0,
    "path_recall": 0.0,
    "reached_assets_jaccard": 0.0
  },
  "detection_latency_seconds": {"median": 0.0, "p95": 0.0}
}
```

Accuracy is deliberately not reported (class imbalance makes it misleading). All numbers must be reproducible from one command and a fixed `corpus_seed`.

---

## 10. Corpus & Ground Truth Format

```
data/
  corpus/
    assets.json                       # asset inventory with criticality
    scenario_01_bruteforce/
      events.json                     # canonical events (normal + attack)
      ground_truth.json
    scenario_02_account_takeover/
    scenario_03_lateral_movement/
    scenario_04_exfiltration/
  fixtures/
    canonical_events.json
    expected_features.json
    expected_alerts.json
    expected_incidents.json
    expected_attribution.json
    ground_truth.json
```

`ground_truth.json`:

```json
{
  "scenario_id": "scenario_02_account_takeover",
  "seed": 42,
  "attack_class": "account_takeover",
  "malicious_event_ids": ["evt-2001", "evt-2044", "evt-2091"],
  "expected_incident_count": 1,
  "entry_point_entity_id": "ent-user-3f9a1c22",
  "attack_path_entity_ids": ["ent-ip-91b0d4e7", "ent-user-3f9a1c22", "ent-application-2d4b6e11", "ent-database-8a1f3c07"],
  "reached_asset_entity_ids": ["ent-application-2d4b6e11", "ent-database-8a1f3c07"],
  "techniques": ["credential_access", "initial_access", "collection"]
}
```

---

## 11. Delivery to the Platform

The pipeline runner (`backend/app/services/pipeline.py`) writes outputs through the existing API, never by direct SQL:

| Output | Endpoint | Notes |
| :--- | :--- | :--- |
| Fused alerts (`alert`, `review`) | `POST /api/v1/alerts` | One row per member detector alert; `event_ids` links evidence |
| Incidents | `POST /api/v1/incidents` | `alert_ids` links member alerts |
| Attribution Result | `POST /api/v1/attributions` | Endpoint does not exist yet — **CR-04** |
| Risk Scores | Incident / entity fields | **CR-04** |
| Evaluation results | File artifact | Read by `GET /api/v1/evaluation/summary` — **CR-03** |

---

## 12. Change Requests to Developer B

Raised October 09, 2026. Detection code is built against this contract and fixtures in the meantime; integration (Phase 9) depends on these.

| ID | Request | Affects | Status |
| :--- | :--- | :--- | :--- |
| **CR-01** | Add `application` and `database` to allowed `source_layer` values in `EVENT_SCHEMA.md` and model comments | Event schema | Requested |
| **CR-02** | Document entity types `domain`, `cloud_identity` (already in fixtures) and add `application`, `database`, `device` | Event schema, `entities` | Requested |
| **CR-03** | Alerts: add `detector`, `detector_version`, `technique`, `technique_id`, `entity_id`, `score`, `confidence`, `decision`, `evidence (JSONB)`. Evaluation endpoint reads `evaluation_results.json` instead of hard-coded values; remove hard-coded confidence / blast-radius figures from `DashboardPage.tsx` and non-existent engines from `HealthPage.tsx` | Alerts table + schema, `evaluation.py`, frontend | Requested |
| **CR-04** | Incidents: add `risk_score`, `risk_level`, `layers`, `first_seen`, `last_seen`. Attributions: add `entry_point`, `attack_path`, `reached_assets`, `blast_radius`, `dwell_time_seconds`, `explanation` (JSONB where structured) and a `POST /api/v1/attributions` endpoint; graph endpoint returns the stored `graph` instead of recomputing `patient_zero` / `blast_radius` in `incidents.py` | Incidents, attributions, API | Requested |
| **CR-05** | Make `attributions.actor_name` nullable (threat-actor naming is out of scope for v1) | Attributions table | Requested |
| **CR-06** | Use the single deterministic entity ID scheme (§2.1) everywhere. `entities.py` currently uses Python `hash()`, which changes between process restarts | `entities.py`, `incidents.py`, `models/entity.py` | Requested |
| **CR-07** | Persist each event's `entities` list (event↔entity link table or JSONB column) and `metadata`. `POST /events` currently drops both, so actor/target relationships are lost once stored | `events` table, `events.py` | Requested |

---

## 13. Versioning & Change Control

- Every object carries `schema_version`. Field additions bump the minor version; renames or removals bump the major version and require Developer B sign-off before merge.
- Component versions (`feature_set_version`, `detector_version`, `calibration_version`, `method`) are recorded on every output so any number in the dashboard can be traced to the code that produced it.
- Any change to this file is announced to Developer B and noted in `CURRENT_STATUS.md`.
