# Detection & Intelligence Build Plan — Developer A

**Owner:** Developer A (Detection & Intelligence)  
**Branch:** `predictions`  
**Contract:** `docs/DETECTION_CONTRACT.md`  
**Last Updated:** October 09, 2026

## 1. Goal

Build the analytical brain of the platform so that it answers the product sentence:

> Ingest security telemetry from every layer, decide which activity is hostile, and return a single causal account of each incident: where it entered, what path it took, what it reached, and how confident the system is in that account.

Each phase below maps to one part of that sentence:

| Product sentence | Phases |
| :--- | :--- |
| "from every layer" | 1 (cross-layer corpus), 2 (entity resolution) |
| "decide which activity is hostile" | 2 (features), 3 (detectors), 4 (fusion & calibration) |
| "a single … account of each incident" | 5 (correlation) |
| "where it entered, what path it took, what it reached" | 6 (attribution) |
| "how confident the system is" | 4 (calibration), 6 (account confidence), 7 (risk) |

And to the three failures in the problem statement:

| Failure | Addressed by |
| :--- | :--- |
| Visibility fragmentation | Phase 2 — cross-layer entity resolution |
| Alert fatigue | Phase 4 — fusion, deduplication, suppression, abstention; Phase 5 — consolidation |
| Absent attribution | Phase 6 — entry point, path, reach, dwell time |

**Target buyer for v1:** mid-market SOC (2–5 analysts). Optimise for fewer, consolidated, prioritised, explainable alerts — measured as alerts per analyst per day.

---

## 2. Current Starting Point (October 09, 2026)

- `backend/app/services/` is empty. No detection, correlation, attribution or risk logic exists.
- `incidents.py` computes a placeholder `patient_zero` (earliest `first_seen`) and `blast_radius` (entity count).
- `evaluation.py` returns hard-coded metrics; `DashboardPage.tsx` shows hard-coded confidence and blast radius.
- Fixtures contain 4 events, 3 alerts, 2 incidents — no application or database layer events, no ground truth.
- Contract change requests CR-01 … CR-07 sent to Developer B (see `DETECTION_CONTRACT.md` §12).

---

## 3. Module Layout

```
backend/app/services/
  detection/
    __init__.py
    resolve.py          # Phase 2 — entity resolution → Enriched Event
    features.py         # Phase 2 — Feature Vector
    rules.py            # Phase 3 — rules engine
    anomaly.py          # Phase 3 — Isolation Forest
    sequence.py         # Phase 3 — sequence detector
    envelope.py         # Phase 4 — Alert Envelope builder / validation
    fusion.py           # Phase 4 — fusion, calibration, abstention, suppression
  attribution/
    __init__.py
    correlation.py      # Phase 5 — Incident Object
    graph.py            # Phase 6 — Attribution Result
    risk.py             # Phase 7 — Risk Score
  pipeline.py           # Phase 9 — end-to-end runner + platform delivery
scripts/
  generate_corpus.py    # Phase 1
  evaluate.py           # Phase 8
data/
  corpus/               # Phase 1 — scenarios + ground truth
  evaluation/           # Phase 8 — evaluation_results.json, calibration artifact
backend/tests/detection/  # tests for every phase
```

Directory names follow `docs/ARCHITECTURE.md` (`services/detection/`, `services/attribution/`).

---

## 4. Phases

### Phase 0 — Setup & Contract Freeze

| Item | Detail |
| :--- | :--- |
| **Tasks** | Create branch `predictions`; write `DETECTION_CONTRACT.md` and this plan; commit playbook PDF; raise CR-01 … CR-07 with Developer B; request approval for `numpy`, `scikit-learn`, `networkx` |
| **Outputs** | `docs/DETECTION_CONTRACT.md`, `docs/DETECTION_PLAN.md` |
| **Depends on** | Nothing |
| **Done when** | Developer B acknowledges the contract; dependencies approved |

### Phase 1 — Attack Corpus & Ground Truth

| Item | Detail |
| :--- | :--- |
| **Tasks** | Seeded generator producing normal background activity across identity, application, endpoint (host) and database layers for a small organisation (users, roles, apps, hosts, databases with criticality); inject four attack scenarios; vary timing, volume and ordering per seed; write `ground_truth.json` per scenario |
| **Scenarios** | `scenario_01_bruteforce` (identity → application) · `scenario_02_account_takeover` (identity → application → database) · `scenario_03_lateral_movement` (identity → host → host) · `scenario_04_exfiltration` (application → database, bulk read) |
| **Outputs** | `scripts/generate_corpus.py`, `data/corpus/**`, `data/corpus/assets.json` |
| **Acceptance tests** | Same seed ⇒ byte-identical output · every event validates against `EventCreate` · every ground-truth event ID exists in its scenario |
| **Depends on** | Contract §1, §10 |

### Phase 2 — Entity Resolution & Feature Engine

| Item | Detail |
| :--- | :--- |
| **Tasks** | Deterministic entity IDs (contract §2.1); role derivation (actor user / IP / device, target, criticality); sliding windows per entity; compute feature catalogue `fs-1.0.0`; maintain per-entity history for novelty and peer-cohort baselines |
| **Outputs** | `detection/resolve.py`, `detection/features.py`, `data/fixtures/expected_features.json` |
| **Acceptance tests** | Same input replay ⇒ identical features · window length configurable · events missing required payload keys are skipped and counted, not crashed on · hand-checked expected values for selected events |
| **Depends on** | Phase 1 |

### Phase 3 — Detectors

| Step | Detail |
| :--- | :--- |
| **3a Rules** | Versioned rule set (`rules-1.0.0`): brute force, password spray, login from new IP/country after failures, privilege change outside change window, privileged/bulk DB read, remote session fan-out, off-hours admin activity. Highest precision, built first |
| **3b Isolation Forest** | Train on normal-only windows, score all windows; separate `fit` / `score`; persisted model with version; score normalised to `[0,1]` |
| **3c Sequence** | Markov / n-gram model of per-entity action sequences; flags low-probability transitions (e.g. login → privilege change → bulk SELECT). Kept only if it detects cases rules + Isolation Forest miss |
| **Outputs** | `detection/rules.py`, `detection/anomaly.py`, `detection/sequence.py` — all emitting the Alert Envelope |
| **Acceptance tests** | Every rule has one passing and one failing test case · deterministic preprocessing · per-detector precision / recall by attack class · documented comparison: rules vs Isolation Forest vs sequence |
| **Depends on** | Phase 2 |

### Phase 4 — Alert Envelope, Fusion, Calibration, Alert-Fatigue Controls

| Item | Detail |
| :--- | :--- |
| **Tasks** | Envelope builder + validation; group alerts per entity / overlapping window; combine detector scores; calibrate on a held-out split (Platt or isotonic); thresholds τ_alert / τ_review chosen on validation data; decisions `alert` / `review` / `suppress`; deduplicate repeats within a suppression window |
| **Outputs** | `detection/envelope.py`, `detection/fusion.py`, `data/evaluation/calibration.json`, reliability diagram |
| **Acceptance tests** | Fusion produces a reliability / calibration artefact (ECE, Brier) · uncertain cases are routed to `review` instead of forced · alerts per analyst per day reported before vs after fusion |
| **Depends on** | Phase 3 |

### Phase 5 — Correlation into Incidents

| Item | Detail |
| :--- | :--- |
| **Tasks** | Link fused alerts sharing resolved entities within a time horizon, respecting attack-stage order; merge into one Incident Object; derive title, severity, layers, stages |
| **Outputs** | `attribution/correlation.py`, `data/fixtures/expected_incidents.json` |
| **Acceptance tests** | Each known attack scenario becomes exactly one consolidated incident · unrelated benign noise does not merge into it · consolidation ratio reported |
| **Depends on** | Phase 4 |

### Phase 6 — Attribution (centre of the product)

| Item | Detail |
| :--- | :--- |
| **Tasks** | Per-incident directed graph in NetworkX (nodes = resolved entities, edges = observed actions with timestamps and anomaly scores); entry point = earliest anomalous root; time-respecting attack path to each reached asset; forward reachability for blast radius; dwell time; account confidence; plain-language explanation; graph serialised in the platform's `GraphNode` / `GraphEdge` shape |
| **Outputs** | `attribution/graph.py`, `data/fixtures/expected_attribution.json` |
| **Acceptance tests** | Entry point matches ground truth for all four scenarios · path and reached assets checked against ground truth · every path edge cites a real event ID |
| **Depends on** | Phase 5 |
| **Not doing** | Neo4j, graph neural networks, threat-actor naming |

### Phase 7 — Explainable Risk Scoring

| Item | Detail |
| :--- | :--- |
| **Tasks** | Time-decayed score per entity and per incident (contract §8); criticality-weighted; contributors list retained |
| **Outputs** | `attribution/risk.py` |
| **Acceptance tests** | Every non-zero score has at least one contributor · score decays with age (half-life test) · higher-criticality targets rank higher for equal confidence |
| **Depends on** | Phase 6 |

### Phase 8 — Evaluation Harness

| Item | Detail |
| :--- | :--- |
| **Tasks** | One command runs corpus → features → detectors → fusion → incidents → attribution → risk and writes `evaluation_results.json` (contract §9) |
| **Metrics** | Precision / recall / F1 per attack class and per detector · calibration (ECE, Brier, reliability bins) · abstention rate · alerts per analyst per day · incident consolidation ratio · entry-point accuracy, path precision / recall, reached-asset Jaccard · detection latency. **No accuracy headline.** |
| **Outputs** | `scripts/evaluate.py`, `data/evaluation/evaluation_results.json` |
| **Acceptance tests** | Same seed ⇒ same numbers · evaluated on a seed not used for training / calibration |
| **Depends on** | Phases 1–7 |

### Phase 9 — Integration & Handoff

| Item | Detail |
| :--- | :--- |
| **Tasks** | Pipeline runner posts alerts, incidents and attributions through the platform API; end-to-end test from corpus to API responses; handoff message (playbook §20); Developer A section in `CURRENT_STATUS.md` |
| **Outputs** | `services/pipeline.py`, `backend/tests/test_e2e_pipeline.py` |
| **Acceptance tests** | End-to-end fixture scenario passes after merge · Developer B can integrate using only contract + fixtures |
| **Depends on** | Phases 1–8, Developer B CR-01 … CR-07 merged |

---

## 5. Dependency Order

```
Phase 0 ──► Phase 1 ──► Phase 2 ──► Phase 3 ──► Phase 4 ──► Phase 5 ──► Phase 6 ──► Phase 7
                                                                                       │
                                                                     Phase 8 ◄─────────┘
                                                                        │
                       Developer B CR-01…CR-07 ─────────────────────► Phase 9
```

Phases 0–8 are independent of Developer B and run against fixtures. Only Phase 9 waits for platform changes.

---

## 6. Working Rules (from the playbook)

- Small commits on `predictions`; pull / rebase before each phase.
- No change to shared schemas without updating the contract first and telling Developer B.
- One feature implementation for training and inference.
- No new dependency without approval.
- Every phase ships tests and fixtures; module notes explain how to run it.

## 7. Out of Scope for v1

Blocking or automated response, full graph database, graph neural networks, more than three detectors, threat-actor / campaign naming, log retention, large-scale infrastructure, dashboard styling.

---

## 8. Progress Tracker

| Phase | Status | Notes |
| :--- | :--- | :--- |
| 0 — Setup & contract | In progress | Contract + plan drafted; CRs sent to Developer B |
| 1 — Corpus & ground truth | Not started | |
| 2 — Resolution & features | Not started | |
| 3 — Detectors | Not started | |
| 4 — Fusion & calibration | Not started | |
| 5 — Correlation | Not started | |
| 6 — Attribution | Not started | |
| 7 — Risk scoring | Not started | |
| 8 — Evaluation | Not started | |
| 9 — Integration & handoff | Blocked on CR-01 … CR-07 | |
