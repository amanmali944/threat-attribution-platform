# Developer A — Status and Hand-off (Detection & Intelligence)

**Branch:** `predictions` · **Contract:** `docs/DETECTION_CONTRACT.md` · **Plan:** `docs/DETECTION_PLAN.md` · **Full build log:** `logs.md`

## What Developer A delivers

| Layer | Module | What it produces (contract section) |
| :--- | :--- | :--- |
| Entity resolution | `app/services/detection/resolve.py` | Enriched Events, deterministic entity IDs `ent-{type}-{sha256(tenant:identifier)[:8]}` (§2) |
| Features | `app/services/detection/features.py` | Feature Vectors, fs-1.2.0, 28 features, rolling entity history (§3) |
| Detectors | `rules.py` (rules-1.2.0, 12 rules), `anomaly.py` (Isolation Forest 1.1.0) | Alert Envelopes (§4) |
| Fusion | `fusion.py` (fusion-1.0.0, cal-1.0.0) | Fused Alerts with calibrated confidence and `alert` / `review` / `suppress` (§5) |
| Correlation | `app/services/attribution/correlation.py` | Incident Objects (§6) |
| Attribution | `app/services/attribution/graph.py` (graph-attribution-1.1.0) | Attribution Results: entry point, attack path, reached assets, blast radius, graph (§7) |
| Risk | `app/services/attribution/risk.py` | Risk Scores with contributors (§8) |
| Pipeline + delivery | `app/services/pipeline.py` | `run_pipeline(...)` and `deliver(post, result)` to the platform API |
| Evaluation | `scripts/evaluate.py` | `data/evaluation/evaluation_results.json` (§9), read by `GET /api/v1/evaluation/summary` |

## Measured results (AIT-LDS v2.0, 8 scenarios; figures are the 6 held-out scenarios)

| Question | Answer |
| :--- | :--- |
| Is each intrusion detected? | 6 / 6, first alert 5 minutes after the VPN login |
| Window-level precision / recall (pipeline) | 0.89 / 0.88; rules alone 0.98 / 0.87 at 0.38 false alarms per day |
| Alert volume per day | 21 flagged windows → 6.4 Fused Alerts → 2 incidents |
| Does each intrusion become one incident? | 6 / 6, holding 100 % of its alerts, across identity, network, application and endpoint layers |
| Is the entry point right? | 6 / 6 (account, attacker address, exact event) — 4 / 6 with the pre-registered method; see `logs.md` Phase 6 |
| Is the compromised server found? | 6 / 6; reached-asset precision 1.0, recall 0.69 |
| Is the intrusion the top risk? | critical in 6 / 6, ranked first in 5 / 6 |
| Calibration | ECE 0.002, Brier 0.002 |

Limits: one attack family (8 runs of the same intrusion template on different companies, users and dates); the review band is empty on this data; the VPN server acts as a hub in correlation (one development scenario merged 7 low-confidence benign alerts). All in `logs.md`.

## How to run

```
cd backend
python -m pytest tests -q                      # 353 tests: platform + detection + end-to-end
python -I ../scripts/evaluate.py               # whole evaluation from the converted corpus (~30 min)
python -I ../scripts/evaluate.py --assemble-only   # rebuild evaluation_results.json from stage outputs
```

Delivering a pipeline run to a running platform:

```python
import requests
from app.services.pipeline import run_pipeline, deliver
result = run_pipeline(raw_events, baseline=(start, end), score=(start, end), assets=inventory)
report = deliver(lambda path, body: (lambda r: (r.status_code, r.json()))(requests.post(BASE + path, json=body)),
                 result, raw_events=raw_events)
```

`deliver` posts, in order: the events the alerts cite (`POST /events`), Fused Alerts decided `alert` or `review` (`POST /alerts`, with `detector`, `detector_version`, `technique`, `confidence`, `decision`, `evidence`), incidents linked to the platform's alert IDs (`POST /incidents`, with `risk_score`, `risk_level`, `layers`, `first_seen`, `last_seen`), and attributions linked to the platform's incident IDs (`POST /attributions`, with `entry_point`, `attack_path`, `reached_assets`, `blast_radius`, `graph`). Alerts carry at most 200 event IDs; the full count is in `evidence`. Verified end to end against the platform in `backend/tests/test_e2e_pipeline.py` (in-memory database).

## Change requests to Developer B (found by the end-to-end test)

| ID | Finding | Why it matters | Suggested change |
| :--- | :--- | :--- | :--- |
| CR-08 | `GET /api/v1/evaluation/summary` silently returns hard-coded fallback numbers when `evaluation_results.json` fails the response model (`except Exception: pass`) | A schema mismatch shows invented metrics on the dashboard with no error. Found when the artefact had a text note inside a numeric object (fixed on Developer A's side) | Log the validation error and return it (or a clear "evaluation unavailable" state) instead of fallback figures |
| CR-09 | `POST /events` looks up existing entities by `identifier` only, not `(entity_type, identifier)` | A host and an application with the same name (or a user and a host) collide; the second entity is never registered | Filter on `entity_type` as well |
| CR-10 | `AttributionCreate.method` is accepted but not stored or returned | The UI cannot show which attribution method produced the result | Store and return `method` |

**One edit to a Developer B file, for review at merge:** `backend/tests/test_api_v1.py::test_evaluation_summary_route` asserted `"endpoint_execution" in per_class_metrics` — a class name from the endpoint's hard-coded fallback. Now that `data/evaluation/evaluation_results.json` exists, the endpoint serves the measured figures (CR-03 working as intended) and that line failed. It now asserts that `per_class_metrics` is non-empty; every other assertion is unchanged.

Nothing else is required from the platform: alerts, incidents, attributions, events and the evaluation summary all accept Developer A's payloads as they are.
