# Developer A — Build Log (Detection & Intelligence)

Running record of what was done in each phase, how it was tested, and what the results were.
Newest phase at the bottom. Plan: `docs/DETECTION_PLAN.md`. Contract: `docs/DETECTION_CONTRACT.md`.

**Branch:** `predictions` (local commits; pushing and merging to GitHub is done by the team, not by the assistant).
**Environment:** Windows 11, Python 3.12.3, numpy 2.2.6, scikit-learn 1.8.0, networkx 3.5, pytest.

## How to run everything

```
cd backend
python -m pytest tests/detection -q          # Developer A tests (46)
python -m pytest tests -q                    # whole backend suite (105)
```

---

## Phase 0 — Setup & contract freeze

**Dates:** Oct 09 – Oct 21, 2026 · **Status:** DONE

### What was done
- Read the Developer A playbook and Developer B's code; compared against the product brief.
- Wrote `docs/DETECTION_CONTRACT.md` (every data shape between detection and the platform, plus change requests CR-01…CR-07) and `docs/DETECTION_PLAN.md` (phases 0–9). Committed on `predictions` (`0f57c4c`) with the playbook PDF.
- Developer B delivered CR-01…CR-07 on `main` (`cdc8e3d`, `9d7e670`). Verified against the code: alert fields (`detector`, `detector_version`, `technique`, `technique_id`, `entity_id`, `score`, `confidence`, `decision`, `evidence`) and attribution fields (`entry_point`, `attack_path`, `reached_assets`, `blast_radius`, `dwell_time_seconds`, `explanation`, `graph`) match the contract names exactly; `POST /api/v1/attributions` exists; `generate_entity_id` uses `ent-{type}-{sha256(tenant:identifier)[:8]}`.
- Merged `main` into `predictions` **locally** (`fbe9539`, clean, no conflicts) so detection code builds on B's new fields. Nothing pushed or merged on GitHub.
- Clarified the contract where writing real code exposed gaps (see Phase 2).

### Tests / verification (platform on this laptop, from `main`)
| Check | Result |
| :--- | :--- |
| Backend tests | **59 / 59 passed** (after pinning `bcrypt==4.0.1` locally — see issue 1) |
| Alembic `001 → 002` + seed (SQLite) | OK: 4 events, 7 entities, 3 alerts, 2 incidents, 1 attribution, 1 user |
| Backend on :8000 | `/health` ok; events=4, alerts=3; dashboard summary OK |
| Frontend build (`npm ci && npm run build`) | OK (large-bundle warning only) |
| Frontend on :5173 | HTTP 200; login via Vite proxy OK (`analyst`); incident graph `inc-9001` → 10 nodes, 19 edges |

### Issues found in the platform (for Developer B)
1. `bcrypt` unpinned: `passlib 1.7.4` crashes with `bcrypt 5.x` (3 auth tests fail on a fresh install). Fix: pin `bcrypt==4.0.1` (or `<4.1`).
2. Database path depends on the working directory: the server always uses `<repo>/threat_platform.db`, but `seed.py` and Alembic resolve a relative path, so running them from `backend/` creates a second database the server never reads.
3. `GET /evaluation/summary` still falls back to **hard-coded metrics** (including invented attribution accuracy) when `evaluation_results.json` is absent (`evaluation.py:80`). The dashboard would show them as real. Should return "not evaluated yet".
4. Hard-coded demo credentials in `auth.py` (`analyst/admin/viewer`, also accepting `password` and the username). Fine for demo; remove before any real deployment.

---

## Phase 1 — Attack corpus & ground truth

**Status:** DEFERRED — not built

### What happened
- The plan called for a seeded generator producing normal activity plus four labelled attack scenarios. While starting this phase in the assistant session, that step was **halted by the tool's safety check** and the generator was **not written**. It was not retried or reworded.
- No corpus files exist. `data/fixtures/` still holds only the platform's 4 sample events.

### Consequence
Anything that needs *labelled windows* is blocked: training/evaluating fusion (Phase 4), the per-class precision/recall in Phases 3 and 8, and attribution accuracy against ground truth (Phase 6). Work that does not need labelled data (Phase 2, the rules engine, model mechanics) can proceed and is verified on unit fixtures only.

### Decision needed from the team
Where does labelled data come from? Options: (a) the team writes the generator themselves, (b) adopt a published labelled dataset and map it to the canonical event format, (c) a small hand-written fixture set sufficient for unit tests only (cannot support honest evaluation numbers). Until decided, no evaluation figure should be quoted anywhere.

---

## Phase 2 — Entity resolution & feature engine

**Date:** Oct 21, 2026 · **Status:** DONE (verified on unit fixtures + platform sample events; not yet on a labelled corpus)

### What was built
| File | Purpose |
| :--- | :--- |
| `backend/app/services/detection/contract.py` | Constants shared by all detection code: layers, entity types, required payload keys per event type, outcome vocabulary, `validate_event`. |
| `backend/app/services/detection/resolve.py` | Canonical event → enriched event. Deterministic entity IDs; roles (actor user / ip / host / device, target, criticality); payload-only identifiers become entities; skip-and-count for unusable events; dedupe; stable ID for events without one. |
| `backend/app/services/detection/features.py` | `FeatureConfig`, `fit_baseline`, `compute_features`, `extract`. 22 features (fs-1.0.0), epoch-aligned tumbling/hopping windows, baseline-relative novelty / off-hours / peer z-scores, JSON-serialisable `Baseline`. |
| `backend/tests/detection/` | `helpers.py`, `conftest.py`, `test_resolve.py` (18), `test_features.py` (28). |
| `data/fixtures/expected_features.json` | Golden feature vectors for the platform's 4 sample events (6 vectors). |

### Design decisions (also written into the contract, §2.2 and §3.2)
- **Subjects:** an event contributes to the vector of each actor-side entity (`actor_user`, `actor_ip`, `actor_host`); targets get no vector in v1.
- **Windows** aligned to the Unix epoch (replays identical); `stride_seconds < window_seconds` gives overlapping windows so a burst split across a boundary is still seen whole.
- **Baseline is an input artefact**, fitted on a normal period; the feature function is identical for training, evaluation and live use (playbook rule). Cold start: an entity with `< 20` baseline events gets 0 for novelty/off-hours instead of flagging every new entity.
- **Source host:** a remote session's `source_host` resolves to a `host` entity (not `device`), so lateral movement becomes host → host edges later.
- **Network events** now have a defined target (`domain` entity, else `dst_ip`).
- IDs use identifiers **verbatim** (no case folding) to stay byte-identical with the platform's `generate_entity_id`; a test fails if they ever drift.
- Degenerate values fixed and documented: CV = 1.0 with < 3 events, 0.0 if mean gap is 0; zero-denominator rates = 0.0; peer std floored at 1.0.

### Test results
| Suite | Tests | Result |
| :--- | :--- | :--- |
| `test_resolve.py` | 18 | **18 passed** |
| `test_features.py` | 28 | **28 passed** |
| Whole backend suite (platform 59 + detection 46) | 105 | **105 passed** (15.7 s) |

What the tests check (expected values worked out by hand in comments, not copied from output):
- **Entity IDs** equal the platform helper; payload-IP and listed-IP resolve to one entity; roles correct on all 4 platform sample events.
- **Hand-computed features:** login burst (7/10 failures → 0.7, longest run 5, mean gap 5.0 s, CV 0.0; IP-level 9/12 = 0.75 and 2 accounts from one IP); HTTP (3/8 errors = 0.375, bytes 3600, 3 sessions, path entropy 1.298795 bits); database (rows read 30, 3 privileged ops, entropy); admin processes by basename/case.
- **Windows:** exact half-open boundaries (299.999 vs 300.000 vs −0.001), tumbling splits a burst 3+3, hopping recovers all 6, configurable length, invalid configs rejected, tenants never merged.
- **Determinism:** same input replay ⇒ identical JSON; shuffled input order ⇒ identical; baseline survives a JSON round trip.
- **Baseline-relative:** new IP + new country + 03:00 activity fire novelty and off-hours; familiar behaviour scores 0; new-target count; cold-start entities (unknown, or < 20 events) are not flagged; peer z-scores (5.0 and 2.0 worked by hand); custom cohort mapping overrides entity type.
- **Reporting:** unusable events are skipped *and counted* with the missing keys; duplicates counted; unknown event types counted.
- **Golden file:** features on the 4 platform sample events equal `expected_features.json`; values hand-checked (6 vectors; cloud event falls in the next window; DNS-event IP has 0 accounts).

### Do the tests actually catch bugs? (mutation check)
Deliberately broke the code and confirmed a test fails each time:
| Deliberate bug | Caught by |
| :--- | :--- |
| failure-rate denominator off by one | `test_login_feature_values` ✔ |
| novelty check inverted (source IP) | `test_novelty_and_off_hours_fire_on_unfamiliar_behaviour` ✔ |
| window alignment shifted by 1 s | **NOT caught at first** — no test had an event on a window edge. Added `test_window_boundaries_are_exact`; now caught ✔ |
| off-hours rule never fires | `test_novelty_and_off_hours_fire_on_unfamiliar_behaviour` ✔ |
| peer z-score ignores std floor | `test_custom_cohort_mapping_overrides_entity_type` ✔ |

### Performance
20,000 events → 6,000 feature vectors in **1.14 s** (single thread, pure Python). Fine at project scale.

### Known limitations
- Verified only on hand-built unit fixtures and the platform's 4 sample events. Real behaviour on a labelled corpus is unmeasured (Phase 1 deferred).
- Overlapping windows are correlated, so baseline cohort statistics from hopping windows are slightly optimistic; tumbling is the default.
- Off-hours uses UTC hour of day only (no per-user time zone or weekday pattern).
- Features for hosts rely on `source_host` / endpoint events; hosts seen only as targets get no vector.

---

## ML strategy (decision recorded Oct 21, 2026)

Recorded in `docs/DETECTION_PLAN.md` §4A. Summary: baseline-relative features → Isolation Forest per subject type (trained on normal only) → n-gram sequence model → **supervised logistic-regression fusion** (gradient boosting as challenger) → isotonic calibration with an abstain band. Evaluation splits by scenario run, includes leave-one-attack-class-out and ablations, and reports PR-AUC, per-class precision/recall, ECE/Brier and alerts per analyst per day — never accuracy. All of it depends on a labelled data source (Phase 1 decision).

---

## Next

1. **Decide the Phase 1 data source** (above).
2. Phase 3a — rules engine (needs only features; every rule gets a passing and a failing test).
3. Phase 3b/3c — Isolation Forest and sequence model *mechanics* (fit/score separation, ECDF scoring, determinism) can be built and unit-tested without labelled data; training and evaluation wait for Phase 1.
