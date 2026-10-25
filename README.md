# Cross-Layer Threat Detection & Attribution Platform

Reads security logs from several layers (web, login, DNS, VPN), **detects** attacks with rules + machine learning, **groups** alerts into incidents, **explains** how the attacker got in and what they reached, **scores** risk, and shows it all in a web dashboard.

| Read this | For |
| :--- | :--- |
| **This README** | how to install, run, test and where everything is |
| [`docs/SYSTEM_OVERVIEW.md`](docs/SYSTEM_OVERVIEW.md) | **system diagram** + every phase: plan, problems, results, tests |
| [`guide_to_B.md`](guide_to_B.md) | short plain-language summary of the ML side |
| [`logs.md`](logs.md) | full build log with every number |
| [`docs/DETECTION_CONTRACT.md`](docs/DETECTION_CONTRACT.md) | exact data formats between detection and platform |
| [`docs/HANDOFF_DEVELOPER_A.md`](docs/HANDOFF_DEVELOPER_A.md) | detection hand-off + change requests CR-08…CR-10 |
| [`CURRENT_STATUS.md`](CURRENT_STATUS.md), [`docs/API_CONTRACT.md`](docs/API_CONTRACT.md) | platform side (Developer B) |

**Team:** Developer A = detection / ML / attribution / evaluation · Developer B = API / database / auth / frontend.

---

## 1. Where everything is

```
threat-attribution-platform/
├── backend/
│   ├── main.py                        FastAPI app entry point (port 8000)
│   ├── requirements.txt
│   ├── app/
│   │   ├── api/v1/                    [B] REST endpoints  (/api/v1/...)
│   │   ├── models/ schemas/ core/ db/ [B] database models, Pydantic schemas, config, seed
│   │   └── services/
│   │       ├── detection/             [A] contract, resolve, features, rules, anomaly, fusion, labeling, evaluation
│   │       ├── attribution/           [A] correlation, graph (attribution), risk
│   │       └── pipeline.py            [A] run_pipeline() + deliver() to the API
│   └── tests/
│       ├── test_*.py                  [B] platform tests  (+ test_e2e_pipeline.py [A])
│       └── detection/                 [A] detection tests
├── frontend/                          [B] React + TypeScript + Vite dashboard
├── scripts/                           [A] data download, conversion, evaluation
│   ├── adapters/                      raw log → canonical event (Apache, auth.log, dnsmasq, OpenVPN, AIT assets)
│   ├── fetch_remote_zip.py            downloads only the needed files from big dataset zips
│   ├── build_ait_corpus.py            converts all 8 AIT companies
│   ├── evaluate_*.py, summarize_ait.py   one script per evaluation stage
│   └── evaluate.py                    ONE command: whole evaluation → evaluation_results.json
├── data/
│   ├── evaluation/                    [A] committed results of every phase (JSON)
│   ├── specs/                         [A] splits + labels definition per dataset
│   ├── fixtures/                      [B] demo data + golden feature file
│   └── external/                      downloaded datasets (git-ignored, NOT in GitHub)
├── docs/                              contracts, plan, architecture, system overview
├── logs.md  guide_to_B.md             Developer A build log and summary
└── docker-compose.yml                 PostgreSQL + backend + frontend
```

---

## 2. Install (once)

Needs **Python 3.12** and **Node.js 20+** (tested with Python 3.12.3, Node 22).

```bash
git clone https://github.com/amanmali944/threat-attribution-platform
cd threat-attribution-platform
git checkout predictions            # Developer A's work (until merged into main)

pip install -r backend/requirements.txt
pip install "bcrypt==4.0.1"         # bcrypt 5.x breaks passlib login (known issue)

cd frontend && npm ci && cd ..
```

---

## 3. Run the platform

### Option A — local (simplest, uses SQLite)

Without PostgreSQL the backend falls back to SQLite at `<repo>/threat_platform.db`.

```bash
# 1. demo data (once)
python backend/app/db/seed.py

# 2. backend → http://localhost:8000   (API docs: http://localhost:8000/docs)
cd backend
python main.py

# 3. frontend (new terminal) → http://localhost:3000
cd frontend
npm run dev
```

**Login:** `analyst` / `analyst123` (also `admin` / `admin123`, `viewer` / `viewer123`). Demo credentials only.

Quick checks: `http://localhost:8000/health` → `{"status":"ok"}` · `http://localhost:8000/api/v1/evaluation/summary` → **our real measured numbers** (from `data/evaluation/evaluation_results.json`).

### Option B — Docker

```bash
docker compose up --build           # PostgreSQL :5432, backend :8000, frontend :3000
```

---

## 4. Run the tests

```bash
cd backend
python -m pytest tests -q                 # everything: 353 passed, 3 skipped (~35 s)
python -m pytest tests/detection -q       # Developer A only
python -m pytest tests -q --ignore=tests/detection   # Developer B platform tests
python -m pytest tests/test_e2e_pipeline.py -v       # detection → real FastAPI app, end to end
```

**On a fresh clone** some real-data tests **skip** (`"AIT slice not converted"`, `"Org Y windows not built"`) because the datasets are not in GitHub. That is expected — everything else still runs. They run once you download the data (section 5). The 3 skips you always see are old Phase 3 result files produced with an older feature set (kept as history).

### Tests per phase

| Phase | What it checks | Command (from `backend/`) |
| :--- | :--- | :--- |
| 1 · data + labels | adapters parse real logs, every line accounted for, labels never leak into training | `pytest tests/detection/test_web_server_adapter.py tests/detection/test_syslog_auth_adapter.py tests/detection/test_ait_adapters.py tests/detection/test_labeling.py -q` |
| 1e · AIT corpus | download tool, split generator, asset inventory | `pytest tests/detection/test_fetch_remote_zip.py tests/detection/test_make_ait_spec.py tests/detection/test_ait_assets.py -q` |
| 2 · entities + features | entity IDs = platform IDs, hand-computed feature values, determinism, golden file | `pytest tests/detection/test_resolve.py tests/detection/test_features.py -q` |
| 3 · detectors | every rule fires / near-miss, gate, Isolation Forest, metrics | `pytest tests/detection/test_rules.py tests/detection/test_anomaly.py tests/detection/test_evaluation.py -q` |
| 3 · results | committed results consistent and reproducible | `pytest tests/detection/test_phase3_results.py tests/detection/test_phase3_ait_results.py tests/detection/test_phase3_ait_corpus.py -q` |
| 4 · fusion | calibration, thresholds, folding, leave-one-out folds | `pytest tests/detection/test_fusion.py tests/detection/test_phase4_results.py -q` |
| 5 · correlation | alerts → incidents, pivots, horizon | `pytest tests/detection/test_correlation.py tests/detection/test_phase5_results.py -q` |
| 6 · attribution | entry point, time-ordered path, reach, graph shape | `pytest tests/detection/test_attribution_graph.py tests/detection/test_phase6_results.py -q` |
| 7 · risk | formula, half-life, levels, contributors | `pytest tests/detection/test_risk.py tests/detection/test_phase7_results.py -q` |
| 8 · evaluation file | every contract key, no accuracy, matches stage outputs | `pytest tests/detection/test_evaluation_results.py -q` |
| 9 · integration | pipeline → FastAPI → read back | `pytest tests/test_e2e_pipeline.py -v` |

Frontend checks (Developer B): `cd frontend && npm run lint && npm run build`.

---

## 5. Reproduce the evaluation (optional, ~1 hour)

All results are **already committed** in `data/evaluation/`. Do this only to regenerate them. Run Python with `-I` on downloaded data.

```bash
# 1. download the needed slice of each AIT company (25–52 MB each, not the 7–27 GB zips)
for s in russellmitchell fox harrison santos shaw wardbeck wheeler wilson; do
  python -I scripts/fetch_remote_zip.py "https://zenodo.org/records/5789064/files/$s.zip?download=1" ait-slice data/external/ait/scenarios/$s
done

# 2. convert all 8 companies → events, assets, splits, windows (+ integrity report)
python -I scripts/build_ait_corpus.py data/external/ait/scenarios data/external/ait/corpus

# 3. whole evaluation: detectors, fusion, correlation, attribution, risk (~35 min)
python -I scripts/evaluate.py

# only rebuild evaluation_results.json from the stage outputs (seconds)
python -I scripts/evaluate.py --assemble-only
```

Commands for the smaller Org X / Org Y datasets are at the top of [`logs.md`](logs.md).

**Important rule:** `russellmitchell` and `fox` are **development** companies (changes allowed); `harrison, santos, shaw, wardbeck, wheeler, wilson` are **held-out**. Any new detector change judged on the held-out six is no longer an honest result — test new ideas on new data.

### Where the results are

| File (`data/evaluation/`) | Phase | Contents |
| :--- | :--- | :--- |
| `ait_corpus_report.json` | 1e | integrity of the 8-company corpus |
| `phase3_org_y.json`, `phase3_ait_russellmitchell_*.json` | 3 | first detector results (history) |
| `phase3_ait_corpus_asis.json`, `_clean.json` | 3e | frozen detectors on all 8 companies |
| `phase4_fusion_loso_logreg.json`, `_hgb.json` | 4 | fusion, leave-one-scenario-out |
| `calibration.json` | 4 | final fusion model thresholds + coefficients |
| `phase5_correlation.json` | 5 | incidents per company |
| `phase6_attribution.json` | 6 | entry point / path / reach vs ground truth |
| `phase7_risk.json` | 7 | risk ranking |
| **`evaluation_results.json`** | 8 | **summary the dashboard reads** (`GET /api/v1/evaluation/summary`) |

---

## 6. Send detection results into the running platform

```python
# from backend/, with the backend running on :8000
import requests
from app.services.pipeline import run_pipeline, deliver

BASE = "http://localhost:8000/api/v1"
result = run_pipeline(raw_events, baseline=(start, end), score=(start, end), assets=inventory)
report = deliver(lambda path, body: (lambda r: (r.status_code, r.json()))(requests.post(BASE + path, json=body)),
                 result, raw_events=raw_events)
```

`deliver` posts, in order: events → alerts (`alert` / `review` only) → incidents → attributions. A working example with real-looking data is `backend/tests/test_e2e_pipeline.py`. Without a trained fusion model the pipeline runs **rules-only**.

---

## 7. Headline results (6 held-out companies, never seen while building)

| | |
| :--- | :--- |
| Attacks detected | **6 / 6**, first alert 5 min after the attacker's login |
| False alarms | **0.38 / day** |
| Analyst load | 21 raw hits/day → 6.4 alerts → 2 incidents |
| Attack = one incident | 6 / 6 |
| Entry point correct | 6 / 6 (pre-registered method 4 / 6) |
| Attack ranked top risk | 5 / 6 |

Details, problems and limits: [`docs/SYSTEM_OVERVIEW.md`](docs/SYSTEM_OVERVIEW.md).

---

## 8. Git workflow

- `main` — Developer B's platform. `predictions` — Developer A's detection work.
- Merging `predictions` into `main` is decided by the team; review the one-line change in `backend/tests/test_api_v1.py` (see hand-off).
- Open for Developer B: **CR-08** (no silent demo metrics), **CR-09** (entity lookup by type + identifier), **CR-10** (store attribution `method`).

## 9. Troubleshooting

| Symptom | Fix |
| :--- | :--- |
| Login fails / 3 auth tests fail | `pip install "bcrypt==4.0.1"` |
| Dashboard evaluation shows unexpected demo numbers | `evaluation_results.json` failed validation and the endpoint fell back silently (CR-08). Run `pytest tests/detection/test_evaluation_results.py` |
| Real-data tests skipped | datasets not downloaded — expected; see section 5 |
| Frontend can't reach API | backend must be on port 8000 (Vite proxies `/api` → `localhost:8000`) |
| Non-ASCII error printing on Windows | run Python with `-I`; scripts write UTF-8 |
