# Guide for Developer B — what Developer A built (in plain words)

Short version of `logs.md`. No ML background needed.

---

## 1. What the detection side does

Think of it as a factory line. Each step hands its output to the next:

1. **Read logs** → turn web, login (SSH / sudo), DNS and VPN logs into the same **event format** you store (`POST /events`).
2. **Describe behaviour** → every 5 minutes, for every user / IP / host, count things: how many logins, how many errors, new IP address?, privileged commands?, very long DNS names? (28 numbers per window, the "features").
3. **Detect** with two methods:
   - **Rules** — simple, readable checks ("a web-server account ran `su`", "someone read `/etc/shadow`", "a user logged in from an IP they never used"). 12 rules.
   - **Anomaly model (Isolation Forest)** — learns what *normal* looks like and flags what doesn't fit.
4. **Fusion** → combines both into **one alert with a confidence** (0–1) and a decision: `alert`, `review` or `suppress`. Repeats of the same thing within 30 minutes are folded into one alert.
5. **Correlation** → groups related alerts into **one incident** ("these 5 alerts are the same attack").
6. **Attribution** → tells the story of the incident: **where the attacker came in** (entry point), **what path they took**, **what they reached**, how long they stayed.
7. **Risk score** → 0–100 per incident (critical / high / medium / low) with the reasons listed.
8. **Deliver** → posts everything to **your API**: events, alerts, incidents, attributions.

All code: `backend/app/services/detection/`, `backend/app/services/attribution/`, `backend/app/services/pipeline.py`.

---

## 2. How we decided to work (before building)

- **Real data, not made-up data.** We used a public research dataset (**AIT-LDS v2.0**): 8 simulated companies, each with normal employees for a few days and then one real multi-step attack, with every attack log line labelled. We only download small slices (~40 MB per company instead of 7–27 GB).
- **Honest testing, like an exam.** We split the 8 companies:
  - **2 "practice" companies** — we were allowed to look at results and improve the system on them.
  - **6 "exam" companies** — never looked at while building. We **froze and committed** the system first, then tested once.
  This is why the numbers below can be trusted: the system had never seen those 6 companies.
- **Measure what an analyst cares about**: was the attack caught, how fast, how many false alarms per day, did we find the right entry point — never just "accuracy".
- **Write down mistakes** instead of hiding them (all in `logs.md`).

---

## 3. Results on the 6 unseen ("exam") companies

| Question | Result |
| :--- | :--- |
| Was the attack detected? | **6 out of 6**, first alert **5 minutes** after the attacker logged in |
| False alarms | **about 1 every 3 days** (only high-severity rules: none) |
| Alerts an analyst has to look at | 21 raw hits/day → **6 alerts/day → 2 incidents/day** |
| Was each attack shown as ONE incident? | **6 / 6** |
| Did we find how the attacker got in (stolen VPN login)? | **6 / 6** (first version: 4 / 6 — see mistakes) |
| Did we find the server they broke into? | **6 / 6** |
| Was the attack the highest-risk incident? | **5 / 6** |

The full evaluation runs with one command: `python -I scripts/evaluate.py` and writes `data/evaluation/evaluation_results.json` — **your `/evaluation/summary` endpoint now reads this file**, so the dashboard shows real numbers.

---

## 4. Mistakes and problems we found (and what we did)

**On our side:**

| What went wrong | What we did |
| :--- | :--- |
| First version only caught the noisy web scan (1 of 4 attack steps) | Found 4 clear reasons (e.g. the system "forgot" new history, missing checks for `su` / `/etc/shadow`), fixed them on practice data → now 4 of 4 steps |
| A rule for DNS scanning caused false alarms and caught nothing | Removed it, written down |
| A safety check switched off a rule because it fired "too often" — but it was firing on a real data theft already running | Changed the check: if the hits all come from 1–2 machines, keep the rule and report those machines |
| Downloading data: our rule for "company servers vs internet" was wrong in 4 companies and dropped the attacked server | Fixed (rule by server role names), re-downloaded |
| Entry point wrong in 2 exam companies: a normal user's request on the shared VPN address came 1 minute before the attacker | Fixed to follow the contract's definition ("root of the graph"). **Honest note:** fixed *after* seeing the exam results, so we report both: 4/6 (original) and 6/6 (fixed) |
| The "combine detectors" model (fusion) did **not** beat the rules alone at the alert threshold | Reported as is; the pipeline is "rules first" — fusion can add alerts but never hide a rule hit |
| The VPN server connects everything, so in one practice company 7 low-confidence normal alerts were merged into the attack incident | Written down; proposed fix needs new data to test |

**On the platform side (found by our end-to-end test against your API):**

| ID | Problem | Why it matters | Suggested fix |
| :--- | :--- | :--- | :--- |
| **CR-08** | `GET /evaluation/summary`: if `evaluation_results.json` doesn't match the response model, the code (`except Exception: pass`) silently returns the **hard-coded demo numbers** | The dashboard can show fake metrics with no error. It happened once (fixed on our side) | Log / return the error instead of the demo numbers |
| **CR-09** | `POST /events` looks up existing entities by `identifier` only | A host and an app with the same name collide; the second is never registered | Filter by `entity_type` too |
| **CR-10** | `method` in `POST /attributions` is accepted but not saved | UI can't show which method produced the attribution | Store and return it |

Everything else in your API worked: events, alerts, incidents and attributions were all accepted and read back correctly (`backend/tests/test_e2e_pipeline.py`).

**One change we made in your code — please review:** `backend/tests/test_api_v1.py::test_evaluation_summary_route` checked for `"endpoint_execution"`, a class name from the demo numbers. Now that the real file exists, that line failed. We changed it to "per-class metrics must not be empty". Nothing else of yours was changed.

---

## 5. What you need to know to use it

- **Run all tests:** `cd backend` → `python -m pytest tests -q` (353 pass).
- **Send a pipeline run into the platform:** see `docs/HANDOFF_DEVELOPER_A.md` (has a code example using `run_pipeline` and `deliver`).
- **Fields you will receive** (already in your schemas from CR-03 / CR-04):
  - Alerts: `detector`, `confidence` (0–1), `decision` (`alert` / `review`), `technique`, `evidence`.
  - Incidents: `risk_score`, `risk_level`, `layers`, `first_seen`, `last_seen`.
  - Attributions: `entry_point`, `attack_path` (each step names the real event that proves it), `reached_assets`, `blast_radius`, `graph` (same node / edge shape as your `GraphNode` / `GraphEdge`), `explanation` (one readable sentence).
- **Only `alert` and `review` are sent** — `suppress` never reaches the platform.

Questions → `logs.md` (full details per phase) or `docs/DETECTION_CONTRACT.md` (exact formats).
