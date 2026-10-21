# Developer A — Build Log (Detection & Intelligence)

Running record of what was done in each phase, how it was tested, and what the results were.
Newest phase at the bottom. Plan: `docs/DETECTION_PLAN.md`. Contract: `docs/DETECTION_CONTRACT.md`.

**Branch:** `predictions` (local commits; pushing and merging to GitHub is done by the team, not by the assistant).
**Environment:** Windows 11, Python 3.12.3, numpy 2.2.6, scikit-learn 1.8.0, networkx 3.5, pytest.

## How to run everything

```
cd backend
python -m pytest tests/detection -q          # Developer A tests (239 + 3 version-gated skips)
python -m pytest tests -q                    # whole backend suite (298)

# Real-data conversion (needs the dataset downloaded into data/external/, see Phase 1):
python -I scripts/adapters/web_server_logs.py <organization dir> <output dir> --tenant org-x
python -I scripts/adapters/syslog_auth.py <organization-y dir> <output dir> --tenant org-y --year 2025
python -I scripts/build_org_y_windows.py <derived auth dir> data/specs/org_y_incident.json <windows dir>
python -I scripts/evaluate_org_y.py <windows dir> data/specs/org_y_incident.json data/evaluation/phase3_org_y.json --model-dir <models dir>
python -I scripts/convert_ait_scenario.py data/external/ait/russellmitchell data/external/ait/derived/russellmitchell --scenario russellmitchell --year 2022
python -I scripts/build_ait_windows.py data/external/ait/derived/russellmitchell data/specs/ait_russellmitchell.json data/external/ait/windows/russellmitchell-asis
python -I scripts/build_ait_windows.py data/external/ait/derived/russellmitchell data/specs/ait_russellmitchell.json data/external/ait/windows/russellmitchell-clean --clean-baseline
python -I scripts/evaluate_ait.py data/external/ait/windows/russellmitchell-asis data/specs/ait_russellmitchell.json data/external/ait/derived/russellmitchell data/evaluation/phase3_ait_russellmitchell_asis.json
python -I scripts/evaluate_ait.py data/external/ait/windows/russellmitchell-clean data/specs/ait_russellmitchell.json data/external/ait/derived/russellmitchell data/evaluation/phase3_ait_russellmitchell_clean.json

# Multi-scenario AIT corpus (Phase 1e): fetch the standard slice of each scenario, then build everything
python -I scripts/fetch_remote_zip.py "https://zenodo.org/records/5789064/files/<scenario>.zip?download=1" ait-slice data/external/ait/scenarios/<scenario>
python -I scripts/build_ait_corpus.py data/external/ait/scenarios data/external/ait/corpus
python -I scripts/evaluate_ait.py data/external/ait/corpus/windows/<scenario>-asis data/specs/ait/<scenario>.json data/external/ait/corpus/derived/<scenario> data/external/ait/corpus/eval/<scenario>-asis.json --dump-windows data/external/ait/corpus/dumps/<scenario>-asis.jsonl
python -I scripts/evaluate_fusion.py data/external/ait/corpus/dumps <results json> --scenarios <scenario> <scenario> ... --variant asis
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

## Phase 1 — Real-data corpus & ground truth

**Status:** IN PROGRESS — 1a (Org X), 1c (Org Y), 1b (labels/splits for Org Y) and 1d conversion (AIT `russellmitchell`) done; AIT labels/splits next

### Decision history
- The original plan was a seeded synthetic generator (normal activity + four labelled attack scenarios). When this phase was started in the assistant session, that step was **halted by the tool's safety check** and the generator was **not written**; it was not retried or reworded.
- Decision (Oct 21, 2026, with the user): use **small slices of published datasets** instead. The database and cloud layers have no usable public labelled data, so they are **unvalidated** and must be reported that way. Candidates surveyed: AIT-LDS v2.0 (CC BY-NC-SA 4.0), LANL Multi-Source (12 GB), CERT insider (r4.2/r6.2), Web Server Log Dataset (MIT), SR-BH 2020 (CC0), an ATT&CK-labelled endpoint dataset (no download link found), DARPA OpTC (very large).
- Order: 1a Org X (2.1 MB) → 1b labels and time-ordered splits → 1c Org Y (391 MB; real privilege escalation; check client-IP diversity before downloading) → 1d an AIT slice (multi-source, multi-step).
- Raw and derived data live in `data/external/` (git-ignored; never committed).

### 1a — Web Server Log Dataset, Organization X (Zenodo 10.5281/zenodo.20001206, MIT)
**Date:** Oct 21, 2026

**Download and handling:** `organization-x.zip`, 2,135,289 bytes, MD5 `b4bf79effa6f3ee1b9e53f278d916620` (matches Zenodo). Listed the members first (65 entries, no unsafe paths), then extracted into a fresh empty directory with a path-checked extractor. Python run with `-I` on all third-party data.

**What the data is:** Apache access logs (15 rotated files), `auth.log`, `syslog`, and a ground-truth YAML of 39 text-pattern rules. 213,205 access lines, 2025-09-23 → 2025-10-07 (UTC). Client IPs are anonymised.

**Findings about the data (these limit what Org X can be used for):**
| Finding | Detail |
| :--- | :--- |
| **One client IP** | 213,192 of 213,205 requests come from `255.102.154.224` (probably a proxy in front of the server); the other 13 are `::1`. **No per-IP or per-user behaviour exists**, so Org X cannot evaluate entity-level detection. |
| No user identity | Apache user field is `-` on every line. |
| `auth.log` is noise | 4,334 lines: 4,328 cron session open/close, 2 sudo, 1 `sshd: Accepted`. No brute force. Not converted. |
| Heavy benign monitors | HetrixTools and Uptime-Kuma bots are ~70,000 requests (33%). |
| Labels are rules, not review | 639 events (0.30%) match `moderate` rules; 10,890 (5.1%) match the `strict` `dir_scan` rule. Rules key on user-agent and URL text, so a model can learn the rules. |

**What was built:** `scripts/adapters/web_server_logs.py`: Apache combined-format parser (handles escaped quotes, timeout-style `"-"` requests, `-` bytes), timezone conversion to UTC, canonical `application/http_request` events, rule-based labelling into a **sidecar** `labels.jsonl` (never inside events), report with counts and checksums. Deterministic IDs `wsld-<file>-<line>`. Rotated files read oldest first.

**Conversion result (real data):**
| Measure | Result |
| :--- | :--- |
| Lines read | 213,205 |
| Events written | **213,205** (0 unparsed — a first, naive regex missed 28 lines with escaped quotes; fixed) |
| Contract problems (`validate_event`) | **0** |
| Time | 102 s (single thread); `events.jsonl` 131.6 MB |
| Rules file SHA-256 | `f5969561…cf2767` recorded in `report.json` |

**Feature engine on real data (smoke test, not an evaluation):** 38,027 baseline + 23,341 test events → baseline fit 3.0 s, features 1.8 s, 290 vectors, **0 non-finite values**, replay identical, ~280 MB RSS, 0 events skipped. Only one entity type/entity (the proxy IP), so peer z-scores compare the entity with itself and are meaningless here.

**Tests (`test_web_server_adapter.py`, 14):** parsing (UTC conversion, escaped quotes, timeout lines, garbage, bytes `-`), event contract validity and resolution, authenticated user entity, rule semantics (ALL patterns, case-insensitive, `code:` via status, `%` wildcard, strict vs moderate separation), numeric rotation order oldest-first, end-to-end conversion counts, byte-for-byte determinism, and two checks against the real data (every raw line accounted for: `events + unparsed == raw lines`; rules checksum matches). **14 passed.** Whole backend suite: **119 passed** (platform 59 + detection 60).

**Mutation check (do the tests catch bugs?):** rule needs ANY instead of ALL ✔ caught · status code not injected into match text ✔ · rotation order reversed ✔ · escaped-quote support removed ✔.

**Verdict:** Org X proves the converter, the contract validation and the feature engine on real logs. It **cannot** measure entity-level detection (single client IP, no users), so it is plumbing and regression data, not an evaluation set.

**Known limitations:** label rules re-implemented against raw lines, not the authors' log2timeline pipeline (approximate); `%` treated as a wildcard; `auth.log` and `syslog` not converted; timestamps from Apache carry an explicit offset (+0700) and are converted correctly, but syslog lines (not converted) have no year or zone.

### 1c — Web Server Log Dataset, Organization Y (same Zenodo record, MIT)
**Date:** Oct 21, 2026 · **Status:** DONE for the chosen slice

**Looked before downloading (no full download):** Zenodo supports HTTP range requests (confirmed with a 206 response), so I read the zip's directory and profiled selected members remotely — nothing written to disk. Org Y's zip is 390,765,762 bytes, 260 members; 322 MB of it is top-level system logs (including a 2.4 GB `syslog.1` that we do not need).

**What the remote profile showed (this decided what to fetch):**
| Member | Finding |
| :--- | :--- |
| Web access log, first vhost (Apr 27–29) | 50,433 requests, **99.96% from one IP**, 33,181 `POST /wp-login.php` with a different user-agent each time (real web-login brute force from one source) |
| Four other vhosts' access logs | only 3–4 distinct client IPs each; mostly attack traffic. **Web layer is not entity-diverse.** |
| `var/log/auth.log` | 775,150 lines, Apr 27 – May 1: **219,382 failed SSH logins from 406 distinct IPs, 2,320 usernames tried**, 33 accepted logins from 9 IPs, 2,191 sudo commands |
| Ground-truth YAML | 30 rules, incl. the post-compromise chain (sudo commands, web-panel actions, vhost create/delete) |

**Fetched (≈ 5 MB over the network, 130 MB on disk):** the YAML, `auth.log`, and five vhost access logs, into a fresh directory with a path-checked extractor; each member's CRC32 is verified while reading. A transient network error (IncompleteRead) interrupted one run; added retries and a resume mode that skips completed members. Data is git-ignored.

**Adapters:** shared rule code moved to `scripts/adapters/_common.py`; `web_server_logs.py` extended (`--access-glob`, `--app-regex` so the application is the virtual-host name); new `scripts/adapters/syslog_auth.py`:
- sshd `Failed …` → identity `user_login` FAILURE; sshd `Accepted …` → SUCCESS; sudo commands → endpoint `process_execution` (`process_name: sudo`, so the feature engine counts them as privileged).
- Skipped **and counted**: sshd "Invalid user" duplicates, PAM duplicates of failures, connection noise, cron, session open/close.

**Conversion results (real data):**
| Source | Lines | Events | Skipped | Unparsed | Contract problems | Time |
| :--- | ---: | ---: | ---: | ---: | :---: | ---: |
| `auth.log` | 775,150 | 221,606 (failed 219,382 · accepted 33 · sudo 2,191) | 553,543 | 1 (NUL padding) | **0** | 34 s |
| 5 vhost access logs | 173,107 | 173,104 | – | 3 (NUL padding) | **0** | 36 s |

`lines == events + skipped + unparsed` holds exactly for `auth.log`.

**Bugs the real data exposed (all fixed, all now covered by tests):**
1. sudo lines with a `GROUP=` field were dropped — they are exactly the ownership-change steps of the labelled incident chain.
2. SSH scanners send usernames that are **empty or contain spaces**; 61 failed logins were silently skipped. Found by an independent raw-file count (the test uses different regexes from the adapter on purpose). Empty usernames are stored as `<empty>`.
3. Label counts counted rule hits, so an event matching two rules with the same label counted twice. Now counted per event.

**Label picture (rule-derived, see caveats):**
| Layer | Result |
| :--- | :--- |
| SSH | `bruteforce_login_server_attempt` on **every one** of the 219,382 failures. Post-compromise chain labels exist but are tiny: vhost create/delete, mkdir, chmod, chown, file creation — 1–2 events each. |
| Web | strict `bruteforce_login_web` on 91,378 events (52.8%); moderate rules on only 12. |
| **Missing** | The rules `bruteforce_login_success` and `ssh_login_success` name the intruder's original IP, but the published logs were re-anonymised afterwards, so **they match nothing**. No event is labelled as "the compromise". The dataset's own description puts the incident at 05:28–07:07 on Apr 29; the first successful root logins appear at 05:34 on Apr 29, which fits only if the syslog clock is UTC (assumed, not proven). |

**First look at real features (not an evaluation):** 80,000 SSH events → 12,588 vectors in 1.1 s, 0 skipped. In that stretch (Apr 27 – early Apr 28) **100% of IP windows are 100% failed logins** — there is no benign class — and one IP made 454 attempts in five minutes against one account.

**Tests:** `test_syslog_auth_adapter.py` (15) + `test_web_server_adapter.py` (14): parsing incl. odd spacing/zone offset, classification of every skip reason, event validity and resolution, sudo counted as privileged, the three bugs above, per-event label counts, byte-for-byte determinism, accounting of every line, and a real-data check against an independent count of the raw file. Detection suite: **75 passed**; whole backend: **134 passed**. Mutation check (username regex, `GROUP=` support, UTC-offset sign, per-hit label counting): **all 4 caught**.

**What this data can and cannot do:**
- ✔ A real identity layer with entity diversity (406 source IPs, 2,320 usernames), real brute force, successful logins, post-compromise privileged commands, and real web-login brute force — the first data here that can exercise entity-level features and the attack-path / entry-point work.
- ✘ It is almost entirely hostile traffic: very little benign activity to learn "normal" from (33 successful logins, cron-driven sudo). A baseline "fitted on normal" is thin in the identity layer.
- ✘ "Brute force" labels are trivially separable; the meaningful target is **the incident** (success after failures, then privileged commands), whose labels are weak. Any detection score on the brute-force labels must not be presented as detection quality.
- ✘ Still no database or cloud layer.
- The Org Y IPs look real (not anonymised like Org X). They stay in the git-ignored `data/external/` and are deliberately not quoted in the docs.

### 1b — Window labels, incident target and time-ordered splits (Org Y)
**Date:** Oct 21, 2026 · **Status:** DONE

**First, what the ground truth actually looks like** (timeline built from the converted events, IPs replaced by tags):
- **None of the 33 accepted logins came from an IP that had failed before.** The intruder logged in as root with a valid password on the first try — "success after brute force" is *not* the pattern here.
- First accepted root login 05:34:30 Apr 29; two source IPs log in as root between 05:34 and 06:12 (incl. two public-key logins at 06:11, i.e. a key was installed).
- **Privileged-command burst:** sudo (root→root) runs at ~1 per hour every hour, then **334 in the 06:00 hour**, plus commands as two newly created site users. All 13 rule-labelled post-compromise steps (create site → mkdir → chmod → chown → copy files → delete site, twice) fall between 06:09:07 and 07:08:46.
- After 07:10: more root logins from other IPs and a second account (`iisti9694`) on Apr 29–30. The ground truth does not say whether these are benign or malicious.

**Definitions (code: `backend/app/services/detection/labeling.py`; spec: `data/specs/org_y_incident.json`, committed, no IPs):**
| Term | Definition |
| :--- | :--- |
| Routine sudo command | Digit-normalised command seen in ≥ 20 distinct hours of the pre-incident period (baseline + train). Learned from earlier data only. Found 3 (cron-driven log reads and a `chown` of the panel directory). |
| Notable event | A successful login, or a sudo command that is not routine |
| Incident event | A notable event inside the documented incident interval 2025-04-29 05:28–07:10 (dataset description 05:28–07:07; last labelled step 07:08:46; UTC assumed) |
| Window label | `incident` if it contains an incident event · `unknown` if it contains a notable event outside the interval (**excluded from scoring**, not counted as benign) · `background` otherwise |

**Splits (time-ordered, half-open, aligned to the 300 s window so no window can straddle a boundary; the spec loader refuses an incident that touches baseline / train / validation):**
| Split | Period (UTC) | Use | Windows | incident | unknown |
| :--- | :--- | :--- | ---: | ---: | ---: |
| baseline | Apr 27 | fit the feature baseline only (66,177 events), not scored | – | – | – |
| train | Apr 28 | fit unsupervised models on background | 11,889 | 0 | 0 |
| validation | Apr 29 00:00–04:00 | thresholds / alert budget from background | 581 | 0 | 0 |
| gap | Apr 29 04:00–05:00 | excluded | 140 | 0 | 0 |
| test | Apr 29 05:00 – May 1 00:30 | evaluation | 15,752 | **21** | 50 |

Incident windows by entity type: 10 user, 6 host, 5 IP. Notable events: 356 incident, 42 unknown. Build time 18.7 s (one UTC day at a time to keep memory low). Outputs in `data/external/.../derived/org-y/windows/` (git-ignored): `train/validation/test.jsonl`, `baseline.json` (entity IDs are hashes), `dataset_report.json`.

**Cross-check against the ground truth:** all 13 rule-labelled post-compromise commands are classified `incident` by the definition above (13 / 13).

**Tests (`test_labeling.py`, 16 passed):** spec validation (rejects incidents overlapping train or validation, incidents running past the test end, misaligned or overlapping splits, missing splits), half-open split membership incl. a straddling window, routine-command learning (distinct hours, digit normalisation, period limits), event classes, label precedence (incident > unknown > background), an end-to-end check that labels follow entities (noise during the incident stays background), and a real-data check over all ~28,000 written windows (no incident outside test, every window inside its split, labels never inside features, counts equal the report). **Mutation check: 5 / 5 caught** (leakage guard removed, routine threshold off by one, precedence swapped, split check ignoring window end, every notable event called incident). Whole backend suite: **150 passed**.

**Limits that must travel with any result from this data:**
1. **One incident.** Org Y supports a *zero-shot* evaluation of unsupervised and rule detectors (train on background, score the test period). It **cannot train or calibrate** a supervised fusion model for incident detection: there are no incident windows outside the test split, by design. With n = 1 incident, any recall figure is a single observation, not an estimate.
2. **The incident's shape was seen while defining the labels** (the sudo burst, logins without prior failures). Rules or thresholds tuned after this would be fitted to the test incident. Therefore: thresholds come only from train / validation background, rules must be justified as generic behaviour, and Org Y results will be reported as *optimistic (incident seen during labelling)*.
3. Time zone assumed UTC; the incident interval depends on it.
4. 50 test windows are `unknown` and excluded; if some of them are malicious, recall is overstated, and if benign, false-alarm rates are understated.

### 1d — AIT-LDS v2.0, scenario `russellmitchell` (slice)
**Date:** Oct 21, 2026 · **Status:** conversion DONE · windows / labels / evaluation next

**Source:** AIT Log Data Set v2.0, Zenodo record 5789064, licence **CC BY-NC-SA 4.0** (non-commercial, share-alike — derived data stays in the git-ignored `data/external/`). `russellmitchell.zip` is 7,132,670,599 bytes with 14,911 members. A simulated small company (web/intranet server, VPN, firewall with DNS, file share, mail) with employees working normally for days before a scripted multi-step attack.

**What was fetched (no full download):** the zip directory was read by HTTP range requests; **23 members** were extracted (≈18 MB over the network, ≈49 MB on disk), each CRC32-checked: `dataset.yaml`, the attacker's step timeline `attacks.log`, host/log configuration, **all 8 label files**, and the raw logs they label — intranet Apache access logs (4 rotations), intranet `auth.log` (2) and `audit.log`, firewall `dnsmasq.log`, VPN `openvpn.log`, file-share `audit.log`. (A first listing crashed on a non-ASCII member name under the Windows console; the script now writes UTF-8. `-I` mode ignores `PYTHONIOENCODING`, which is why setting it did nothing.)

**Ground truth is much better than Org Y's:** one JSON object per labelled raw line, `{"line", "labels", "rules"}`, in `labels/` mirroring `gather/`. A log with no label file has no attack lines.

**What happened in this scenario** (dataset window Jan 21 00:00 – Jan 25 00:00, UTC; from `attacks.log` and the labels):
| Time (Jan 24, UTC) | Step | Layer / log | Labelled lines |
| :--- | :--- | :--- | ---: |
| 03:01:00 | VPN login **with jhall's certificate from a new external IP**, while jhall's normal session (another IP) is still connected | identity / openvpn | 28 (1 connection event) |
| 03:01:21 | DNS brute force (414 queries in one second), then network/host discovery to 03:37 | network / dnsmasq | 414 + 92 |
| 03:56–03:57 | service scan, then `dirb` and `wpscan` against the intranet WordPress | application / Apache | 4,462 dirb + 3,186 wpscan |
| 03:58:20 | webshell upload (wpDiscuz vulnerability), then ~30 recon commands through it | application / Apache | 3 + 32 |
| 04:37 | reverse shell; web-server account `su` to jhall (password cracked offline) | endpoint / auth.log | 1 su event |
| 04:38:06 | `sudo cat /etc/shadow` as jhall; VPN disconnect at 04:38:11 | endpoint / auth.log | 2 sudo events |
| **Jan 21 00:00 → Jan 24 13:52** | **DNSteal exfiltration from internal host 10.143.0.103, labelled continuously from the first minute of the dataset** | network / dnsmasq | 53,054 lines → 17,693 query events |

**Adapters added or extended:**
| File | Change |
| :--- | :--- |
| `scripts/adapters/_common.py` | `load_line_labels`, `ait_label_path`, `LineLabeller` / `RuleLabeller` (one labelling interface for both datasets) |
| `scripts/adapters/web_server_logs.py` | `--line-labels`, configurable event-ID prefix and dataset name |
| `scripts/adapters/syslog_auth.py` | `su` events (endpoint `process_execution`, `process_name: su`, counted as privileged); `--line-labels`; ID prefix |
| `scripts/adapters/dnsmasq.py` (new) | one `network/dns_query` event per `query[...]` line; forwarded / reply / cached lines skipped and counted; target = registered domain (so 17k unique exfiltration subdomains do not become 17k entities), full name, length and label count kept in the payload |
| `scripts/adapters/openvpn.py` (new) | one `identity/user_login` SUCCESS per completed connection (user = certificate CN, source IP, assigned VPN IP); handshake, soft resets and session lines skipped and counted |
| `scripts/convert_ait_scenario.py` (new) | runs every adapter for one scenario, one output per source and host (IDs cannot collide), writes `summary.json` |

**Conversion results (real data)** — every source balances `lines = events + skipped + unparsed`, 0 contract problems:
| Source | Lines | Events | Skipped | Labelled events | Notes |
| :--- | ---: | ---: | ---: | ---: | :--- |
| Web (intranet Apache, 4 files) | 11,184 | 11,184 | 0 | 7,695 | only ~5 benign internal clients; 8,027 requests from the attacker address |
| DNS (firewall dnsmasq) | 275,900 | 81,277 | 194,623 | 17,978 | 15 query sources; 17,693 labelled queries are the exfiltration |
| VPN (openvpn) | 5,537 | 66 | 5,471 | 1 | 3 users: ahayes 31, twhite 32, jhall 3 connections |
| Auth (intranet) | 628 | 6 | 622 | 3 | 3 SSH logins, 1 su, 2 sudo |

The labelled counts were checked against an **independent recount from AIT's own label files** (every labelled line of a kind we convert must become a labelled event): web 7,695 = 7,695, DNS 17,978 = 17,978, VPN 1 = 1, auth 3 = 3.

**Tests (`test_ait_adapters.py`, 12 passed):** label-path mapping and lookup, missing label file = no attack lines, dnsmasq parsing / skip reasons / registered domain / event validity / conversion counts, OpenVPN one-login-per-connection / event validity / conversion, `su` as a privileged process, web adapter in line-label mode, and the real-data recount above. **Mutation check: 4 / 4 caught** (label lookup off by one line, registered domain cut to one label, VPN connections never emitted, `su` invoker and target swapped). Whole backend suite: **197 passed** (platform 59 + detection 138).

**What this means for the next steps:**
1. **This is the first dataset that allows an honest evaluation.** It has days of benign activity before a labelled multi-layer attack, and rules-1.1.0 was decided from Org Y *before* this data was opened. Caveat: the AIT timeline has now been read to define labels, so the incident's shape is known; thresholds will still come only from the benign days.
2. **The DNS exfiltration runs from the first minute of the data.** For that host there is no clean "normal" period, and the spec loader will (correctly) refuse it as an incident overlapping train. It needs to be handled as a separate target. Plan: evaluate it both ways and report both — (a) as is, with the contaminated baseline (realistic: nobody gets clean data), and (b) with that host's labelled windows excluded from baseline and training, disclosed as label-informed cleaning — and judge it mainly by peer comparison against the other 14 query sources.
3. **Cold-start blind spot.** jhall connected to the VPN only twice before the attack, below the 20-event minimum history, so novelty features stay 0 and RULE-IDN-003 cannot fire on the stolen-certificate login. The guard that stops false alarms on new accounts also hides misuse of rarely used accounts. To be measured, not tuned away.
4. **Cross-layer gap for attribution:** the VPN gives the intruder 10.9.0.10, but web and DNS logs see the attacker as 172.19.131.174 (translated at the firewall). Linking the VPN identity to the later activity needs NAT or firewall connection logs, which are not in this slice.
5. Only ~500 benign web requests in four days: the web layer is small, so its baselines will be thin.

### 1b (AIT) — Window labels and time-ordered splits for `russellmitchell`
**Date:** Oct 21, 2026 · **Status:** DONE

**Why the method differs from Org Y:** Org Y had no label for the compromise itself, so incident events were inferred ("notable" event inside the documented interval). AIT ships per-event ground truth, so labels now come **straight from the dataset**. `labeling.py` gained an event-label mode; the Org Y path is unchanged.

**Definitions (code: `labeling.py` → `classify_by_event_labels`, `label_windows(..., precedence)`; spec: `data/specs/ait_russellmitchell.json`, committed):**
| Term | Definition |
| :--- | :--- |
| `incident` class | Any of the 16 intrusion labels: VPN foothold, DNS / network / service scans, traceroute, dirb, wpscan, attacker HTTP, webshell upload and commands, su to jhall, sudo as jhall |
| `exfiltration` class | `dnsteal`, `dnsteal-received`, `dnsteal-dropped` (one internal host) |
| Ignored label | `attacker` — an umbrella label that in this slice sits only on the DNSteal lines (17,693 / 17,693); the class comes from the `dnsteal*` labels |
| Window label | `incident` > `exfiltration` > `background` (first class the window contains). No `unknown` class: AIT labels every attack line, so unlabelled means benign |
| Incident interval | Jan 24 03:00–04:40 — labelled intrusion events run 03:01:00 → 04:38:06, widened to window boundaries |

**Guards in the spec loader and the builder (the build stops if one fails):** classes must start with `incident`, must not share labels, must not be called `unknown` / `background`, and a label cannot be both ignored and mapped; **any label that maps to no class stops the build** (a typo in the spec cannot silently turn attack events into background); every incident event must fall inside the interval; classified + ignored-only events must equal the labelled-event total of all sources; every incident event must land in an incident window.

**Splits:**
| Split | Period (UTC) | Use | Windows | incident | exfiltration | background |
| :--- | :--- | :--- | ---: | ---: | ---: | ---: |
| baseline | Jan 21 | fit the feature baseline only (22,383 events, 22 entities) | – | – | – | – |
| train | Jan 22 | fit unsupervised models | 1,167 | 0 | 288 | 879 |
| validation | Jan 23 00:00–23:00 | calibrate thresholds on background | 1,129 | 0 | 276 | 853 |
| gap | Jan 23 23:00–24:00 | excluded | 24 | 0 | 12 | 12 |
| test | Jan 24 | evaluation | 992 | **10** | 167 | 815 |

The exfiltration host has a window in every 5-minute slot (288 per day) — it never stops.

**Two variants, built and kept side by side** (`data/external/ait/windows/russellmitchell-asis` and `-clean`, git-ignored):
- **as-is:** the baseline is fitted on everything in Jan 21, exfiltration included — what a real unsupervised system would see.
- **clean-baseline:** the 4,962 exfiltration events of Jan 21 are removed from the baseline fit using the labels (17,421 events remain). This is label-informed cleaning, **optimistic for exfiltration**, and is reported as such. Window counts are identical; only baseline-relative features differ.

**Cross-check results (real data):** 25,677 labelled events = 7,984 incident + 17,693 exfiltration, 0 unmapped labels, 0 incident events outside the interval, 0 events failing resolution; 7,984 / 7,984 incident events and 12,731 / 12,731 post-baseline exfiltration events sit in a window with their label. Build time 8.4 s.

**The 10 incident windows (all in test):**
| Window (Jan 24) | Entity | Events | What it is | What stands out |
| :--- | :--- | ---: | :--- | :--- |
| 03:00 | VPN source IP (external) | 1 | stolen-certificate VPN login | nothing — one login from an IP with no history |
| 03:00 | user jhall | 1 | the same login | nothing — jhall is cold-start (2 prior connections) |
| 03:00 | shared internal address | 143 | DNS brute force mixed with normal users' queries | volume z = 4.3, burst timing |
| 03:35 | shared internal address | 18 | end of network discovery | weak |
| 03:55 | shared internal address | **7,719** | dirb + wpscan + webshell | volume z = 269, 99% HTTP errors, endpoint entropy 12.8 bits |
| 03:55 | intranet server address | 93 | DNS lookups made by the webshell commands | volume z = 2.6 |
| 03:55 | another internal client | 13 | a few labelled DNS / web lines | weak |
| 04:35 | host intranet-server | 3 | su + 2 sudo | 3 privileged operations; host has no history at all |
| 04:35 | user jhall | 2 | sudo as jhall | 2 privileged operations |
| 04:35 | web-server account | 1 | su to jhall | 1 privileged operation |

**Correction to 1d, point 4 (found while inspecting the windows):** `172.19.131.174` is **not an attacker-only address**. It produces ~2,600–2,900 DNS queries and 300–500 web requests on *every* day, and jhall's legitimate SSH logins on Jan 21 and 23 come from it. ~~it is the firewall's NAT address for the internal user network~~ **Corrected later (Phase 1e, from the scenario's `servers.yaml`): it is the VPN server's own address — every VPN client, the attacker included, is masqueraded behind it.** Consequences: (a) attack windows on that IP are mixed with normal traffic, so only loud steps (the 7,719-event scan) stand out; (b) for attribution, "the attacker's IP" is a shared address — the causal chain has to be carried by the VPN session, user and host, not by the IP.

**Tests (`test_labeling.py`, +13 → 29 passed):** event-label spec loads without the routine-hours field; a heuristic spec without it is rejected; five bad-class specs rejected (wrong order, shared labels, reserved names, empty class, ignored-and-mapped); precedence (incident beats exfiltration), ignored-only events unlabelled, **unmapped labels surfaced**; custom window-label precedence; the committed AIT spec is valid; and a real-data check over both variants (incident windows only in test and inside the interval, every window in its split, labels never in features, counts equal the report, full label coverage). **Mutation check: 4 / 4 caught** (precedence ignored, unmapped labels dropped, class overlap accepted, window precedence reversed). Detection suite: **151 passed**.

**What this means for the evaluation (next):**
1. **10 positive windows is small.** Every recall figure moves in 10% steps; it is still one incident (n = 1).
2. **Expected easy:** the web scan (03:55) — any volume or error-rate detector will see it. **Expected hard:** the VPN login (cold start, 1 event), the DNS steps hidden in a shared NAT address, and the host privilege step (host has no history — the Isolation Forest has no host model). Rules on privileged operations are the only real chance for 04:35.
3. **Exfiltration is evaluated separately** on the 167 test exfiltration windows, both variants. fs-1.1.0 has no DNS-specific features (query length, label entropy) — the payload already carries them, so if exfiltration is missed, that is the reason to add them (fs-1.2.0), decided on validation, not test.

### Next in Phase 1
- The same slice from more AIT scenarios, for anything supervised (fusion needs more than one incident).

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

## Phase 3 — Detectors: rules (3a) and Isolation Forest (3b), first end-to-end result

**Date:** Oct 21, 2026 · **Status:** 3a DONE · 3b DONE · 3c (sequence model) not started

### In one paragraph
Both detectors now run on real data and emit contract-valid alerts. On Org Y's single real incident, a generic rule raised the first alert in the **first 5-minute window** of the incident, and the best combination caught **15 of 21** incident windows with **~48 false alarms per day**. These numbers are optimistic (one incident, seen while building the labels and one feature) and must not be quoted as detection quality. The run also exposed one real flaw in the rule calibration, which is diagnosed below and left unfixed on this test set on purpose.

### What was built
| File | What it does |
| :--- | :--- |
| `backend/app/services/detection/envelope.py` | Builds and validates the Alert Envelope (contract §4); deterministic alert IDs |
| `backend/app/services/detection/rules.py` | Rule set `rules-1.0.0` (9 rules), calibration of volume thresholds from background windows, serialisable |
| `backend/app/services/detection/anomaly.py` | Isolation Forest `iforest-1.0.0`: one model per entity type, trained on background only, ECDF scores in [0,1], per-alert explanation |
| `scripts/evaluate_org_y.py` | The evaluation protocol below; writes `data/evaluation/phase3_org_y.json` (committed, no IPs) and saves models to the git-ignored `derived/org-y/models/` |

**Contract changes made in this phase** (all written into `docs/DETECTION_CONTRACT.md`):
- **Feature set fs-1.1.0:** added `volume.login_count` and `volume.login_success_count`. Without them "a successful login" could not be expressed. **Disclosure:** added after the Org Y incident had been seen. Golden fixture regenerated and hand-checked; Org Y windows rebuilt (the leakage test flagged the stale fs-1.0.0 windows before the rebuild, as it should). Baselines from another feature set are now refused.
- Alert `technique` may also be `reconnaissance` or `unknown` (anomaly detectors); evidence items carry `op`/`threshold` (rules) or `baseline_z` (Isolation Forest).

### The rule set (rules-1.0.0)
| Rule | Behaviour | Applies to | Threshold | Severity |
| :--- | :--- | :--- | :--- | :--- |
| RULE-IDN-001 | Brute-force login burst | user, ip | ≥10 logins, ≥90% failing, ≥10 failures in a row | low |
| RULE-IDN-002 | Password spray from one source | ip | ≥5 accounts, ≥5 logins, ≥90% failing | medium |
| RULE-IDN-003 | Successful login from a never-seen source | user | ≥1 success and a source IP new to this account | high |
| RULE-IDN-004 | Successful login after repeated failures | ip | ≥1 success and ≥5 failures in a row | high |
| RULE-PRIV-001 | Privileged command burst | user, host | calibrated: max(5, 99.9th percentile of background) | high |
| RULE-PRIV-002 | Role or privilege change | user | ≥1 role change | medium |
| RULE-PRIV-003 | Privileged activity at an unusual hour | user, host | off-hours and ≥1 privileged command | medium |
| RULE-APP-001 | Web error burst (scanning) | ip | ≥20 requests, ≥50% errors | low |
| RULE-DB-001 | Bulk data read | user | calibrated: max(10,000 rows, 99.9th percentile) | high |

### Evaluation protocol (fixed before looking at any test output)
1. Rule thresholds calibrated on **background windows of train + validation only** (12,470 windows).
2. Isolation Forest trained on **train background** (11,889 windows); scores ranked against train + validation background.
3. The test split (Apr 29 05:00 → May 1; 15,752 windows, 1.81 days) scored **once**. The 50 `unknown` windows are excluded from precision and recall; alerts on them are counted separately.
4. Reported: ROC-AUC and average precision (PR-AUC), precision / recall / false alarms per day at fixed operating points, whether the incident was detected, and the delay to the first alert. Two baselines for context: random scoring and "event count only".

### Results on the test split (21 incident windows, 15,681 background)
| Detector | Incident windows caught | Precision | False alarms / day | First alert after incident start | ROC-AUC | Avg. precision |
| :--- | ---: | ---: | ---: | :--- | ---: | ---: |
| Random scoring (expected) | – | – | – | – | 0.50 | 0.0013 |
| "Event count only" baseline | – | – | – | – | 0.908 | 0.028 |
| Rules: any rule | 15 / 21 | 0.013 | 609 | 5 min | – | – |
| Rules: high severity only | 14 / 21 | 0.143 | 46 | 5 min | – | – |
| Isolation Forest (ranking) | – | – | – | – | 0.873 | 0.083 |
| Isolation Forest, score ≥ 0.99 | 7 / 21 | 0.033 | 113 | 35 min | – | – |
| Isolation Forest, score ≥ 0.999 | 3 / 21 | 0.250 | 5 | 85 min | – | – |
| **High-severity rules OR Isolation Forest ≥ 0.999** | **15 / 21** | **0.147** | **48** | **5 min** | – | – |

"5 min" = the alert is available at the end of the first incident window. Isolation Forest by entity type: host AP 0.79 (ROC 0.98, 6 incident windows), user AP 0.20 (ROC 0.99, 10), **IP AP 0.002 (ROC 0.59, 5) — no better than chance**.

Per-rule fires on the test split (validation fires in brackets):
| Rule | incident | background | unknown | (validation) |
| :--- | ---: | ---: | ---: | ---: |
| RULE-IDN-001 brute-force burst | 10 | 1,002 | 5 | (98) |
| RULE-IDN-002 password spray | 0 | 301 | 0 | (2) |
| RULE-IDN-003 success from never-seen source | 5 | **0** | 9 | (0) |
| RULE-PRIV-001 privileged command burst | 11 | 84 | 1 | (8) |
| RULE-PRIV-003 privileged at unusual hour | 2 | 5 | 0 | (1) |
| IDN-004, PRIV-002, APP-001, DB-001 | 0 | 0 | 0 | (0) — nothing of that kind in this data |

### What the numbers mean
1. **The incident was detected quickly, but by a rule whose input was added after seeing it.** RULE-IDN-003 (successful login from a source the account never used) fired on the first incident window with zero background false alarms. It is a standard detection, but its feature was added after the incident was seen, so this is a demonstration, not evidence.
2. **The brute-force alerts are not wrong, they are just not the incident.** RULE-IDN-001/002 raised 1,303 alerts (~720/day) on windows labelled `background`. Those windows really are hostile brute force; they are "background" only because our target is the compromise. This is exactly the alert-fatigue problem: real but low-value alerts drowning the one that matters. Phase 4 must aggregate and suppress them (one alert per source per period), not delete the rules.
3. **Flaw found in rule calibration (RULE-PRIV-001).** 82 of its 84 background false alarms have exactly 19 privileged commands. That is root's routine hour: 18 cron log reads + 1 hourly root job, all in the :00 window. The calibrated threshold was the background maximum (19) and the rule fires at "≥", so **every routine hour fires**. The validation split already showed this (8 fires in 4 background hours), but the protocol had no validation gate to stop it. **Not fixed here**: changing it and re-scoring the same incident would be tuning on the test set. Post-hoc diagnosis only: at "strictly above 19" the rule would have fired on 10 incident and 2 background test windows.
4. **Anomalous is not the same as malicious.** On this internet-facing server the "normal" IP is a brute-forcer hammering hundreds of attempts, so the Isolation Forest learns that hammering is normal — correctly. The intruder's IP logged in quietly once or twice, which is *not* anomalous in volume terms (IP ROC 0.59). The model is useful where the incident is a behaviour change on a host or account (privileged-command burst: host AP 0.79, user ROC 0.99).
5. **ROC-AUC misleads under this imbalance (21 positives in 15,702).** "Event count only" has a higher ROC-AUC (0.908) than the Isolation Forest (0.873), yet a third of its average precision (0.028 vs 0.083). Average precision and false alarms per day are the numbers to watch; this is why the plan bans an accuracy headline.
6. **Isolation Forest scores saturate.** Windows outside the training range get isolated at almost the same depth, so extreme windows tie near 1.0. Seen in a unit test (an extreme outlier scored 0.9967 against a fresh reference set) and in the top-10 list (several background windows at 0.9995–1.0).

### Problems found during this phase and what was done
| Problem | Found by | Action |
| :--- | :--- | :--- |
| Calibrated threshold equal to the routine maximum fires every routine hour | Test-split result; already visible on validation | Diagnosed and recorded; fix planned for rules-1.1.0, to be judged on unseen data (AIT), not on Org Y |
| No way to express "successful login" | Writing RULE-IDN-003 | fs-1.1.0 (+2 features), disclosed as post-incident |
| Stale fs-1.0.0 windows after the feature change | `test_labeling` real-data check | Windows rebuilt; labels unchanged (21 incident, 50 unknown) |
| Isolation Forest score saturation | Unit test expected exactly 1.0 | Test now requires ≥ 0.99; behaviour documented |

### Tests
| Suite | Tests | Result |
| :--- | ---: | :--- |
| `test_rules.py` — every rule has a firing case and a near-miss; entity-type filtering; nearest-rank quantile; floor vs calibrated threshold; refusal to run uncalibrated; envelope validity, deterministic IDs, round trip, contract violations caught | 21 | passed |
| `test_anomaly.py` — log transform, outlier vs background, determinism and input-order independence, no model for tiny types, explanations, alerts respect the threshold, reference set, metadata | 8 | passed |
| `test_phase3_results.py` — committed results are arithmetically consistent, limits are attached, AP beats random, and **re-running the evaluation reproduces the committed file exactly** | 5 | passed |
| `test_features.py` — +1 (baseline from another feature set refused), login counts checked by hand | 30 | passed |
| Detection total / whole backend | 126 / 185 | **all passed** |

**Mutation check: 8 / 8 caught** — entity-type filter removed, calibration floor ignored, "≥" treated as ">", quantile rank off by one, log transform removed, minimum-training-size check removed, explanations sorted the wrong way, training order not normalised.

### Decisions carried into the next steps
- **rules-1.1.0:** calibrated thresholds must be strictly above everything seen in background (plus a margin), and a **validation gate**: a rule that fires on more than 0.5% of validation background windows is flagged before any test scoring. Judged on AIT, not by re-scoring Org Y.
- **Fusion (Phase 4)** must aggregate repeated brute-force alerts per source and time, and combine the strong signals (success from a new source, privileged burst, host/user anomaly scores). Supervised fusion needs labelled incidents outside the test split, so it needs AIT.
- The Isolation Forest stays as a host/account behaviour-change detector; IP-level anomaly scores are not useful on noise-dominated servers.

---

## Phase 3 (continued) — rules-1.1.0 and the first unseen evaluation (AIT `russellmitchell`)
**Date:** Oct 21, 2026 · **Status:** DONE

### In one paragraph
On the first dataset the detectors were not built around, the system catches **the loud part of the attack and nothing else**. At fixed operating points it flags 1 of 10 incident windows (the 7,719-request web scan at 03:55), with **0 false alarms in a full day**, first alert 60 minutes after the intrusion began. It misses the stolen-certificate VPN entry, the DNS discovery and the privilege escalation, and it misses the exfiltration completely. The reasons are specific and measurable (cold start, a shared NAT address, Isolation Forest saturation, no DNS features), and none of them was tuned away after seeing the result.

### What was built
| File | What it does |
| :--- | :--- |
| `backend/app/services/detection/rules.py` | **rules-1.1.0** (now the default) next to rules-1.0.0, selected by `RuleEngine(ruleset=...)`; `CalibrationPolicy`; `gate()` (validation gate); disabled rules stay silent unless `include_disabled=True`; `to_dict` / `from_dict` carry the rule set, ops, gate and disabled rules |
| `backend/app/services/detection/evaluation.py` (new) | shared metrics for one *task* (positive label vs background, other labels excluded): `operating_point`, `task_ranking`, `ranking_metrics`, `latency_minutes` |
| `scripts/evaluate_ait.py` (new) | the AIT protocol below; per-rule, per-window and per-stage tables; saves models to a git-ignored folder |
| `scripts/evaluate_org_y.py` | pinned to `rules-1.0.0` (the rule set its committed result was produced with) — the reproduction test still passes byte-for-byte |
| `data/evaluation/phase3_ait_russellmitchell_{asis,clean}.json` | committed results (entity IDs are hashes; checked: no IP addresses or user names) |

### rules-1.1.0 (decided on Org Y before AIT was opened)
| | rules-1.0.0 | rules-1.1.0 |
| :--- | :--- | :--- |
| Calibrated bound | 0.999 quantile of background | background **maximum × 1.25** |
| Comparison | `>=` (a tie with the routine maximum fires) | strictly `>` the bound; the floor stays an inclusive minimum (`>=`) |
| Validation gate | none | calibrate on **train**, then any rule firing on **> 0.5 %** of validation background windows is turned off before the test |

### Evaluation protocol (fixed in code before the test split was scored)
- **Training pools.** *as-is*: every train / validation window, no labels used before the test (the exfiltration is inside, as it would be in production). *clean-baseline*: the same minus exfiltration windows (label-informed, disclosed).
- **rules-1.1.0** (primary): calibrate on train pool → gate on validation pool → score test once. **rules-1.0.0** (comparison): calibrate on train + validation, no gate.
- **Isolation Forest:** fit on train pool, ECDF reference train + validation.
- **Two tasks:** incident vs background (exfiltration excluded) and exfiltration vs background (incident excluded). An alert on the other attack class is reported, never counted as a false alarm.
- **Stages:** each incident window is mapped from its AIT step labels to entry / discovery / web attack / privilege; a stage is detected if any of its windows is flagged.

### Results (test = Jan 24, 992 windows: 10 incident, 167 exfiltration, 815 background)
**Incident task** — identical for both variants except the Isolation Forest false alarms:
| Decision | Incident windows flagged | False alarms / day | Stages detected |
| :--- | ---: | ---: | :--- |
| rules-1.1.0, any rule | 1 / 10 | 0 | web attack (discovery counted only because the same window holds the service scan) |
| rules-1.1.0, high severity | 0 / 10 | 0 | — |
| rules-1.0.0, any rule | 1 / 10 | 0 | same as 1.1.0 |
| Isolation Forest ≥ 0.99 | 1 / 10 | 1 (as-is) · 3 (clean) | web attack |
| Isolation Forest ≥ 0.999 | 0 / 10 | 0 | — |
| rules-1.1.0 any OR IF ≥ 0.999 | 1 / 10 | 0 | web attack |

| Ranking (incident) | ROC-AUC | Average precision |
| :--- | ---: | ---: |
| Isolation Forest, all windows (as-is / clean) | 0.563 / 0.602 | 0.092 / 0.093 |
| Isolation Forest, **IP windows only** (as-is / clean) | **0.932 / 0.938** | 0.146 / 0.146 |
| Event count only (baseline) | 0.536 | 0.130 |
| Random | 0.5 | 0.012 |

**Exfiltration task** — no decision flags a single exfiltration window in either variant.
| Ranking (exfiltration) | ROC-AUC | Average precision |
| :--- | ---: | ---: |
| Isolation Forest, as-is | **0.076** (worse than random) | 0.094 |
| Isolation Forest, clean-baseline | 0.882 | 0.480 |
| Event count only | 0.631 | 0.245 |
| Random | 0.5 | 0.170 |

**Validation gate:** every rule fired on 0 % of validation background — nothing was turned off. rules-1.0.0 and 1.1.0 give the same result here: AIT has no cron-driven sudo, so the tie problem never arises.

### Why each stage was missed (from the per-window table)
| Stage | Windows | Why nothing fired |
| :--- | ---: | :--- |
| Entry (VPN login with stolen certificate) | IP 1 event, user 1 event | jhall has 2 prior VPN logins (< 20): cold start, so `novelty.new_source_ip` stays 0 and RULE-IDN-003 cannot fire. No user model in the Isolation Forest (13 training windows < 20). The IP window scored 0.983 but ties with ordinary single-login windows |
| Discovery (DNS brute force, network scan) | 5, mostly on the shared NAT address | mixed with normal users' queries on the same address (volume z = 4.3 at most); no rule covers DNS |
| Web attack (dirb, wpscan, webshell) | 2 | **caught** by RULE-APP-001 (low severity) on the 7,719-event window; the 13-event window is not |
| Privilege (su, sudo cat /etc/shadow) | host 3 ops, user 2, user 1 | RULE-PRIV-001 needs ≥ 5 privileged ops (floor); RULE-PRIV-003 needs a warm entity for "off hours" and the host has **no history at all**; no host or user model in the Isolation Forest |
| Exfiltration | 167 | as-is: it is 25 % of the IP training windows, so the model learns it as normal (ROC 0.08). Clean: ranked well (0.88) but never above 0.99. fs-1.1.0 has no DNS features (query length is the obvious tell: 203 characters on the first exfiltration query) |

### Problems found and what was done
| Problem | How found | Action |
| :--- | :--- | :--- |
| **Isolation Forest saturates beyond the training range:** the 7,719-event window scores 0.998, tied with an ordinary evening window, because splits are drawn inside the training range — "far beyond" and "just beyond" land in the same leaf | top-10 table | Recorded. Not fixable inside the Isolation Forest; it argues for fusing it with measures that do extrapolate (peer z-scores, rule hits) in Phase 4 |
| **Cold start silences the start and the end of the attack** (jhall: 2 logins; intranet host: 0 events before the test) | per-window table | Recorded, not tuned. Candidate: a cohort comparison for entities without history, and "first-ever privileged operation", decided on this scenario and judged on others |
| Unmodelled windows get score 0 in the ranking, which pulls the all-window ROC down (0.93 on IP windows → 0.56 overall) | per-type ranking | Both figures reported; fusion must treat "no model" as missing, not as "normal" |
| rules-1.0.0 evaluator would silently pick up the new default | full test suite (Org Y reproduction) | `evaluate_org_y.py` pinned to `rules-1.0.0` |

### Tests
| File | Count | What is covered |
| :--- | ---: | :--- |
| `test_rules.py` | 29 (+8) | every rule fires / near miss under rules-1.1.0; 1.0.0 thresholds unchanged; 1.1.0 bound = max × 1.25 with `>`, floor stays `>=`; **a tie with the background maximum fires in 1.0.0 and not in 1.1.0** (the Org Y flaw); floor fallback for both rule sets; unknown rule set rejected; gate disables only the over-budget rule with the right counts, disabled rules silent unless asked, widened budget, recalibration clears the gate, 1.0.0 has no gate; round trip keeps rule set, ops and disabled rules |
| `test_evaluation.py` (new) | 7 | task subsets, operating-point counts and rates, alerts on another attack class not counted as false alarms, empty decisions, length check, ranking ignores excluded labels, latency |
| `test_phase3_ait_results.py` (new) | 10 | for both variants: limits travel with the numbers; every operating point is arithmetically consistent; stage coverage agrees with the per-window table; gate report agrees with disabled rules; **re-running the evaluation reproduces the committed file exactly** |

**Mutation check: 6 / 6 caught** (strict bound made inclusive, margin dropped, gate comparison changed, disabled rules still firing, alerts on another class counted as false alarms, task subset keeping every label). Whole backend suite: **235 passed** (platform 59 + detection 176).

### What this means
1. **This is the honest baseline of the system** on unseen data: precise (0 false alarms per day), low recall (1 of 4 stages). Org Y's 15 / 21 was flattered by one loud, seen incident.
2. **`russellmitchell` is now a development scenario.** Its results have been seen, so any change made from here (cold-start handling, DNS features, fusion) must be judged on *other* AIT scenarios. Getting them is the next step.
3. The Isolation Forest is useful as a **ranker inside one entity type** (ROC 0.93 on IP windows), not as a stand-alone alarm. That is a fusion input, which is how the plan uses it anyway.

---

## Phase 1e — Multi-scenario AIT corpus (all 8 scenarios) and the development / held-out split
**Date:** Oct 21, 2026 · **Status:** DONE

### Why
One intrusion cannot calibrate or train anything, and `russellmitchell`'s results have been seen. AIT-LDS v2.0 has **8 scenarios** (different companies, dates, users, address plans, attack timings) with the same labelled attack template. They give 8 independent incidents and a clean protocol:
- **Development scenarios: `russellmitchell`, `fox`.** Detector output may be looked at; every design change is decided here.
- **Held-out scenarios: `harrison`, `santos`, `shaw`, `wardbeck`, `wheeler`, `wilson`.** Converted and integrity-checked only. **No detector is run on them until the design is frozen and committed**; then the frozen system is scored once.

### What was built
| File | What it does |
| :--- | :--- |
| `scripts/fetch_remote_zip.py` (new, replaces a scratch tool) | Reads a remote zip by HTTP range requests, CRC-checked, path-safe. `ait-slice` fetches the standard slice: metadata, attacker timeline, and the web (Apache access), auth, DNS and VPN logs of the **company's** hosts with their label files. 25–52 MB per scenario out of 7–27 GB zips |
| `scripts/make_ait_spec.py` (new) | Writes each scenario's spec from its own `dataset.yaml` + `attacks.log` with **one rule for all**: incident = first VPN connect → last VPN disconnect (window-aligned); baseline = day 1, train = following days, validation = the day before the incident (to 23:00), gap = its last hour, test = incident day → end. Reproduces the hand-written `russellmitchell` spec exactly |
| `scripts/adapters/ait_assets.py` (new) | Asset inventory of the company's hosts from `servers.yaml` (hostname, addresses, FQDNs, groups → criticality 4 for servers, 2 otherwise). Needed by correlation / attribution to link layers |
| `scripts/convert_ait_scenario.py` | Converts **company hosts only**; web logs per host (`web-<host>`, IDs cannot collide) |
| `scripts/build_ait_corpus.py` (new) | Per scenario: convert → assets → spec → windows (as-is and clean) → `corpus_report.json` (integrity checks only, no detector) |
| `data/specs/ait/<scenario>.json` | The 8 generated specs (committed). The hand-written Phase 1b spec `data/specs/ait_russellmitchell.json` is kept as it was |

### Problems found and fixed
| Problem | How found | Fix |
| :--- | :--- | :--- |
| **"Company host" by address was wrong.** The first rule treated 192.168.0.0/16 as AIT's simulated internet. True in 3 scenarios by coincidence; in `harrison`, `santos`, `shaw` and `wheeler` the internet sits elsewhere, so the attacker, external users and internet DNS were kept **and the intranet server, firewall DNS and internal share were dropped** | the fetch log listed `attacker_0` as a company host | Rule by **role name** instead (AIT names roles consistently: `attacker_N`, `ext_user_N`, `remote_employee_N`, `inet-dns`, `<name>_mail`; the company mail server is plain `mail`). Stray internet-host files removed (listed one by one), the 4 slices re-fetched with `--resume`. 20 tests pin the rule |
| `wheeler`'s attacker used **two VPN sessions** (07:35–07:57 recon + web shell, offline password cracking, 17:51–17:52 privilege step) | the spec generator refused it (it expected one session) | Rule generalised to alternating sessions, first connect → last disconnect (10 h 20 min incident; windows between the sessions stay background unless labelled). Unbalanced or out-of-order sessions are still refused |
| The corpus builder overwrote the hand-written `ait_russellmitchell.json` | the provenance test noticed | Generated specs live in `data/specs/ait/`; the hand-written file restored from git |
| `servers.yaml` list parsing returned nothing (`^  {2}-` matched 3 spaces, not 4) | empty groups in the first inventory | Regex fixed; parser tests added |

**Facts learned from `servers.yaml`:** `172.19.131.174` in `russellmitchell` is the **VPN server** (correcting Phase 1b, which called it the firewall NAT); the exfiltration source `10.143.0.103` is the internal **file share**; the web shell's DNS lookups come from the **intranet server** (`10.143.2.4`); every host is configured `timezone: UTC` (confirms the timestamp assumption).

### The corpus (every scenario: line accounting balanced, 0 contract problems, every incident and exfiltration event inside a window with its label)
| Scenario | Role | Company hosts | Events | Incident events | Incident (UTC) | Test windows: incident / exfiltration / background |
| :--- | :--- | ---: | ---: | ---: | :--- | :--- |
| russellmitchell | development | 12 | 157,189 | 7,984 | Jan 24 03:00–04:40 | 10 / 167 / 1,153 |
| fox | development | 13 | 586,398 | 411,036 | Jan 18 11:55–13:15 | 14 / 0 / 2,100 |
| harrison | held-out | 11 | 639,548 | 415,565 | Feb 08 07:05–08:40 | 17 / 112 / 1,023 |
| santos | held-out | 17 | 237,879 | 8,043 | Jan 17 11:15–12:00 | 9 / 0 / 1,631 |
| shaw | held-out | 13 | 244,029 | 5,391 | Jan 29 14:35–15:25 | 8 / 0 / 2,842 |
| wardbeck | held-out | 14 | 275,564 | 5,542 | Jan 23 12:10–13:00 | 8 / 0 / 1,552 |
| wheeler | held-out | 16 | 727,973 | 431,748 | Jan 30 07:35–17:55 (2 sessions) | 13 / 0 / 1,388 |
| wilson | held-out | 15 | 851,789 | 428,383 | Feb 07 10:55–11:50 | 13 / 0 / 3,831 |
| **total** | | | **3,720,369** | **1,713,692** | 8 intrusions | **92 / 279 / 15,520** |

Integrity (`data/evaluation/ait_corpus_report.json`): all 8 scenarios × 2 variants — line accounting balanced, 0 contract problems, 100 % label-to-window coverage. Exfiltration falls in the test day in only 2 scenarios (`russellmitchell`, `harrison`); elsewhere it stops earlier.

The huge incident counts (fox, harrison, wheeler: > 400,000) are `dirb` runs of ~400,000 requests; elsewhere the scan was short. Every incident has exactly 1 host window and 3–4 user windows (VPN login, su, sudo) — the same attack template, which is why held-out results generalise to *this attack family*, not to attacks in general.

---

## Phase 3d — fs-1.2.0 and rules-1.2.0, designed on the development scenarios
**Date:** Oct 21, 2026 · **Status:** DONE (frozen before any held-out scenario was scored)

### What the development scenarios showed (rules-1.1.0 + fs-1.1.0)
Both caught only the web scan. Per-window inspection gave four causes, each generic:
1. **History frozen at day 1.** The baseline was fitted on the first day and never updated, so a user first seen on day 2 was "unknown" for ever.
2. **The 20-event warm-up hid stolen credentials.** In `fox` every VPN user always connects from one fixed address; the attacker logs in as `bpotter` from a new one, but `bpotter` has only 4 logins, so source-IP novelty was never computed.
3. **No feature for a web shell's privilege steps.** It is `www-data` running `su`, then `sudo cat /etc/shadow`.
4. **No DNS features** (tunnelling packs data into 100–250-character names).

### Changes
| Change | Detail |
| :--- | :--- |
| Rolling history (`features.update_history`) | Each day is scored against everything seen before it; cohort statistics stay those of the fitted period. Both window builders use it |
| Login-history gate | `novelty.new_source_ip` needs `min_login_history` = 3 prior successful logins (failed logins do not count), not the 20-event warm-up. Other novelty / off-hours features stay cold |
| fs-1.2.0 (+4 features, 28 total) | `privilege.service_account_ops`, `privilege.credential_file_access`, `dns.distinct_names`, `dns.long_names` (≥ 100 characters). Contract §3.1 / §3.2 updated |
| rules-1.2.0 (+3 rules, 12 total) | RULE-PRIV-004 service account switching user / using sudo (high, T1548); RULE-PRIV-005 credential file accessed (high, T1003.008); RULE-NET-002 ≥ 10 long DNS names in a window (high, T1071.004) |
| Gate: persistent findings | A rule over the 0.5 % budget whose validation fires all sit on ≤ 2 entities stays **on**, and those entities are reported as persistent findings. In `russellmitchell` as-is, the tunnelling rule fired on 25 % of validation windows — all from the one exfiltrating file share. 1.1.0's gate turned it off (the compromise looked like noise); 1.2.0's keeps it on |
| Tried and dropped | RULE-NET-001 "DNS enumeration burst" (calibrated distinct names): the brute force gave 137 / 155 distinct names in its window, ordinary busy windows of the same shared address 153–233 → 0 of 2 caught, 2 false alarms. The signal is a one-second burst that a 5-minute count blurs. ID retired |
| iforest-1.1.0 | Same model, fs-1.2.0 inputs |
| Versioning | Old results stay as historical records; their reproduction tests now skip with the reason (produced by fs-1.1.0) instead of being overwritten |

### Development results (in-sample: these scenarios shaped the change)
| Scenario | Rule set | Incident windows | Stages (entry / discovery / web / privilege) | False alarms / day | First alert | Exfiltration windows |
| :--- | :--- | ---: | :--- | ---: | ---: | ---: |
| russellmitchell | rules-1.1.0 (fs-1.1.0, Phase 3) | 1 / 10 | – / – / ✓ / – | 0 | 60 min | 0 / 167 |
| russellmitchell | **rules-1.2.0** | **5 / 10** | ✓ / ✓* / ✓ / ✓ | **0** | **5 min** | **167 / 167** (as-is and clean) |
| fox | rules-1.1.0 (fs-1.1.0) | 5 / 14 | – / ✓* / ✓ / – | 0.5 | 25 min | – |
| fox | **rules-1.2.0** | **9 / 14** | ✓ / ✓* / ✓ / ✓ | 0.5 | **5 min** | – |

\* Discovery is credited only because the web-scan windows also contain the service scan; no rule detects the DNS brute force or the host discovery themselves.

The Isolation Forest at ≥ 0.999 still flags no incident window (saturation, Phase 3); within IP windows it ranks well and is used as a fusion input.

### Tests and checks
New: rolling history, the login-history gate (both sides of the limit, failed logins excluded, round trip), the four features (case and path handling, name normalisation, the 100-character limit), rules-1.2.0 cases, rule lists per version, the persistent-finding gate (kept on 1 entity, disabled across 3, 1.1.0 still disables). Golden fixture regenerated and hand-checked: only the 4 new features differ (all 0 except one DNS name on one IP window). **Mutation check: 8 / 8 caught** (login gate removed, failed logins counted, history not rolled, case-sensitive service accounts, DNS names not normalised, long-name limit moved, persistent rule disabled anyway, entity concentration ignored).

---

## Phase 4 — Fusion, calibration, alert-fatigue controls (design; final evaluation pending)
**Date:** Oct 21, 2026 · **Status:** design frozen on the development scenarios; leave-one-scenario-out over all 8 next

### What was built
| File | What it does |
| :--- | :--- |
| `backend/app/services/detection/fusion.py` (new) | 16 fusion inputs (rule hits by severity, IF score + "no model" flag, 8 key features, entity type) → logistic regression (C = 0.1; HistGradientBoosting challenger) → isotonic calibration on out-of-fold predictions (leave-one-scenario-out inside the training scenarios) → τ_alert (lowest confidence with out-of-fold precision ≥ 0.8) and τ_review (keeps 90 % of hostile windows) → alert / review / suppress → Fused Alerts (contract §5): repeats of one entity within 30 minutes folded, `suppressed_duplicates` counted. Explanations: coefficient × standardised input |
| `scripts/evaluate_ait.py --dump-windows` | Writes every scored test window (label, stages, rule hits, IF score, features); each scenario's detectors are calibrated on its own earlier days, so these outputs are out-of-sample |
| `scripts/evaluate_fusion.py` (new) | Leave-one-scenario-out: fusion trained on the other scenarios, the held-out scenario scored once. Reports ranking vs each single detector, calibration (ECE, Brier, reliability bins), decisions, recall per class and stage, alerts per day before / after folding |

### Development check (train on one development scenario, test on the other)
| Fusion version | Tested on | Hostile windows at "alert" | False alarms | Rules alone (any) |
| :--- | :--- | ---: | ---: | :--- |
| unweighted, C = 1 | russellmitchell | 171 / 177 | 0 | 172 / 177, 0 FA |
| unweighted, C = 1 | fox | 9 / 14 | **120** | 9 / 14, 1 FA |
| **weighted, C = 0.1 (frozen)** | russellmitchell | 172 / 177 | 0 | 172 / 177, 0 FA |
| **weighted, C = 0.1 (frozen)** | fox | 4 / 14 | 5 | 9 / 14, 1 FA |

What went wrong and what was changed: `russellmitchell`'s hostile windows are 94 % one exfiltration stream, so a model trained there learnt mostly that stream, and an alert threshold set inside one scenario (0.06) did not transfer. **Fix:** every (scenario, label) group gets equal training weight; stronger regularisation; calibration and thresholds stay unweighted so confidence matches real frequencies. With one training scenario fusion still does not beat the rules — reported as is; the real test is leave-one-out over 7 training scenarios.

**Pre-registered pipeline decision (before any held-out score): rules first.** A high-severity rule hit → alert; any other rule hit → at least review; otherwise fusion decides. Fusion may add alerts and reviews, never silence a rule. Pure fusion and the pipeline decision are both reported.

---

## ML strategy (decision recorded Oct 21, 2026)

Recorded in `docs/DETECTION_PLAN.md` §4A. Summary: baseline-relative features → Isolation Forest per subject type (trained on normal only) → n-gram sequence model → **supervised logistic-regression fusion** (gradient boosting as challenger) → isotonic calibration with an abstain band. Evaluation splits by scenario run, includes leave-one-attack-class-out and ablations, and reports PR-AUC, per-class precision/recall, ECE/Brier and alerts per analyst per day — never accuracy. All of it depends on a labelled data source (Phase 1 decision).

---

## Next

1. **Held-out evaluation** of the frozen detectors (fs-1.2.0, rules-1.2.0, iforest-1.1.0) on the 6 held-out scenarios, once.
2. **Phase 4 final:** fusion leave-one-scenario-out over all 8 (design frozen), calibration artefact, alerts per day before / after.
3. **Phase 5 correlation** using the asset inventories (address → host, FQDN → host) to link the VPN login, the web / DNS activity and the privilege steps into one incident; **Phase 6 attribution** (entry point, path, reach).
3. **Phase 3c — sequence model** (order of actions per entity), kept only if it catches something rules and the Isolation Forest miss.
4. **Phase 4 — fusion, calibration and alert aggregation** (brute-force alerts per source → one; abstain band).
