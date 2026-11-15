# Product readiness audit (Milestone 1)

**Date:** 2026-11-15. **Commit audited:** `090a780` (main, after PR #23, prompt fix 3 / m5-v4).
**Where:** the Linux cloud container of this session. It has the code and the committed synthetic
samples only: **no real AIT-ADS files, no ATT&CK bundle, no SigmaHQ rules, no bge-small cache, no
Ollama model, no Docker services**. Anything that needs those is marked *Unverified here* and points
at the evidence recorded on the Windows machine (`docs/session-notes.md`, `results/PILOT_GATE.md`).
No code was changed for this audit.

Status words: **Verified** = implemented and exercised in this audit (tests or a run);
**Partial** = implemented with known gaps; **Missing** = not implemented; **Unverified** = code
exists, not established here that it works.

## 1. What was run

| check | command | result (actual output) |
|---|---|---|
| backend tests | `pytest -q` in `backend/` | **525 passed, 12 skipped** in 21.2 s |
| backend types | `mypy` (strict) | **no issues, 90 source files** |
| frontend tests | `npm test` (`node --test src/lib/*.test.ts`) | **80 tests, 80 pass, 0 fail** |
| frontend types | `npm run typecheck` | exit 0 |
| frontend build | `npm run build` | ok, 526 ms; main chunk 518.9 kB (Vite warns > 500 kB) |
| stack start | API + Vite on the synthetic store (earlier in this session) | sign-in and Overview render, 0 console errors |
| API walk | TestClient over a copy of the synthetic store (script below) | every expected status code (table in 4.2) |

The 12 skips: 8 need real files (AIT-ADS x4 incl. the real-data leak test, ATT&CK bundle x2,
bge-small x1, SigmaHQ rules x1) and 4 need docker-compose services (PostgreSQL x2, OpenSearch,
Kafka). The last recorded Windows figure (before PR #23) is 532 passed, 4 skipped. This run's
525 includes the 1 test added in PR #23, so 525 + 8 data tests = 533 = 532 + 1: consistent, but
the Windows figure was not re-run. **The infra tests (PostgreSQL, pgvector,
OpenSearch, Kafka, MinIO) have never run anywhere** (`SENTINEL_TEST_*` never set; Docker
Desktop was broken on the Windows machine, PROGRESS.md).

Checking the claims from the project presentation:

| claim | verdict |
|---|---|
| FastAPI backend, React + TypeScript frontend | Verified (ran both) |
| SQLite with PostgreSQL support | SQLite Verified; PostgreSQL **Unverified** (integration tests never ran) |
| Wazuh, Suricata, AMiner ingestion | Verified on the synthetic sample (9 alerts: 3 / 2 / 4); real-file test skipped here, recorded passing on Windows |
| ATT&CK v20.1 mapping | Unverified here (bundle absent); synthetic 3-technique bundle tests pass |
| Sigma detection | Engine Verified on synthetic tests; real rules absent here |
| HistGB and IsolationForest | Verified as **offline evaluation code** only (see 3.2) |
| BM25 + dense RAG with bge-small | BM25 / hybrid logic Verified (HashEmbedder double); bge-small Unverified here |
| single agent and LangGraph multi-agent | Verified with FakeClient; real-model behaviour only from the Windows pilot records |
| deterministic evidence verification | Verified (tests) |
| Ollama with Qwen 2.5 7B | Unverified here (no model); recorded on Windows (digest `27d8d9d16c31`) |
| JSON, CSV, PDF reports | Verified (API walk: 2,183 B JSON, 223 B CSV, 4,600 B PDF) |
| human approval workflow | Verified (API walk, four-eyes, execute once) |
| 532 backend / 80 frontend tests passing | Frontend 80/80 Verified. Backend 525 here; 532 is plausible on Windows, not re-run |

## 2. Feature-by-feature status

| # | Feature | Status | Evidence | Problem | Required action |
|---|---|---|---|---|---|
| 1 | Multi-source ingestion (Wazuh / Suricata / AMiner) | **Verified** (synthetic) | `alert_pipeline.py`, `ingestion/`, `test_alert_pipeline.py`, `test_alert_normalizer.py`; ingest of the sample: 9 alerts, 9 event labels linked | Only replay of AIT-ADS files; no live collector (Beats/Logstash documented, not built). CSV/JSON event loader (`pipeline.py`) is separate from the alert platform | Acceptable for the MVP; say "dataset replay" in the paper and demo (already done in the UI) |
| 2 | Normalization + storage | **Verified** (SQLite) / PostgreSQL **Unverified** | `storage/`, migrations 0001-0003, `test_platform_storage.py`, health `database: sqlite` | PostgreSQL/OpenSearch/Kafka/MinIO paths never executed against real services | Either run `docker compose --profile lite` once and the 4 infra tests, or describe them as "interfaces, not tested" |
| 3 | Rule-based detection (Sigma) | **Partial** | `detection/sigma_engine.py`, `test_sigma_engine.py`; recorded: 256 rules, 90 compile, 166 skipped by reason; **2 rules fire** (russellmitchell 6,387 alerts, shaw 1,468) | Root cause (from the code, see 3.1): Sigma sees **only log lines that another detector already alerted on** (no raw log stream, AIT-LDSv2 not used by user decision), so it is a re-detection pass over the pool, not an independent detector | Milestone 2: per-rule applicability report on the real rules; decide whether to add the raw-log input |
| 4 | ML detection / anomaly analysis | **Partial** | `detection/features.py`, `ml_baselines.py`, `test_ml_baselines.py`; recorded F1 (event_label, HistGB): cross rm->shaw 0.896, shaw->rm 0.970; LOPO shaw 0.179 | **Evaluation only**: no saved model, no `predict` path, no ML score on any stored alert, nothing in the API/UI. `host_count_60s` dominates permutation importance (0.72 / 0.46); recall on unseen phases near 0 (shaw dirb 0.0066, rm privilege_escalation 0.0000) | Milestone 2: (a) confirm the burst-rate dependence and report it as a finding; (b) add logistic regression / random forest only as a reasoned comparison; (c) if ML is to be a product feature, persist a model and attach scores as *detections*, not incidents |
| 5 | Alert triage | **Verified** | `detection/triage.py` severity table H1-L1, each row tested (`test_triage.py`) | Severity is a first-match table, no "confidence"; Sigma/ML not part of the default triage input | Fine for the MVP |
| 6 | Incident correlation | **Partial** | union-find over entities with a 300 s gap and a 3,600 s span cap; incidents keep alert ids + timeline (`test_triage.py`, API walk) | Entities are **host IP and source IP only**: no user, process, destination or detection-reference links. No per-incident correlation rationale or confidence. Largest dev incidents are 11,208 / 6,003-alert single-source bursts | Milestone 3: add user / destination entities **where the alert carries them**, write a rationale per merge (which entity, gap), keep "never invent links" |
| 7 | MITRE ATT&CK integration | **Partial** | `intel/attack.py`: Wazuh native `rule.mitre.id`, Sigma tags, `RULE_TABLE`; `test_intel.py` | Suricata and AMiner alerts carry no technique (by design: no guessing) | Keep; report coverage per detector |
| 8 | RAG knowledge retrieval | **Partial** | `rag/` + `agent/rag_tool.py`; frozen 25-query set; recorded recall@1/3/5 dense 0.28/0.48/0.56, hybrid 0.48/0.68/0.68 | Recall numbers are on a small set already tuned against (alpha fixed a priori, but the set was seen). ATT&CK v20.1 bundle has **no detection text**. **RAG is only in the graph arm** (see critical issue C1). LLM-with vs without RAG **never measured** | Milestone 4: re-run `rag-eval` on Windows, failure list per query, a no-RAG vs RAG comparison designed before running |
| 9 | Multi-agent investigation (LangGraph) | **Partial** | `agent/graph.py`: supervisor + 6 agents (log_analysis, correlation, knowledge_retrieval, anomaly_analysis, investigation, report_generation) + verifier node; FakeClient tests for every edge, budget and failure path | **Study-only: no API route or UI runs the graph** (the copilot runs the single agent). Pilot (m5-v3): graph oracle 3/7 and 5/7, fused 4/7 and 1/7 vs single 5/7 and 6/7; H1 graph vs single -0.43 (PILOT). No structured fact / hypothesis / conclusion separation in the output (only verdict + findings + claims) | Milestone 5/6: expose the graph in the product (investigation run + stored trace), keep the study runner unchanged |
| 10 | Evidence verification | **Verified** | `agent/verifier.py`, tests; applied to both arms and to copilot answers | Checks citations and claims against the alert record and its log lines only; cannot check knowledge claims (ATT&CK statements) | Document the scope; Milestone 4 adds source ids for RAG statements |
| 11 | LLM incident explanations | **Partial** | copilot `/copilot/ask` (investigate + explain modes) | Needs Ollama; here returns 503 (correct). Real answers recorded once on Windows (1.7 s) | Verify with the model during Milestone 6 |
| 12 | Incident reporting | **Verified** | `outputs/reports.py`; API walk: JSON / CSV / PDF all 200 with the right content types | Report is deterministic and label-free; contains no agent investigation (no graph output) | Milestone 6: optional investigation section, clearly marked as agent output + verifier status |
| 13 | Analyst copilot | **Partial** | single agent + verifier per question | Not tested against a model here; no conversation memory (one question per call, by design) | Milestone 6 check with the model |
| 14 | SOC dashboard | **Verified** (synthetic) | 15 screens, 80 frontend tests, build ok, sign-in + Overview rendered with 0 console errors | No **event explorer** (the platform stores alerts; raw events exist only as the log lines inside alerts). No investigation workspace with agent trace. Main bundle > 500 kB. Sidebar calls the synthetic scenario a "dev scenario" (label bug) | Milestone 6: investigation workspace; fix the label |
| 15 | Human-controlled response | **Verified** | API walk (table 4.2): executive 403, unknown / non-state-changing / extra-key actions 422, execute before decision 409, requester deciding own 403, execute once then 409, all audited | Executor is simulated (by design) | None for the MVP |
| 16 | Experimental evaluation | **Partial** | study pipeline, baselines, controls, stats (paired bootstrap + Holm), freeze, final runner, paper export, all tested | Pilot gate **FAIL** on m5-v3 (one cell 21.4 %); m5-v4 re-pilot **not run** (needs Windows + Ollama); held-out not started (correct) | Milestone 8 sequence, after the decision on C1 |
| — | Security | **Partial** | JWT + bcrypt, RBAC matrix test, executive sees no raw records, pydantic body limits, no upload endpoint, secrets from env only, read-only agent tools, audit log | **Prompt injection through log lines: documented open risk, no test** (`docs/security-notes.md`). No rate limiting on `/auth/login`. No automated SQL-injection test (queries are parameterised `?` in the code inspected) | Milestone 7: injection test corpus (crafted log lines must not change tool permissions, citations outside the case, or verifier outcome) |

## 3. Detection findings (the two known problems)

### 3.1 Why only 2 of 90 compiled Sigma rules fire

From the code and the recorded runs, before any change:
1. **Input scope** (main cause): `SigmaEngine.run` evaluates the `evidence.log_lines` of alerts
   already in the pool. A Sigma rule can only fire on a line that Wazuh or AMiner already raised an
   alert on. Behaviour that no detector alerted on never reaches Sigma.
2. **Log-source coverage:** parsers exist for apache access/error, auditd and syslog only. 166 of
   256 rules are skipped by counted reason because their fields are not in these logs
   (process_creation 123, proxy 29, file_event 8, network_connection 5, nginx 1). This is correct
   behaviour, not a mapping bug: the project rule is "never map a field the line does not carry".
3. **Not yet established:** for the 88 compiled rules that never fire, whether each is (a) a missing
   field mapping, (b) an unsupported condition, or (c) genuinely absent behaviour. This needs the
   real rules and logs, i.e. the Windows machine. It is Milestone 2's first deliverable.

### 3.2 Why the ML baselines lean on one feature

Recorded (session notes, B4 fix): permutation importance is dominated by `host_count_60s`, the
number of alerts from the same host in the previous 60 s. Removing detector and rule id does not
lower F1. The dev attacks with the most alerts (dirb, wpscan) are floods, so an alert rate
separates them. The phases the model never saw are missed (LOPO shaw F1 0.179). Leakage guards are
in place and tested: no label, phase, scenario, alert id, raw timestamp or source line in the
features; strictly past window counts; encoders fitted on training only; contamination "auto".
So the dependence is a **property of the data** (burst attacks), not a leak. The honest product
reading is "the ML layer detects bursts", and that should be the claim.

## 4. End-to-end check done here

### 4.1 Pipeline on synthetic data
`ingest-alerts` (synthetic sample) -> replay into a scratch store (9 stored, 0 rejected) -> triage
(6 incidents, all Low, 2 alerts excluded by selection) -> API -> console. Detection by Sigma/ML,
the agent investigation, RAG and the verifier were **not** in this chain (no rules, no model).

### 4.2 API walk (scratch script, TestClient, copy of the synthetic store)

| step | expected | got |
|---|---|---|
| GET /incidents without token | 401 | 401 |
| analyst GET /incidents | 200, alert refs present | 200, 6 incidents, refs present |
| analyst POST /reports; download json / csv / pdf | 201; 200 x3 | 201; 200 x3 (application/json, text/csv, application/pdf) |
| executive POST /approvals | 403 | 403 |
| `manual_review` (not state-changing) / extra action key (`cmd`) | 422 / 422 | 422 / 422 |
| analyst requests `isolate_host` | 201 | 201 |
| execute before decision | 409 | 409 |
| requester decides own request | refused | 403 |
| manager approves; execute; execute again | 200; 200; 409 | 200; 200; 409 |
| copilot ask with no model configured | 503 | 503 |
| audit log | all actions present | login, login.failed, denied, report.create, approval.request, approval.decide, action.execute, action.execute.refused, user.create |

## 5. Critical issues and weaknesses (ranked)

- **C1. The single vs graph comparison confounds architecture with tool access.** The single agent's
  tools are `list_alerts, get_alert, search_alerts, get_raw_log` (`agent/tools.py` `TOOL_NAMES`).
  The graph adds `search_attack` (RAG), `recall_notes`, `search_notes` (`agent/graph.py`
  `AGENT_TOOLS`). The protocol's research question includes "investigation architecture", but any
  difference between the arms also includes "RAG access", and the methodology doc does not state
  this. **This must be decided before the protocol freeze** (options in section 7). It is a
  protocol change, so it needs your approval.
- **C2. The multi-agent graph is not part of the product.** No route or screen runs it; the demo
  chain "multi-agent investigation -> verifier -> report" does not exist end to end.
- **C3. Pilot gate still FAIL, m5-v4 not run.** Blocked on the Windows machine.
- **C4. ML is evaluation code, not a detector in the platform.** No model artefact, no scores on alerts.
- **C5. Sigma is a re-detection pass** over alerted lines (3.1); its applicability per rule is unknown.
- **C6. Correlation uses two entity kinds** and records no rationale or confidence.
- **C7. Prompt-injection protection is untested.**
- **C8. Infrastructure backends (PostgreSQL, pgvector, OpenSearch, Kafka, MinIO) never tested.**
- Minor: frontend main chunk 519 kB; sidebar labels the synthetic scenario "dev"; no login rate limit.

## 6. Original requirements vs MVP

| requirement | assessment |
|---|---|
| 1-2 ingestion, normalization, storage | implemented (replay only) |
| 3 rule-based detection | implemented, limited by input scope (C5) |
| 4 ML detection | implemented as an offline study (C4); product integration missing |
| 5 triage | implemented |
| 6 correlation | partial (C6) |
| 7 ATT&CK | implemented for Wazuh / Sigma; none for Suricata / AMiner by design |
| 8 RAG | implemented; no-RAG vs RAG not measured |
| 9 multi-agent | implemented for the study; missing in the product (C2) |
| 10 evidence verification | implemented (record and log lines; not knowledge statements) |
| 11 LLM explanations | implemented, model-dependent |
| 12 reporting | implemented (no agent section) |
| 13 copilot | implemented (single agent) |
| 14 dashboard | implemented; missing event explorer and investigation workspace |
| 15 human-controlled response | implemented and verified |
| 16 experimental evaluation | implemented; gate pending |
| event explorer over raw events | **outside the MVP as built**: raw events are not ingested (AIT-LDSv2 excluded by user decision). The console can show the log lines inside alerts; say so rather than build a raw-event store |
| user / process correlation | limited by the data: AIT-ADS alerts rarely carry users and never processes |

## 7. Recommended roadmap (prioritised)

1. **Decide C1 (you, before any re-pilot).** Options:
   a. give the single agent `search_attack` too (both arms same evidence and knowledge access;
      the arms then differ only in architecture + memory). Changes the single prompt (m5-v5) and
      forces another dev re-pilot;
   b. keep the arms as they are and add a declared third factor in the methodology ("graph =
      architecture + RAG + memory"), no code change;
   c. add a "graph without RAG" arm (more runtime, ~+50 %).
   My recommendation: **a**, because it answers the stated research question; it costs one more
   ~1.6 h dev pilot, which has to run anyway for m5-v4.
2. **Re-pilot on Windows** with the decided prompts, then the gate (already scripted).
3. **Milestone 2 (Windows, real data):** Sigma per-rule applicability report; ML comparison (LR, RF
   against HistGB / IF, with the full metric list), framed around the burst finding.
4. **Milestone 6 first slice (can be done here):** product investigation route that runs the
   existing graph (or the single agent) on an incident, stores the trace and the verifier result,
   and an investigation workspace screen; FakeClient tests; synthetic end-to-end test covering
   ingest -> triage -> investigation -> verifier -> report -> approval. No study code touched.
5. Milestone 3 correlation rationale + entities; Milestone 4 RAG failures + no-RAG comparison;
   Milestone 7 injection tests + infra tests; Milestone 8 freeze and held-out.

**Recommended first milestone to execute: roadmap item 4** (product investigation route + workspace
+ synthetic end-to-end test). Reasons: it closes the largest gap against your success criterion
(C2), it needs neither the real data nor the model, and it does not touch the frozen study code,
so it cannot disturb the pilot. Items 1-3 need your decision or the Windows machine.

## 8. Notes on the requested documents

- `docs/ARCHITECTURE.md` and `docs/RESEARCH_METHODOLOGY.md` would collide with the existing
  `docs/architecture.md` and `docs/research-methodology.md` on Windows (case-insensitive file
  system: two files differing only by case break the checkout). The existing lower-case files are
  kept as the architecture and methodology documents.
- `docs/PRODUCT_READINESS_REPORT.md` is written after the fixes (Milestone 7), as requested.
- `docs/IMPLEMENTATION_LOG.md` is started with this audit.
