# Product readiness report

**Date:** 2026-11-15. **Branch:** `claude/amazing-edison-ns3q8m` (not merged; no PR opened, per your
instruction). Baseline: `docs/PRODUCT_READINESS_AUDIT.md` (commit `090a780`).
**Where verified:** a Linux cloud container with the code and the committed **synthetic** sample only.
No real AIT-ADS data, ATT&CK bundle, Sigma rules, embedding model, Ollama or Docker were available, so
nothing below is a real-data or real-model result. Windows steps for those: `docs/windows-guide.md`.

## 1. Tests executed (actual output, this container)

| suite | baseline (audit) | now |
|---|---|---|
| backend pytest | 525 passed, 12 skipped | **567 passed, 12 skipped** |
| backend mypy (strict) | clean, 90 files | **clean, 95 files** |
| frontend `npm test` | 80 / 80 | **87 / 87** |
| frontend typecheck / build | ok / ok | ok / ok (main chunk still > 500 kB, Vite warning) |
| headless browser walk (real API, scripted stub model) | sign-in + Overview | + Investigate tab (graph and single runs), incident header (correlation, ML), 1440 / 1366 / 390 px, 0 console errors |

The 12 skips, and how to run them:

| skipped test | reason | how to run |
|---|---|---|
| `test_ait_ads_real.py` x3, `test_agent_tools.py:173` | real AIT-ADS files absent | put the files in `data/raw/ait_ads/` (Windows has them) |
| `test_intel.py:61`, `test_rag.py:129` | ATT&CK bundle absent | `data/raw/mitre/enterprise-attack.json` |
| `test_rag.py:136` | bge-small cache absent | `data/models/fastembed/` |
| `test_sigma_engine.py:251` | SigmaHQ rules absent | `data/raw/sigma/repo/` |
| `test_infra_integration.py` x4 | PostgreSQL, pgvector, OpenSearch, Kafka not running | `docs/windows-guide.md` section 5 |

New test files: `test_prompt_m5_v5.py` (5), `test_preflight.py` (5), `test_investigation.py` (9),
`test_sigma_coverage.py` (2), `test_ml_model.py` (4), `test_correlation.py` (8), `test_security.py` (3),
`test_e2e_workflow.py` (2), plus 3 ML comparison tests and 1 RAG evaluation test; frontend
`lib/investigation.test.ts` (7).

## 2. What changed, by critical issue

| issue | status | evidence |
|---|---|---|
| C1 arms differ in tool access | **resolved (option a)** | single agent gets `search_attack` through the same `AttackSearchTool`; prompt m5-v5, m5-v4 text kept (sha256 pinned); shared notes stay graph-only; `manifest.tool_access`; methodology section "Investigation arms and tool access" |
| C2 graph not in the product | **resolved** | `POST /incidents/{id}/investigations`, persisted steps / verifier / ATT&CK retrieved (migration 0004), Investigate tab, report from an investigation |
| C3 pilot gate FAIL | **open (blocked)** | m5-v5 not piloted: needs Windows + Ollama. `pilot-preflight` added to check inputs before the run |
| C4 ML offline only | **resolved in code** | `ml-train` / `ml-score`, versioned sha256-checked bundle, scores on alerts (migration 0005), incident line; never changes severity. Model comparison (+ LR, RF, PR-AUC, ROC-AUC, timing, `no_host_counts` ablation) added; **numbers pending** (real data) |
| C5 Sigma 2 of 90 | **explained in code** | per-rule funnel (compiled / applicable / evaluated / matched / skipped with reason) and per-rule usefulness; no rule or mapping changed. Funnel **numbers pending** (real rules) |
| C6 correlation without reasons | **resolved** | `detail.correlation` on every incident (links, shared indicators, gaps, strength label), header line; grouping unchanged |
| C7 prompt injection untested | **tested** | injected log text stays JSON-escaped data, prompt unchanged, unknown tools refused, approvals untouched, false claims dropped; plus login limit and SQL-injection tests |
| C8 infra never tested | **open (blocked)** | Docker not available here; validation steps written (`docs/windows-guide.md` section 5) |

Also found and fixed: a test (`run-pilot` CLI) wrote graph memory into the repo's `data/platform/`
on every test run; it now uses `tmp_path`, and a session guard fails any test that touches that folder.

## 3. Feature status now

| feature | status | note |
|---|---|---|
| ingestion, normalisation, SQLite storage | Verified (synthetic) | real files recorded passing on Windows earlier |
| PostgreSQL / OpenSearch / Kafka / MinIO | Unverified | interfaces present, never run |
| Sigma detection | Partial | re-detection over alerted lines by design; coverage now measurable |
| ML detection | Partial | in the platform; real performance numbers pending; burst-rate dependence documented |
| triage + correlation | Verified (synthetic) | every incident explains its grouping |
| ATT&CK mapping | Partial | Wazuh native ids + rule table; none for Suricata / AMiner by design |
| RAG | Partial | evaluation richer (outcomes, MRR, latency); real recall not re-run here |
| single agent + graph | Verified with FakeClient / scripted stub | real-model behaviour only from the Windows pilot records (m5-v3) |
| evidence verifier | Verified | also re-applied when a report takes an investigation |
| investigation workspace | Verified (synthetic, stub model) | |
| reports JSON / CSV / PDF | Verified | can carry a completed investigation |
| approvals + audit | Verified | e2e test: four eyes, execute once, audit actions |
| copilot | Partial | needs the model; relationship to investigations made explicit in the UI |
| dashboard | Verified (synthetic) | every chart states its question and reads an API aggregate (inventory below) |
| security controls | Verified (tests) | login limit, RBAC, injection tests; see `docs/security-notes.md` |

Dashboard chart inventory (question as shown in the console; source = API aggregate of stored data):
Overview: alert volume by detector over time; queue by severity / untouched; detector context;
ATT&CK tactic x technique; top hosts / sources; kill-chain stages. Incidents: ATT&CK lanes; entity
graph. Executive: severe workload trend; top risks; throughput; observed stages. Entity: activity,
reported rules, queue membership. Audit: actions over time. Reports: alert arrival, involved entities.
Study: coverage vs baselines, citation precision, unsupported claims before / after the verifier,
cost, source x arm (results files only; pilot-labelled). No chart uses sample data; the synthetic
data source is labelled "synthetic sample, not real telemetry" in the shell.

## 4. Known limitations

- Alert-level platform: no raw-event store (AIT-LDSv2 excluded by your earlier decision). The console
  shows the log lines inside alerts and does not claim to be a raw-event explorer. Expanding the scope
  needs your approval (storage, ingestion time, retention, privacy).
- Users and processes are not correlation entities: the data rarely carries users and never processes.
- ML scores are uncalibrated and, for the training scenarios, in-sample.
- Sigma sees only lines another detector alerted on.
- The arms still differ in architecture (control flow, prompts, shared notes); the study measures the
  multi-agent design as built, not one component of it.
- Investigations run one at a time (shared model lock); a 7B local model is slow on large incidents.

## 5. Remaining blockers (external)

1. m5-v5 dev re-pilot and gate (Windows + Ollama). 2. Real-data numbers for Sigma funnel, ML
comparison, RAG evaluation, correlation strengths (Windows data). 3. Infrastructure validation
(Docker). 4. Protocol freeze, six held-out scenarios, statistics, paper assets: only after a PASS and
your go. 5. A real-model run of the Investigate tab.

## 6. Assessment

The product now runs the promised chain end to end (security alerts -> detection -> correlation ->
multi-agent investigation with ATT&CK retrieval -> evidence verification -> report -> human approval
-> audit), proven by an automated test and a browser walk on synthetic data with a scripted model.
It is **demonstrable** as an academic prototype. It is **not yet validated** on real data with the real
model since these changes, and the **research is not complete**: the pilot gate is still FAIL until
the m5-v5 pilot runs, and no held-out result exists.
