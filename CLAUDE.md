# CLAUDE.md — SentinelAI

Context for AI assistants working in this repository.

## Project

**SentinelAI — Autonomous AI-Powered Security Operations Center (SOC).** A
research-oriented platform for AI-assisted cybersecurity investigation,
built in phases.

| Phase | Scope | Status |
|-------|-------|--------|
| 1 — Data foundation | Load CSV/JSON/JSONL, validate, normalize to a canonical schema, data-quality report | **Done** |
| 2 — Study foundation | Deterministic metrics, AIT-ADS alert schema and loader, alert-source variants, case units and case-level scoring | **Done**: metrics, M2 loader, M3 variants + frozen split, M4 cases + case scoring + dev ceilings, M4b noise controls + baselines + claim kinds, M4b decisions (nearest-time noise fallback, event_label headline, k = 5/10/matched, frozen detector order, pilot truncation side by side) |
| 2b — CICIDS2017 detection baselines | Feature matrices, leakage-safe splits, baseline classifier | **Optional, off the critical path** (only after the pilot, if the user asks) |
| 3 — SentinelAI pipeline | The original plan (user decision 2026-11-07): ingest -> normalize -> detection layer -> correlation -> ATT&CK RAG -> multi-agent investigation -> evidence verification -> report -> human approval -> demo UI; the paper measures the detector-conditioned study on top of it | **In progress**, milestone by milestone (roadmap below) |

### Roadmap (phase 3)

The M7-M12 milestones are now delivered inside waves (pace rule below):
M7 RAG and M8 multi-agent + verifier -> Wave C; M9 correlation -> Wave B3;
M10 reports + approval and M11 UI -> Wave D; M12 held-out + statistics -> Wave E.
Held-out scenarios stay untouched until Wave E.

**Pace (user decision 2026-11-07, replaces "build only the next milestone"):
build wave by wave; inside a wave, each sub-milestone is its own tested,
committed unit; stop only at a gate or a blocker.** Waves map the 5-stage
SentinelAI architecture: A = platform foundation (ingestion, storage, API),
B = detection and analysis (Sigma, ML, ATT&CK/IOC, triage/correlation),
C = multi-agent investigation (RAG, LangGraph, verifier, matched-budget
pilot; **GATE: stop and report the pilot numbers**), D = outputs and
operations (reports, approvals, UI, copilot, feedback, metrics), E = held-out
runs and statistics (**only after the user says go**). Kafka, vector
databases, PostgreSQL, OpenSearch and MinIO are now authorized, each behind
an interface with an in-process fallback. Every other rule stands: tests
first, pytest + mypy clean, CLAUDE.md updated in the same commit as code,
real numbers only, dev scenarios only until Wave E, held-out guard stays,
secrets only from the environment, no paid APIs. Cut order if time runs
short (first to last): Copilot chat, Jira, compliance extras, Grafana
dashboards, OpenSearch, Kafka. Never cut: the study pipeline, the
multi-agent comparison, the verifier, statistics.

| Wave / unit | Status |
|-------------|--------|
| M5 | **Done** (FakeClient only; no real model run yet) |
| M6 | Case selection options **done** (`run-agent --select reachable`, `--case-id`). 2-case smoke test + gated mini-pilot **blocked: no local model** (Ollama + `qwen2.5:7b-instruct` approved, download paused: slow internet) |
| A | **Done, merged** (PR #3): replay collector, stream (in-memory / Kafka), enrichment, batched consumer, SQLite / PostgreSQL storage with migrations, separate truth area, FTS5 / OpenSearch, local / MinIO objects, FastAPI + JWT + RBAC + audit, Prometheus metrics, docker-compose `lite`/`full` |
| B1 | **Done**: ATT&CK KB from local STIX + deterministic alert mapping (Wazuh native ids, then `RULE_TABLE`), IOC store + matcher, OTX/MISP/VirusTotal disabled stubs with a labelled synthetic sample |
| B2 | **Done**: Sigma engine over alert evidence lines (`app/detection/sigma_engine.py`; 90/256 rules compile, the rest skipped by counted reason), `Detector.SIGMA` as a platform detector (not a study variable), single label door `app/detection/labels.py`, frozen-sections hash test |
| B3 | **Done**: `app/detection/triage.py` (label-free): existing dedup kept, entities host/src-IP, union-find grouping with gap 300 s (inclusive), first-match severity table H1-L1, incidents via `put_incident` with timeline; CLI `triage`, API `POST /incidents/build` (RBAC `incident.build`, audited); descriptive dev check (labels.csv phase overlap) in `triage_report.py` only |
| B4 | Not started: ML detection baselines (IsolationForest / scikit-learn / XGBoost) on AIT-ADS **dev scenarios only** (CICIDS2017 not available: its URL returns a registration page) |
| C | Not started: ATT&CK RAG (bge-small already local), LangGraph supervisor + agents, evidence verifier, matched-budget comparison; **GATE after the pilot** |
| D | Not started: reports (JSON/PDF/CSV), approvals, React dashboard (needs the npm download), copilot, feedback script, Grafana JSON, security notes, Jira stub |
| E | Only after the user says go |

**Where we stopped (2026-11-07) and what comes next:** see the last section of
`docs/session-notes.md` ("Where we left off"). In short: build B2 (Sigma), B3
and B4 offline; then the Wave C code with FakeClient tests; resume the paused
downloads (Ollama + model, npm, Docker images) when the internet allows; then
run the M6 smoke test and the Wave C pilot and stop at the gate.

Nested rules: `backend/CLAUDE.md`, `infra/CLAUDE.md` (and `frontend/CLAUDE.md`
once the frontend exists). This file is the index.

## Commands

Run from `backend/` with the repo's `.venv` (Windows; Git Bash paths shown):

```bash
cd backend
../.venv/Scripts/python.exe -m pytest          # all tests (synthetic data, no network)
../.venv/Scripts/python.exe -m mypy            # strict mode over app/
../.venv/Scripts/python.exe -m app.main ingest ../data/samples/synthetic_cicids2017_format.csv \
    --mapping cicids2017 --dataset-name synthetic-cicids2017-format

# AIT-ADS: one scenario -> data/processed/<scenario>.{alerts,alerts.rejected,ground_truth}.jsonl
#          + <scenario>.alerts.quality.json  (real files: see "AIT-ADS" below)
../.venv/Scripts/python.exe -m app.main ingest-alerts --data-dir ../data/raw/ait_ads --scenario russellmitchell
# synthetic sample (needs explicit label paths and a synthetic dataset name)
S=../data/samples/synthetic_ait_ads
../.venv/Scripts/python.exe -m app.main ingest-alerts --data-dir $S --scenario synthetic \
    --labels $S/synthetic_labels.csv --event-labels $S/synthetic_alerts.txt \
    --dataset-name synthetic-ait-ads-format --no-output

# M3: variants + dev triage table (DEV scenarios only; reads
# data/processed/<scenario>.{alerts,ground_truth}.jsonl written by ingest-alerts,
# writes data/processed/variants/<scenario>/). Random controls come from study.json.
../.venv/Scripts/python.exe -m app.main variants --scenario russellmitchell
# M4/M4b: cases + per-variant coverage ceilings + deterministic baselines (DEV only;
# also reads ../data/raw/ait_ads/labels.csv, writes data/processed/cases/<scenario>/)
../.venv/Scripts/python.exe -m app.main cases --scenario russellmitchell
# M5: single tool-using agent on dev cases (attack/benign interleaved; writes
# data/processed/runs/<run_id>/). --dry-run prints the token/cost bound and calls nothing.
../.venv/Scripts/python.exe -m app.main run-agent --scenario russellmitchell --variant fused --limit 2 --dry-run
# real model: set SENTINEL_LLM_BASE_URL + SENTINEL_LLM_MODEL (and the key in
# SENTINEL_LLM_API_KEY for a hosted API) -- only with the user's explicit approval
# scripted demo without a model: --fake-responses replies.json (JSON list of reply strings)
# M6 selection: --select reachable (attack cases on alert-reachable phases + their benign
# matches) or --case-id <id> (repeatable)

# Wave A platform: replay a DEV scenario into the stores (SQLite fallback in data/platform/,
# or PostgreSQL / OpenSearch / Kafka via SENTINEL_DB_URL / SENTINEL_SEARCH_URL / SENTINEL_KAFKA)
../.venv/Scripts/python.exe -m app.main platform-ingest --scenario russellmitchell
# B2: Sigma rules over alert evidence lines (DEV only; writes data/processed/sigma/), then the
# dev detection baseline with labels from the platform truth area (needs platform-ingest first)
../.venv/Scripts/python.exe -m app.main sigma --scenario russellmitchell
# B3: incidents from the stored alerts (needs platform-ingest; --include-sigma adds the sigma file)
../.venv/Scripts/python.exe -m app.main triage --scenario russellmitchell --gap-seconds 300
# passwords and secrets only from the environment, never as arguments
../.venv/Scripts/python.exe -m app.main create-user --username alice --role analyst   # needs SENTINEL_NEW_USER_PASSWORD
../.venv/Scripts/python.exe -m app.main serve      # API on 127.0.0.1:8000; needs SENTINEL_JWT_SECRET
```

Infra (optional): copy `.env.example` to `.env`, fill it, then
`docker compose --profile lite up -d` (PostgreSQL + pgvector) or `--profile full`.
See `infra/CLAUDE.md`.

`tests/test_ait_ads_real.py` runs on the real russellmitchell files when
`data/raw/ait_ads/` holds them and skips otherwise (~8 s).

Setup: `python -m venv .venv` then `pip install -r backend/requirements-dev.txt`.
Test and mypy configuration lives in `backend/pyproject.toml` (`pythonpath = ["."]`,
so imports are `from app...`). There is no linter configured.

## Layout

```
backend/app/
  main.py                 CLI: `ingest PATH`, `ingest-alerts --data-dir D --scenario S`,
                          `variants --scenario S`, `cases --scenario S`, `run-agent --scenario S
                          --variant V [--limit N] [--dry-run] [--confirm] [--truncation R]
                          [--fake-responses F]` (all three dev only); print_score_header/row
  pipeline.py             load → normalize → quality report; writes outputs
  alert_pipeline.py       AIT-ADS scenario: Wazuh then AMiner lines → Alert + GroundTruth + report;
                          AitAdsInputs.from_layout, iter_alert_file(path, selection)
  schemas/event.py        canonical SecurityEvent (Pydantic v2)
  schemas/alert.py        Alert, AlertEvidence, GroundTruth, AlertSelection (default exclusions)
  ingestion/alert_normalizer.py raw detector record → Alert | Rejection (AlertMapping-driven)
  ingestion/ground_truth.py AttackTimeline (labels.csv), alerts_csv reader, positional EventLabelLinker
  services/alert_quality.py streaming AlertQualityAccumulator (per detector, duplicates, coverage)
  ingestion/records.py    RawRecord, IngestionError, file checks
  ingestion/csv_loader.py streaming CSV (header cleaning, row-shape errors)
  ingestion/json_loader.py JSON array / {"records": [...]} / JSON Lines
  ingestion/mappings.py   DatasetMapping registry: cicids2017, generic; AIT-ADS AlertMappings
                          (wazuh, suricata, aminer), routing, file layout, CSV conventions
  ingestion/normalizer.py mapping + parsing → SecurityEvent | Rejection
  services/data_quality.py streaming DataQualityAccumulator
  evaluation/metrics.py   judge-free metrics: triage P/R/F1/FNR, attack-step coverage, unsupported-claim
                          rate; Claim(record_id, field, value, kind) with kinds field_value (default)
                          and quote, .event_id alias, Claim.about_alert, Claim.quote; unsupported_claims
  evaluation/case_scoring.py score_case (coverage by time/event_label, citation precision,
                          unsupported claims, load), flatten_record, alert_claim_index, alert_quote_index
  study/config.py         StudyConfig from experiments/config/study.json; ScenarioSplit.require_dev
  study/variants.py       AlertPool (offset index), build_variants, experiment_variants, variant_manifest,
                          triage_by_truth, write_variant, dev_triage_report (dev only)
  study/cases.py          Case, build_cases (attack + matched benign windows), case_alerts (cap:
                          spread|earliest), noise_case_alerts, variant_case_views, reachable_phases,
                          dev_case_report (dev only; ceilings + baselines), summarize_scores,
                          baseline_summaries (any case subset)
  study/baselines.py      deterministic non-LLM citers (BASELINE_NAMES), baseline_rows (@k rows),
                          matched_k, baseline_claims
  agent/config.py         ModelConfig (endpoint; env overrides), AgentConfig (budgets), load_agent_settings,
                          api_key (environment only)
  agent/client.py         OpenAICompatibleClient (stdlib urllib, injectable transport, bounded retries),
                          FakeClient (scripted), ChatResult, estimate_tokens
  agent/tools.py          CaseToolkit: list_alerts, get_alert, search_alerts, get_raw_log; opaque ids,
                          offsets, mask_times; never sees labels
  agent/protocol.py       SYSTEM_PROMPT (PROMPT_VERSION), strict JSON reply parsing (ToolCall, FinalAnswer)
  agent/agent.py          investigate(): bounded loop -> CaseRun (status, tokens, transcript, claims)
  agent/runner.py         prepare_run (dev only), select_cases (interleaved | reachable | case ids),
                          estimate_run, config_hash, run_agent (run log + scores next to baselines)
  storage/                db.py (SQLite | PostgreSQL, templated migrations), repository.py (Repository,
                          AlertReader for agent tools, TruthStore), search.py, objects.py,
                          migrations/{core,truth}/NNNN_*.sql
  platform/               stream.py, collectors.py (dataset replay, dev only), enrichment.py,
                          consumer.py, bootstrap.py (open_stores, ingest_scenario)
  api/                    auth.py (roles, PERMISSIONS, JWT, bcrypt), app.py (routes), server.py
  ops/metrics.py          Prometheus metrics (API + agent cost)
  intel/attack.py         AttackKB.from_stix, Technique, map_alert (native: Wazuh rule.mitre.id,
                          Sigma attack.tNNNN tags), RULE_TABLE
  intel/ioc.py            Indicator, IocStore.match_alert, disabled feed adapters (FEEDS)
  detection/sigma_engine.py  log-line parsers (apache_access/error, auditd, syslog), load_rules
                          (RuleSet: compiled + skipped by reason), SigmaEngine.run -> sigma Alerts
  detection/sigma_report.py  run_sigma_scenario (no labels), sigma_dev_baseline (labels)
  detection/labels.py     dev_labels(TruthStore, scenario, config): the ONE label door of the
                          detection layer (require_dev; truth area only)
  detection/triage.py     TriageConfig (gap_seconds, selection), entities, group_alerts (union-find),
                          level_class, SEVERITY_TABLE + severity(), build_incidents, build_and_store
  detection/triage_report.py  phase_overlap: descriptive dev check (the only B3 label reader)
backend/tests/            pytest, one file per module + test_pipeline.py (end to end)
data/samples/             committed SYNTHETIC samples (see its README)
data/raw/, data/processed/ git-ignored: local datasets and pipeline outputs
data/samples/synthetic_ait_ads/ SYNTHETIC files in the AIT-ADS shapes (scenario "synthetic")
data/samples/synthetic_attack_stix.json SYNTHETIC 3-technique ATT&CK bundle for tests
data/raw/mitre/, data/raw/sigma/repo/ approved local ATT&CK bundle and SigmaHQ rules (git-ignored)
data/models/fastembed/    local bge-small-en-v1.5 ONNX embedding model (git-ignored)
data/platform/            SQLite fallback stores core.db, truth.db, search.db, objects/ (git-ignored)
docker-compose.yml, infra/ lite/full profiles, Postgres role init, Prometheus config
.env.example              names of every secret; the real .env is git-ignored
docs/                     architecture.md, research-methodology.md, session-notes.md
experiments/config/study.json  frozen split; variant seed, shuffled/noise references; cases; baselines (k list, frozen order); pilot (scenarios, truncations); model (endpoint, null = none); agent (budgets)
```

## Design rules (keep these)

- **Two error levels.** File-level problems raise `IngestionError` (CLI exit 1).
  Record-level problems become a `Rejection`: counted, reported, written to
  `<stem>.rejected.jsonl`. Never drop records silently.
- **Reject, don't coerce.** Invalid timestamps, IPs, ports, protocols,
  severities, source types or feature values reject the record. All errors in
  a record are collected; the first is its primary category.
- **Never invent values.** Missing tokens (`""`, `NaN`, `null`, `N/A`) become
  `None`. No imputation. Only `raw_event` is required in the schema.
- **Keep layers separate:** `raw_event` (original) / canonical fields /
  `label` (ground truth — never a feature; schema rejects a feature named
  `label`) / `features` (candidate model inputs). Canonical columns (IPs,
  ports, timestamp, protocol) are not copied into `features`.
- **Timestamps** are aware UTC. Naive values are rejected unless the mapping
  sets `naive_timezone`; using it records `metadata.timestamp_timezone_assumed`.
  `cicids2017` assumes UTC-03:00 (ADT) — an assumption, overridable with
  `--assume-timezone`.
- **Dataset knowledge belongs in `mappings.py`**, not in loaders or the
  normalizer. Aliases are written in normalized form (lower case, spaces/
  underscores collapsed — see `normalize_column_name`).
- **Streaming:** CSV and JSONL are read row by row; outputs are written
  incrementally. Don't load whole files (no pandas in Phase 1).
- **Dependencies:** the study code paths (ingest, variants, cases, scoring, M5 agent) still need only `pydantic`; the platform (Wave A+) adds FastAPI, PyJWT, bcrypt, psycopg, prometheus-client and optional infra clients, all in `backend/requirements.txt`. Optional infra clients are imported lazily.

## AIT-ADS alerts (M2/M3 policies, decided by the user)

- **Detectors.** Suricata alerts live inside `<scenario>_wazuh.json`:
  `location == /var/log/suricata/eve.json` → `suricata` (signature-based);
  `location == /var/log/suricata/fast.log` **with** an eve.json twin →
  `wazuh` record flagged `duplicate_of_suricata=True`; fast.log **without**
  a twin → `suricata` alert flagged `fast_log_unmatched=True` (kept, not
  excluded; rule_id = `data.id`, no rule_name/severity). Twins are found by
  a first pass over the Wazuh file (`SuricataTwinIndex`, greedy in file
  order). Every other Wazuh record → `wazuh` (rule-based).
  `<scenario>_aminer.json` → `aminer` (anomaly-based); its
  `MatchValueAverageChangeDetector` alerts are ordinary `kind="event"`.
  The detector→type map is `DETECTOR_TYPES` in `schemas/alert.py`.
- **Default exclusions, never drops.** Everything is written to
  `alerts.jsonl`; `AlertSelection` excludes at selection time.
  `DEFAULT_EVALUATION_SELECTION` drops `training_mode` and
  `duplicate_of_suricata`; `INVESTIGATION_SELECTION` also drops
  `kind="aggregate"` (AMiner `CountData`/`FrequencyData`). Variants (M3) must
  go through `AlertSelection`, and including excluded alerts is an explicit
  option.
- **IDs.** Wazuh/Suricata `alert_id` = the record's own `id`. AMiner has none:
  `alert_id = "aminer-" + sha256(scenario, file, line, canonical JSON)[:32]`
  with `alert_id_derived=True`. `event_ids` stays empty: the alerts carry no
  log-event IDs, and IDs are never invented. AIT-LDSv2 is **not** used
  (user decision): the verifier (M8) checks claims against fields of the alert
  record and the raw log lines in its evidence.
- **Evidence** = what the alert carries: `source_alert_id`, `log_lines`
  (`full_log` / AMiner `RawLogData`; empty for aggregates, whose raw line
  only closed the window and stays in `raw_alert`), `log_paths`,
  `log_timestamps`. `severity` is detector-native (Wazuh `rule.level`,
  Suricata `alert.severity`, AMiner none); never rescaled.
- **Ground truth** is `GroundTruth` in `<scenario>.ground_truth.jsonl`,
  joined by `alert_id`; `Alert` has no label or feature fields.
  `time_label` from `labels.csv`, half-open `[start, end)`, sorted
  explicitly (rows are not in time order), overlap → `IngestionError`;
  outside every interval = `"false_positive"` (the dataset's term).
  `event_label` from alerts_csv, linked **by position** (Wazuh lines then
  AMiner lines) and verified per row on (floor seconds, name, ip); the
  first mismatch stops linking for the scenario (`link_status`). The CSV's
  `-` → `event_label=None` with `event_label_available=True`.
- **Clock.** Wazuh `@timestamp` (ISO, Z), AMiner `DetectionTimestamp[-1]`
  and labels.csv (epoch s) are all treated as UTC. This is checked, not just
  assumed, for russellmitchell and shaw: all 10 attack intervals fall
  inside the alert time range and labels.csv-derived `time_label` equals the
  authors' alerts_csv `time_label` for 100% of alerts. Other scenarios: the
  quality report's `attack_intervals_within_alert_range` shows it per run.

## Study design (M3/M4/M4b policies)

- **Frozen split** (`experiments/config/study.json`, frozen 2026-10-31):
  dev = russellmitchell, shaw; held-out = fox, harrison, santos, wardbeck,
  wheeler, wilson. Any dev-only function (scores, ceilings, tuning,
  debugging) must call `config.split.require_dev(scenario)` first;
  `test_study_config.py` fails if a held-out scenario gets through
  `dev_triage_report` or `dev_case_report`. Never edit the split.
- **Truth:** `event_label` is primary for alert-level triage (attack = any
  event label, benign = `-`); `time_label` is the sensitivity analysis.
  Every output keeps both and every variant is reported under both. For
  cases (decision 2026-11-07, reversing M4): the **headline is event_label
  coverage on the alert-reachable phases**, time coverage is the
  sensitivity analysis (noise can reach time coverage, not event-label
  coverage). Reports and CLI tables print the headline column first.
- **Suricata labelling limitation** (methodology doc): Suricata event labels
  come from AIT-NDS netflow matching, so almost none carry one. Report
  Suricata under both labels with the caveat; its base rate is accepted.
- **Variants** are subsets of the pool = investigation-eligible alerts:
  `wazuh`, `suricata`, `aminer`, `fused` (= whole pool), `oracle` (attack
  event_label); **noise controls** `noise-<det>` (the random control:
  event_label-benign alerts count-matched to `<det>`; in cases rebuilt per
  case, same window first (seeded), shortfall filled with the event-benign
  pool alerts **nearest in time** outside the window (deterministic; ties
  by time, source line), split recorded as
  `from_window`/`from_fallback`/`shortfall` plus
  `fallback_max_distance_seconds`); **shuffled-pool rows**
  `shuffled-<det>` (the old M3 random controls, kept for comparison).
  `shuffled-fused` (= pool) is written **only as a manifest** with
  `degenerate: true`, `experiment_variant: false`; never use it as a
  variant. `experiment_variants(pool, config)` is the one entry point.
  Seed purpose strings are fixed (`"random"` for shuffled, so its draws equal
  M3's; `"noise"`, `"noise-case"`); changing them changes every draw.
- **Study unit = case** (`app/study/cases.py`); the M3 20-alert study sample
  is retired. Attack case per labels.csv phase; matched benign windows of
  equal length, seeded, inside the observation range, outside attack
  intervals (+padding), mutually disjoint; unfit ones listed `unavailable`;
  no time-of-day matching, but every case records its UTC time of day.
  Case alerts: `[window_start, window_end)`, time-ordered, cap
  `max_alerts`=100 by `spread` (evenly spaced time ranks; `earliest` is an
  option). Every truncation is recorded per case and variant (rule,
  dropped, dropped attack-labelled by both labels).
- **Case scoring** (`app/evaluation/case_scoring.py`, no LLM): coverage by
  time / by event_label via `attack_step_coverage` with alert ids, reported
  over all phases and over the **alert-reachable** phases (some detector
  has an event-labelled alert inside the phase; unreachable ones listed);
  citation precision (event_label; time = inside the phase), cited ids
  outside the case count as wrong; unsupported claims via
  `Claim(record_id=alert_id, ...)`: kind `field_value` (flattened record,
  exact after strip) or `quote` (exact case-sensitive substring of a raw
  log line, >= 8 chars, no normalization); load = alerts after cap.
  Ceilings (cite every alert) are **ceilings, not agent results**.
  Time coverage can be reached by noise; event-label coverage cannot.
- **Baselines** (`app/study/baselines.py`): cite-all, cite-none,
  cite-top-k-wazuh-level, cite-top-k-detector-order (aminer, wazuh,
  suricata: dev-derived, documented, **frozen 2026-11-07**:
  `baselines.detector_order_frozen`, `FROZEN_DETECTOR_ORDER`, pinned by
  `test_detector_order_is_frozen`; never change it), cite-aminer-only.
  Every k in `baselines.top_k` ([5, 10]) is a row `<name>@k<k>`; agent
  runs add `<name>@k<k>-matched` (k = agent's mean citations per case,
  `matched_k`). Claims copied from the record (unsupported rate 0 by
  construction). They are the reference points an LLM agent must beat:
  **baselines, not agent results**. `summarize_scores` (cases.py) builds
  the row for baselines and agent runs alike.
- **Pilot** runs on dev scenarios only (`pilot.scenarios` must be a subset
  of `split.dev`) and reports both truncation rules (`pilot.truncation`:
  spread, earliest); held-out scenarios stay untouched until M12.
- **Determinism:** seeds derive via SHA-256 from (base seed, purpose,
  scenario, variant); populations are time-ordered with (source_file,
  source_line) tiebreak.
- **Manifests**: `<scenario>.variant.<name>.manifest.json` (rule, seeds,
  counts, by-detector counts, attack share by both labels, selection,
  sha256 of the alerts file; variant alert files are byte-identical lines
  of `alerts.jsonl`); `<scenario>.cases.json` (case windows, benign
  sampling log, per-variant alert ids and truncation);
  `<scenario>.case_ceilings.json`.
- Detector-level triage numbers and case ceilings are **dev-scenario
  numbers** and are labelled so wherever printed or written.

## Investigation agent (M5 policies)

- **Model endpoint.** One OpenAI-compatible chat-completions client
  (`agent/client.py`, stdlib `urllib`) covers Ollama, llama.cpp, vLLM and
  hosted APIs. Settings: `model` in `study.json` (committed with
  `base_url`/`model` = null: **no endpoint configured**), overridable by
  `SENTINEL_LLM_BASE_URL` / `SENTINEL_LLM_MODEL`. Temperature 0 by default.
  **API keys only from the environment** (`model.api_key_env`, default
  `SENTINEL_LLM_API_KEY`); the loader rejects an `api_key` in the config; keys
  never go into manifests, errors or `repr`. Retries: at most
  `model.max_retries` (<= 3), only for timeouts/connection errors/429/5xx.
  Never download models or call a paid API without the user's explicit
  approval for that run.
- **Tests never touch the network**: they use `FakeClient` (scripted replies,
  callables of the messages, or exceptions) or an injected transport.
- **Tool layer** (`agent/tools.py`): `CaseToolkit` is built from the case's
  `Alert` records and the window start only (never ground truth, labels,
  case id, phase, kind or variant). Alert ids are opaque (`al-` + salted
  sha256; salt = run config hash + case index); real ids inside records are
  replaced; times are offsets in seconds from the window start; every other
  absolute date/time in text is masked as `<TIME>` (`mask_times`; masking
  keeps unmasked substrings exact, so quote claims still verify). Selection
  flags, scenario, dataset name and source file/line are dropped. Leak tests
  (`tests/test_agent_tools.py`) scan every tool output, synthetic and real
  dev, for labels, phases, variants, case ids, real ids and dates; keep
  them passing when changing the view.
- **Protocol** (`agent/protocol.py`): one JSON object per reply (`call_tool`
  or `final`), strict parse (no fences, no extra keys); final = verdict
  attack|benign + findings with cited alert ids and claims (`field_value`,
  `quote`). Plain JSON, not native function calling, so any endpoint works.
  Changing `SYSTEM_PROMPT` changes the config hash; bump `PROMPT_VERSION`.
- **Bounded loop** (`agent/agent.py`): `agent.max_tool_calls` per case (one
  "answer now" notice, then `tool_budget_exceeded`); `agent.max_tokens_per_case`
  checked *before* each request (prompt at 3 chars/token + `max_tokens`);
  at most **one repair retry** per case; a second bad reply is
  `status=failed, parse_status=unparseable`: a logged failure with no
  verdict and no citations, never a silent success. Unknown cited ids become
  `unknown:<id>` (wrong citations).
- **Runs** (`agent/runner.py`, CLI `run-agent`): dev scenarios only
  (`require_dev` before any file is read); cases attack/benign interleaved in
  case order, first `--limit`; run log in git-ignored
  `data/processed/runs/<run_id>/` (manifest, per-case transcripts with the
  id map, scores). Agent and baselines are scored on the **same cases** with
  `summarize_scores` (k = 5, 10, matched). `--dry-run` prints the token
  bound (cases x `max_tokens_per_case`) and cost bound and calls nothing;
  a bound above `agent.run_token_budget` needs `--confirm`.
- Agent numbers on dev scenarios are **dev pilot material**, labelled
  `DEV-SCENARIO AGENT RUN`; runs made with `FakeClient` are plumbing checks,
  never agent results.

## Research integrity

- Never fabricate dataset statistics, model performance or test results;
  report actual command output.
- Synthetic data must be named `synthetic_*`, labelled as synthetic, and
  never presented as real traffic or results. Pass `--dataset-name` when
  running the CICIDS2017 mapping on synthetic files.
- Don't download datasets automatically or commit large/raw datasets,
  secrets or credentials.
- Class imbalance is reported, not corrected, in Phase 1. Splitting and
  balancing are Phase 2 decisions (training split only).
- See `docs/research-methodology.md`.

## Gotchas

- Original CICIDS2017 CSVs contain cp1252 bytes (e.g. the dash in
  `Web Attack – Brute Force`): use `--encoding cp1252`.
- CICIDS2017 headers have leading spaces and a repeated `Fwd Header Length`
  (renamed `Fwd Header Length.1`); `Flow ID` is not unique, so `event_id` is
  derived as `<file>:<line>`.
- The Windows console may print non-ASCII labels as `?`; the output files
  are correct UTF-8.
- End-to-end tests in `tests/test_pipeline.py` assert exact counts for the
  sample files. If you change a sample, update those tests and
  `data/samples/README.md`.
- A future API must not accept arbitrary filesystem paths; resolve inputs
  inside an allow-listed data directory.
- AIT-ADS layout in `data/raw/ait_ads/`: `<scenario>_{wazuh,aminer}.json`
  (from Zenodo `ait_ads.zip`), `labels.csv` (Zenodo), and
  `alerts_csv/alerts_csv/<scenario>_alerts.txt` (unpacked from GitHub
  `ait-aecid/alert-data-set` `alerts_csv/alerts_csv.zip`, commit `5459b57`).
  Missing alerts_csv → event labels `not_provided`, not an error.
- alerts_csv's `name` column is unquoted and can contain commas: parse with
  `iter_event_label_rows` (splits from both ends), never with `csv`.
- Shaw has 16 fast.log records with no eve.json twin (TLS decoder SIDs
  2230003/2230010, 2022-01-26 12:13:36); they are Suricata alerts with
  `fast_log_unmatched=True` (russellmitchell: 0).
- After changing ingest logic, re-run `ingest-alerts` for the dev
  scenarios before `variants`: the pool is read from `data/processed/`.
- Suricata `event_label`s were produced by the dataset authors from AIT-NDS
  netflow matching, and very few Suricata alerts carry one (dev: 44/9,186
  and 0/16,708); see docs/session-notes.md before interpreting Suricata
  results.
- Agent run logs (`data/processed/runs/`) hold full transcripts and grow
  with every run; they are git-ignored. `--fake-responses` runs land there
  too (model id `fake`).
- On russellmitchell the first attack case in time order is
  `network_scans`, an unreachable phase, so `--limit 2` there pairs an
  unreachable attack case with a benign one.
- Case manifests can be large-ish (ids for up to 100 alerts x variants x
  cases); they live in git-ignored `data/processed/cases/`.
- The earliest-100 cap drops thousands of attack-labelled alerts in the
  dirb/wpscan cases (dev); ceilings after the cap equal those before it on
  the dev scenarios, but check `coverage_ceiling_before_cap` whenever the cap
  or padding changes. With `spread`, shaw's fused `cracking` case loses all 3
  of its event-labelled alerts (547 in window), so its fused event ceiling
  is 6/10 after the cap vs 7/10 before.
- AMiner `training_mode` and `aggregate` overlap (a record can be both), so
  eligible counts are not simple subtractions.
- `test_alert_pipeline.py` asserts exact counts for `data/samples/synthetic_ait_ads/`;
  update it and `data/samples/README.md` if you change those files.
- Wazuh alerts carry native ATT&CK ids in `rule.mitre.id` (dev: T1078 on the
  dovecot authentication_success alerts dominates); Suricata and AMiner carry
  none. Map only native ids and `RULE_TABLE` rows; never guess.
- pySigma 2.0.2 parses all 256 approved rules (rules/linux, rules/web) with 0
  errors, but ships no in-process backend: `sigma_engine.py` evaluates
  `parsed_condition[i].parse()` itself. 166 rules are skipped by reason
  (process_creation 123, proxy 29, file_event 8, network_connection 5,
  nginx 1): their fields are not in these logs. Never add a field mapping
  that the log line does not carry; the mapping table is the module docstring.
- Sigma sees only lines another detector already alerted on (no AIT-LDSv2):
  its dev numbers are a re-detection rate over the pool, labelled
  "dev detection baseline", never a detector comparison.
- Triage severity is a first-match table (`SEVERITY_TABLE`, rows H1-H3, M1-M3, L1), each row
  tested. Level classes are triage-only (Wazuh >= 12 high, 7-11 medium; Suricata 1 high, 2
  medium; Sigma critical/high, medium); `Alert.severity` is never rescaled. A rebuild deletes the
  scenario's incidents except those a report refers to. Report the gap with every incident number.
- Study code iterates `AIT_ADS_DETECTORS`, never `Detector`: `Detector.SIGMA`
  exists for the platform, and a study variant `sigma` appears only if
  `variants.extra_detectors` lists it (it does not). `test_frozen_sections_are_unchanged`
  pins a sha256 of `split` + the frozen detector order in study.json.
- The CICIDS2017 MachineLearningCSV URL returns an HTML registration page,
  not the zip: check the content type of any dataset download.
- The internet here can be slow (~100 kB/s): run downloads in the background
  and use `git -c http.postBuffer=524288000 push` for large pushes.
- Heredocs with quotes can fail in this Git Bash; write multi-line scripts to
  a scratch file with the Write tool and run that instead.

## Conventions

Python 3.11+, type hints everywhere (mypy strict passes), PEP 8 naming,
`from __future__ import annotations`, module docstrings that explain the
"why". Tests are deterministic and use `tmp_path` for files.

## Build loop (standing rule: how we work)

Nested loops. Do not skip a level.

1. **Outer loop, per wave unit** (one sub-milestone = one small, testable
   slice, committed on the wave's `phase3/wave-<x>` branch): plan -> inner
   loop until done -> update this file -> commit -> report. At the end of a
   wave (or of a work day): session notes, push, open a PR to `main` and
   merge it (user decision 2026-11-07).
2. **Inner loop, per component:** write the test first -> implement ->
   `pytest` -> `mypy` -> fix -> repeat until both are clean. Never report a
   component done on a red run; report real command output.
3. **Innermost loop, per failure:** read the actual error, change one thing,
   re-run. After 3 failed attempts on the same error, stop and ask.
4. **Close of every milestone:** update CLAUDE.md (status table, layout,
   gotchas, any new rule) in the same commit as the code. If code and this
   file disagree, the code wins and this file gets fixed.
5. **No Claude attribution** in commit messages or PRs (no
   `Co-Authored-By: Claude` trailer, no "Generated with Claude Code" line;
   user decision 2026-11-07). Never force-push.
6. **When the user asks for a CLAUDE.md prompt:** give a copy-pasteable prompt
   that regenerates/updates this file from the current repo state, and keep
   this file updated on every change thereafter.

Rules for the study code: metrics are computed from event IDs and field
values only (no LLM judge); real datasets go into `data/raw/` and are only
downloaded by an assistant when the user authorizes that specific file (list
name and size first, verify the published checksum); format knowledge about a
real dataset is never guessed, only encoded after inspecting actual files.
