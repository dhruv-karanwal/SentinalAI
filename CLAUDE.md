# CLAUDE.md — SentinelAI

Context for AI assistants working in this repository.

## Project

**SentinelAI — Autonomous AI-Powered Security Operations Center (SOC).** A
research-oriented platform for AI-assisted cybersecurity investigation,
built in phases.

| Phase | Scope | Status |
|-------|-------|--------|
| 1 — Data foundation | Load CSV/JSON/JSONL, validate, normalize to a canonical schema, data-quality report | **Done** |
| 2 — Study foundation | Deterministic evaluation metrics, AIT-ADS alert schema and loader, detector baselines (ML dataset prep for CICIDS2017 baselines) | **In progress**: metrics done; M2 alert schema + AIT-ADS loader done; next M3 alert-source variants |
| 3 — Investigation agents | Single tool-using agent, multi-agent + event-ID verifier, local 7-9B model | Not started |
| Later | Demo UI, RAG over ATT&CK polish | Not started |

Do not start a later phase, or add agents, LLMs, RAG, Kafka, vector databases,
LangGraph or a frontend, unless the user asks for it. The paper's scope is the
detector-conditioned study in `docs/` and the Google Doc draft; build only
what that study needs.

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
```

`tests/test_ait_ads_real.py` runs on the real russellmitchell files when
`data/raw/ait_ads/` holds them and skips otherwise (~2 s).

Setup: `python -m venv .venv` then `pip install -r backend/requirements-dev.txt`.
Test and mypy configuration lives in `backend/pyproject.toml` (`pythonpath = ["."]`,
so imports are `from app...`). There is no linter configured.

## Layout

```
backend/app/
  main.py                 CLI: `ingest PATH [options]`, `ingest-alerts --data-dir D --scenario S`
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
  evaluation/metrics.py   judge-free metrics: triage P/R/F1/FNR, attack-step coverage, unsupported-claim rate
backend/tests/            pytest, one file per module + test_pipeline.py (end to end)
data/samples/             committed SYNTHETIC samples (see its README)
data/raw/, data/processed/ git-ignored: local datasets and pipeline outputs
data/samples/synthetic_ait_ads/ SYNTHETIC files in the AIT-ADS shapes (scenario "synthetic")
docs/                     architecture.md, research-methodology.md, session-notes.md
experiments/              Phase 2 experiment scripts (none yet)
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
- **Minimal dependencies:** runtime is `pydantic` only (M2 added none).

## AIT-ADS alerts (M2 policies, decided by the user)

- **Detectors.** Suricata alerts live inside `<scenario>_wazuh.json`:
  `location == /var/log/suricata/eve.json` → `suricata` (signature-based);
  `location == /var/log/suricata/fast.log` → `wazuh` record flagged
  `duplicate_of_suricata=True`; every other Wazuh record → `wazuh`
  (rule-based). `<scenario>_aminer.json` → `aminer` (anomaly-based). The
  detector→type map is `DETECTOR_TYPES` in `schemas/alert.py`.
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
  log-event IDs, and IDs are never invented (AIT-LDSv2 would be needed;
  user decides before M6).
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
  2230003/2230010, 2022-01-26 12:13:36). They are still flagged duplicates;
  the report counts them as `fast_log_unmatched`.
- AMiner `training_mode` and `aggregate` overlap (a record can be both), so
  eligible counts are not simple subtractions.
- `test_alert_pipeline.py` asserts exact counts for `data/samples/synthetic_ait_ads/`;
  update it and `data/samples/README.md` if you change those files.

## Conventions

Python 3.11+, type hints everywhere (mypy strict passes), PEP 8 naming,
`from __future__ import annotations`, module docstrings that explain the
"why". Tests are deterministic and use `tmp_path` for files.

## Build loop (standing rule: how we work)

Nested loops. Do not skip a level.

1. **Outer loop, per milestone** (one milestone = one small, testable slice of
   the study, on its own `phase2/<name>` branch):
   plan -> inner loop until done -> update this file -> commit -> report.
2. **Inner loop, per component:** write the test first -> implement ->
   `pytest` -> `mypy` -> fix -> repeat until both are clean. Never report a
   component done on a red run; report real command output.
3. **Innermost loop, per failure:** read the actual error, change one thing,
   re-run. After 3 failed attempts on the same error, stop and ask.
4. **Close of every milestone:** update CLAUDE.md (status table, layout,
   gotchas, any new rule) in the same commit as the code. If code and this
   file disagree, the code wins and this file gets fixed.
5. **When the user asks for a CLAUDE.md prompt:** give a copy-pasteable prompt
   that regenerates/updates this file from the current repo state, and keep
   this file updated on every change thereafter.

Rules for the study code: metrics are computed from event IDs and field
values only (no LLM judge); real datasets go into `data/raw/` and are only
downloaded by an assistant when the user authorizes that specific file (list
name and size first, verify the published checksum); format knowledge about a
real dataset is never guessed, only encoded after inspecting actual files.
