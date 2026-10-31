# CLAUDE.md — SentinelAI

Context for AI assistants working in this repository.

## Project

**SentinelAI — Autonomous AI-Powered Security Operations Center (SOC).** A
research-oriented platform for AI-assisted cybersecurity investigation,
built in phases.

| Phase | Scope | Status |
|-------|-------|--------|
| 1 — Data foundation | Load CSV/JSON/JSONL, validate, normalize to a canonical schema, data-quality report | **Done** |
| 2 — Study foundation | Deterministic evaluation metrics, AIT-ADS alert schema and loader, detector baselines (ML dataset prep for CICIDS2017 baselines) | **In progress** (user approved start; metrics done) |
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
```

Setup: `python -m venv .venv` then `pip install -r backend/requirements-dev.txt`.
Test and mypy configuration lives in `backend/pyproject.toml` (`pythonpath = ["."]`,
so imports are `from app...`). There is no linter configured.

## Layout

```
backend/app/
  main.py                 CLI: `python -m app.main ingest PATH [options]`
  pipeline.py             load → normalize → quality report; writes outputs
  schemas/event.py        canonical SecurityEvent (Pydantic v2)
  ingestion/records.py    RawRecord, IngestionError, file checks
  ingestion/csv_loader.py streaming CSV (header cleaning, row-shape errors)
  ingestion/json_loader.py JSON array / {"records": [...]} / JSON Lines
  ingestion/mappings.py   DatasetMapping registry: cicids2017, generic
  ingestion/normalizer.py mapping + parsing → SecurityEvent | Rejection
  services/data_quality.py streaming DataQualityAccumulator
  evaluation/metrics.py   judge-free metrics: triage P/R/F1/FNR, attack-step coverage, unsupported-claim rate
backend/tests/            pytest, one file per module + test_pipeline.py (end to end)
data/samples/             committed SYNTHETIC samples (see its README)
data/raw/, data/processed/ git-ignored: local datasets and pipeline outputs
docs/                     architecture.md, research-methodology.md
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
- **Minimal dependencies:** runtime is `pydantic` only.

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
values only (no LLM judge); real datasets are downloaded by the user into
`data/raw/` (the cloud sandbox cannot reach Zenodo); format knowledge about a
real dataset is never guessed, only encoded after inspecting actual files.
