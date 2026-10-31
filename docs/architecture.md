# Architecture — Phase 1: Data Foundation

```
Input CSV / JSON / JSONL
        │
        ▼
 Loader (csv_loader / json_loader) ── file-level problem ──► IngestionError (run aborts)
        │  RawRecord(source, position, data | error)
        ▼
 Normalizer + DatasetMapping ─────── record-level problem ─► Rejection(errors, raw data)
        │  SecurityEvent (Pydantic-validated)                      │
        ▼                                                          ▼
 DataQualityAccumulator ◄──────────────────────────────────────────┘
        │
        ▼
 data/processed/<stem>.events.jsonl    clean events for Phase 2
 data/processed/<stem>.rejected.jsonl  every rejected record, with reasons
 data/processed/<stem>.quality.json    data-quality report
```

## Components

| Module | Responsibility |
|--------|----------------|
| `app/ingestion/records.py` | `RawRecord`, `IngestionError`, input-file checks |
| `app/ingestion/csv_loader.py` | Streaming CSV reader; header cleaning; row-shape errors |
| `app/ingestion/json_loader.py` | JSON array / `{"records": [...]}` and JSON Lines |
| `app/ingestion/mappings.py` | `DatasetMapping` registry (`cicids2017`, `generic`) |
| `app/ingestion/normalizer.py` | Mapping, parsing, validation → `SecurityEvent` or `Rejection` |
| `app/schemas/event.py` | Canonical `SecurityEvent` schema and validation rules |
| `app/services/data_quality.py` | Streaming quality statistics |
| `app/pipeline.py` | Wires the stages and writes outputs |
| `app/main.py` | CLI (`python -m app.main ingest ...`) |

## Design decisions

- **Two error levels.** Problems with the file as a whole (missing, empty,
  undecodable, wrong top-level JSON structure) raise `IngestionError`.
  Problems with one record become a `Rejection` that is counted, reported
  and written to `rejected.jsonl` — never dropped silently.
- **Reject, don't coerce.** An invalid timestamp, IP, port, protocol,
  severity, source type or feature value rejects the record. Every problem
  in the record is listed; the first one is its primary category.
- **Missing stays missing.** Empty strings and the tokens `NaN`, `null`,
  `N/A` become `None`. Nothing is imputed.
- **Data layers kept apart.** `raw_event` (original record), canonical
  fields, `label` (ground truth) and `features` (candidate model inputs) are
  separate. The schema rejects a feature called `label`; mapped canonical
  columns are not duplicated into `features`.
- **Streaming.** CSV and JSON Lines are read one record at a time and
  outputs are written incrementally. JSON documents are parsed whole
  (stdlib limitation). Duplicate detection keeps one 16-byte hash per
  record.
- **Configurable mappings.** Dataset knowledge (column aliases, timestamp
  formats, timezone assumption, feature selection) lives in a
  `DatasetMapping`, not in loader or normalizer code.
- **Minimal dependencies.** Runtime: `pydantic` only. No pandas, no
  database, no services; Phase 1 is a local CLI and a library.

## Timestamps

- Stored as timezone-aware UTC.
- ISO 8601 is always tried first, then the mapping's `strptime` formats.
- Naive timestamps are rejected unless the mapping configures
  `naive_timezone`; when that assumption is used, the event records it in
  `metadata.timestamp_timezone_assumed`.
- `cicids2017` assumes UTC-03:00 (Atlantic Daylight Time, the capture site's
  local time in July 2017). This is an assumption; override it with
  `--assume-timezone`.
- `generic` accepts numeric timestamps as Unix seconds (UTC).

## Security notes

- The CLI reads any path it is given; it is a local tool. A future API must
  only accept dataset identifiers or paths resolved inside an allow-listed
  data directory.
- Reports and events store the input file's base name, not its full path.
- No secrets or credentials are read or stored by Phase 1.

# Phase 2 — Alert ingest (AIT-ADS)

```
<scenario>_wazuh.json ─┐  (line by line, Wazuh first, then AMiner)
<scenario>_aminer.json ┘
        │  RawRecord
        ▼
 route_ait_ads_record (mappings.py) ── eve.json → suricata; fast.log → wazuh + duplicate flag
        │  AlertMapping
        ▼
 alert_normalizer ─────────────── record-level problem ─► Rejection
        │  Alert                                              │
        ├── AttackTimeline.label_at(timestamp) ─► time_label  │
        ├── EventLabelLinker (alerts_csv row N) ─► event_label│
        ▼                                                     ▼
 AlertQualityAccumulator ◄────────────────────────────────────┘
        │
        ▼
 data/processed/<scenario>.alerts.jsonl           Alert records (no labels)
 data/processed/<scenario>.ground_truth.jsonl     GroundTruth, joined by alert_id
 data/processed/<scenario>.alerts.rejected.jsonl  rejected records with reasons
 data/processed/<scenario>.alerts.quality.json    per-detector counts, duplicates, coverage
```

| Module | Responsibility |
|--------|----------------|
| `app/schemas/alert.py` | `Alert`, `AlertEvidence`, `GroundTruth`, `AlertSelection` |
| `app/ingestion/mappings.py` | AIT-ADS `AlertMapping`s, routing, layout, CSV conventions |
| `app/ingestion/alert_normalizer.py` | Mapping-driven parsing/validation → `Alert` or `Rejection` |
| `app/ingestion/ground_truth.py` | `labels.csv` timeline; alerts_csv reader; positional linker |
| `app/services/alert_quality.py` | Streaming per-scenario report |
| `app/alert_pipeline.py` | Wires the stages; `iter_alert_file` reads alerts back with a selection |

Design decisions specific to alerts:

- **Exclude at selection, never at ingest.** Training-mode, duplicate and
  aggregate alerts are flagged and written; `AlertSelection` decides what an
  experiment variant sees.
- **Verified positional link.** alerts_csv has no alert id. Rows are paired
  with input records by position and every pair is checked on (time, name,
  ip); linking stops at the first mismatch instead of guessing.
- **Checks run on every ingest**, not once: fast.log↔eve.json twin matching
  and the label-clock check (attack intervals inside the alert time range)
  are part of the quality report.
- **Bounded memory.** Duplicate-id and twin matching keep 16-byte digests;
  the 650 MB Wazuh files are never loaded whole.

# Phase 2 — Alert-source variants (M3)

```
data/processed/<scenario>.alerts.jsonl ─┐
data/processed/<scenario>.ground_truth.jsonl ┘
        │  AlertPool.from_processed (INVESTIGATION_SELECTION; index of byte offsets)
        ▼
 build_variants ── wazuh | suricata | aminer | fused | oracle | random-<ref>
        │                                   │
        │ study_sample (seeded, stratified) │ triage_by_truth (event_label, time_label)
        ▼                                   ▼
 data/processed/variants/<scenario>/
   <scenario>.variant.<name>.{alerts.jsonl,manifest.json}
   <scenario>.sample-<variant>.{alerts.jsonl,manifest.json}
   <scenario>.dev_triage.json               (dev scenarios only)
```

- `app/study/config.py` reads `experiments/config/study.json`; dev-only
  code calls `ScenarioSplit.require_dev`.
- The pool keeps only a small index per alert; variant alerts are re-read
  from `alerts.jsonl` by byte offset, so variant files are byte-identical
  copies of ingested records and memory stays small.

# Phase 2 — Cases and case-level scoring (M4)

```
AlertPool + labels.csv (AttackTimeline)
        │  build_cases: attack case per phase + matched benign windows (seeded)
        ▼
 for each experiment variant × case:
   case_alerts ── window [start-pad, end+pad), time-ordered, cap (earliest) ── truncation recorded
        │
        ▼
 score_case (app/evaluation/case_scoring.py)
   coverage by time / event_label (attack_step_coverage, alert ids)
   unsupported claims (Claim.record_id = alert_id vs flattened alert records)
   load = alerts in case
        │
        ▼
 data/processed/cases/<scenario>/<scenario>.cases.json          windows, sampling log, ids, truncation
 data/processed/cases/<scenario>/<scenario>.case_ceilings.json  per-variant ceilings (dev only)
```

`app.evaluation.case_scoring` imports `app.study.cases` for types only, so
the evaluation layer has no runtime dependency on the study layer.
