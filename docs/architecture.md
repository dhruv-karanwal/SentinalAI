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
