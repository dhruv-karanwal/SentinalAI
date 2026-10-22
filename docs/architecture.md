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
