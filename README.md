# SentinelAI — Autonomous AI-Powered Security Operations Center

SentinelAI is a research-oriented platform for AI-assisted cybersecurity
investigation. It is being built in phases. **Only Phase 1, the data
foundation, is implemented so far.** There are no AI agents, LLM
integration, retrieval, model training or frontend yet.

Phase 1 is a tested pipeline that:

1. loads security events from CSV, JSON and JSON Lines files
2. validates each record and normalizes it into one canonical
   `SecurityEvent` schema (Pydantic)
3. keeps the original record (`raw_event`) and the dataset's ground-truth
   label
4. reports invalid records instead of dropping them, with a reason and
   position for each one
5. writes a data-quality report (counts, rejections, missing values,
   duplicates, timestamps, label distribution, feature statistics)

The first target dataset is a manageable sample of **CICIDS2017**, to be
used later for supervised network intrusion detection experiments. No
dataset is downloaded automatically.

## Prerequisites

- Python 3.11 or newer
- No network access is needed at runtime or to run the tests (only to
  install dependencies)

## Installation

```bash
python -m venv .venv
# Windows (PowerShell):  .venv\Scripts\Activate.ps1
# Windows (Git Bash):    source .venv/Scripts/activate
# Linux/macOS:           source .venv/bin/activate
pip install -r backend/requirements-dev.txt   # or backend/requirements.txt for runtime only
```

Runtime dependency: `pydantic`. Development: `pytest`, `mypy`.

## Repository structure

```text
.
├── backend/
│   ├── app/
│   │   ├── main.py                 CLI entry point
│   │   ├── pipeline.py             load → normalize → report, output writing
│   │   ├── schemas/event.py        canonical SecurityEvent schema
│   │   ├── ingestion/
│   │   │   ├── records.py          RawRecord, IngestionError, file checks
│   │   │   ├── csv_loader.py       streaming CSV loader
│   │   │   ├── json_loader.py      JSON array / JSON Lines loaders
│   │   │   ├── mappings.py         dataset mappings (cicids2017, generic)
│   │   │   └── normalizer.py       mapping + validation → event or rejection
│   │   └── services/data_quality.py
│   ├── tests/                      pytest suite (synthetic data only)
│   ├── pyproject.toml              pytest and mypy configuration
│   ├── requirements.txt
│   └── requirements-dev.txt
├── data/
│   ├── raw/          local datasets (git-ignored)
│   ├── processed/    pipeline outputs (git-ignored)
│   └── samples/      small SYNTHETIC samples (committed)
├── docs/
│   ├── architecture.md
│   └── research-methodology.md
└── experiments/      reserved for Phase 2
```

## Running the pipeline

Run the commands from `backend/`:

```bash
cd backend

# Synthetic CSV in the CICIDS2017 column layout
python -m app.main ingest ../data/samples/synthetic_cicids2017_format.csv \
    --mapping cicids2017 --dataset-name synthetic-cicids2017-format

# Synthetic JSON (array under "records") and JSON Lines, generic mapping
python -m app.main ingest ../data/samples/synthetic_security_events.json
python -m app.main ingest ../data/samples/synthetic_security_events.jsonl
```

Options:

| Option | Meaning |
|--------|---------|
| `--mapping {cicids2017,generic}` | column mapping (default `generic`) |
| `--format {auto,csv,json,jsonl}` | input format; `auto` uses the extension |
| `--limit N` | read at most N input records (valid or not) |
| `--encoding ENC` | file encoding (default `utf-8`) |
| `--dataset-name NAME` | dataset name for records that don't carry one |
| `--assume-timezone TZ` | timezone for naive timestamps: `UTC`, `+HH:MM`, `-HH:MM`, or `none` to reject them |
| `--output-dir DIR` | output directory (default `data/processed/`) |
| `--no-output` | print the summary only |

Outputs, named after the input file:

- `<stem>.events.jsonl`: normalized events, one `SecurityEvent` per line
- `<stem>.rejected.jsonl`: rejected records with every error and the raw data
- `<stem>.quality.json`: data-quality report

The exit code is 0 when the file was processed (even if some records were
rejected) and 1 when the file itself can't be processed (missing, empty,
undecodable, wrong structure).

## Example output

Actual output for the synthetic CSV sample (14 rows, 5 of them invalid on
purpose):

```text
Source:     synthetic_cicids2017_format.csv (csv, mapping=cicids2017)
Records:    14 input, 9 normalized, 5 rejected
  rejected  empty_record: 1
  rejected  invalid_feature: 1
  rejected  invalid_ip: 1
  rejected  invalid_timestamp: 1
  rejected  malformed_record: 1
Timestamps: 8 parsed, 1 missing, 1 parse failures
Duplicates: 1 raw records, 0 event ids, 1 feature vectors
Labels:     8 labelled, 1 unlabelled
  BENIGN: 4 (50.00%)
  DoS Hulk: 2 (25.00%)
  PortScan: 1 (12.50%)
  Web Attack – Brute Force: 1 (12.50%)
Features:   7
```

Excerpt from `synthetic_cicids2017_format.quality.json`:

```json
{
  "record_counts": {"total_input": 14, "normalized": 9, "rejected": 5},
  "duplicates": {
    "duplicate_event_ids": 0,
    "event_ids_derived": 9,
    "duplicate_raw_records": 1,
    "duplicate_feature_vectors": 1
  },
  "timestamps": {
    "parsed": 8, "missing": 1, "parse_failures": 1, "timezone_assumed": 8,
    "min": "2017-07-03T11:55:00+00:00", "max": "2017-07-07T16:45:10+00:00"
  },
  "rejections": {
    "examples": [
      {
        "source_position": 10,
        "category": "invalid_ip",
        "messages": ["source_ip: value is not a valid IPv4 or IPv6 address (got '192.168.10.300')"]
      }
    ]
  }
}
```

These numbers describe synthetic test data. They are not results about
CICIDS2017.

## Using a local CICIDS2017 file

1. Download CICIDS2017 from the Canadian Institute for Cybersecurity
   (University of New Brunswick) and accept its terms. The
   `GeneratedLabelledFlows` (TrafficLabelling) CSVs include IPs, ports and
   timestamps. The `MachineLearningCVE` CSVs don't, and those fields are then
   left empty.
2. Copy one CSV into `data/raw/` (git-ignored), for example
   `data/raw/Tuesday-WorkingHours.pcap_ISCX.csv`.
3. Start with a row limit:

   ```bash
   cd backend
   python -m app.main ingest ../data/raw/Tuesday-WorkingHours.pcap_ISCX.csv \
       --mapping cicids2017 --limit 50000
   ```

4. If you get a decode error (the original files contain cp1252 bytes, e.g.
   the dash in `Web Attack – Brute Force`), add `--encoding cp1252`.

What the `cicids2017` mapping does:

- strips header whitespace (`" Destination Port"`) and renames the repeated
  `Fwd Header Length` column to `Fwd Header Length.1`
- parses day-first timestamps (`3/7/2017 8:55` is 3 July 2017) and assumes
  **UTC-03:00** (ADT, the capture site's local time). This is a documented
  assumption, which you can override with `--assume-timezone`.
- maps protocol numbers 6/17/1 to `tcp`/`udp`/`icmp` and keeps others as
  numbers (e.g. `0`)
- puts all remaining columns in `features` as numbers. `Infinity` is kept
  as infinity and `NaN` is treated as missing.
- keeps `Label` unchanged and out of `features`; `Flow ID` goes into
  metadata (it isn't unique in CICIDS2017)
- derives `event_id` as `<file name>:<line number>`

## Tests and type checks

```bash
cd backend
python -m pytest        # 124 tests, synthetic data only, no network
python -m mypy          # strict mode over app/
```

## Canonical schema (summary)

| Field | Notes |
|-------|-------|
| `event_id` | source id, or derived `<file>:<position>` when the mapping allows it |
| `timestamp` | timezone-aware, stored in UTC; naive values need an explicit assumption |
| `source_type` | `network`, `endpoint`, `authentication`, `application`, `unknown` |
| `source_ip`, `destination_ip` | IPv4/IPv6, validated |
| `source_port`, `destination_port` | 0–65535 |
| `protocol` | lower-case name or IANA number string |
| `event_type` | e.g. `network_flow`, `login_failure` |
| `severity` | `informational`, `low`, `medium`, `high`, `critical` |
| `label` | original ground truth; never a feature |
| `features` | scalar candidate model inputs |
| `raw_event` | original record (required) |
| `dataset_name`, `metadata` | provenance (source file, position, assumptions, unmapped field names) |

Only `raw_event` is required. Missing values are `None` and are never
filled in. See `backend/app/schemas/event.py` and `docs/architecture.md`.

## Current limitations

- JSON documents (not JSON Lines) are parsed in memory; use JSON Lines for
  large inputs.
- Duplicate detection keeps a 16-byte hash per record, so memory grows with
  file size (roughly a few hundred MB for all 2.8M CICIDS2017 rows). Use
  `--limit` for quick runs.
- One file per run; there is no directory or multi-file merge yet.
- Some CICIDS2017 files reportedly write afternoon times in 12-hour form
  without AM/PM. The pipeline can't detect this and doesn't correct it.
- The generic mapping only looks at top-level fields (plus a nested
  `features` object). Nested source structures stay in `raw_event`.
- The `cicids2017` mapping has been tested on synthetic rows in the
  CICIDS2017 layout, not on the full real dataset.
- No API, database or persistence beyond JSONL/JSON files.

## Next milestone — Phase 2

Detection baselines and ML dataset preparation: build feature matrices from
`events.jsonl`, decide how to handle duplicates and non-finite values, split
data by day or attack scenario without leakage, and run baseline classifiers
with documented, reproducible evaluation.
