# Research methodology notes

Ground rules for SentinelAI experiments. Phase 1 implements only the data
foundation; the later items are constraints that the data layer is built to
respect.

## Data provenance

- Synthetic data lives in `data/samples/`, is named `synthetic_*` and is
  used for development and tests only. It is never reported as real traffic
  or as an experimental result.
- Real datasets (e.g. CICIDS2017) are downloaded by the researcher from the
  publisher, placed in `data/raw/` (git-ignored) and used under the
  dataset's own terms.
- Every normalized event keeps its `raw_event`, source file name and
  position, so any result can be traced to the original row.

## Labels and features

- `label` holds the dataset's original ground-truth string, unchanged apart
  from whitespace stripping (e.g. `BENIGN`, `DoS Hulk`).
- `label` is never a model input. Identifiers and context fields (IPs,
  ports, timestamps, flow ids) are kept out of `features` by default; adding
  any of them as features in Phase 2 is an explicit, documented choice
  because they can leak the label in CICIDS2017.

## Data quality before modelling

- Each run produces a quality report: rejected records by reason, missing
  values, duplicates, timestamp failures, label distribution and feature
  statistics.
- Class imbalance is reported, not corrected, in Phase 1. Splitting,
  resampling and class weighting are Phase 2 decisions and must be applied
  to training data only.
- CICIDS2017 is known to contain duplicate flows and non-finite values
  (`Infinity`, `NaN`). The report counts them (`duplicate_raw_records`,
  `duplicate_feature_vectors`, `non_finite_count`); how to handle them is an
  experimental decision for Phase 2, to be documented with the results.

## Reproducibility

- Pipeline runs are deterministic for a given input file, mapping and
  options; the options in effect (mapping, row limit, dataset name) are
  written into the quality report.
- Tests use only committed synthetic data and need no network access.
