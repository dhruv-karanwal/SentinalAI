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

## AIT Alert Data Set (AIT-ADS)

- Source: Landauer, Skopik, Wurzenberger, *AIT Alert Data Set*, version 1,
  2023-08-18, Zenodo, DOI 10.5281/zenodo.8263181 (open access).
  **Licence as shown on the Zenodo record page: "Creative Commons
  Attribution 4.0 International" (`cc-by-4.0`).** Results built on it must
  cite the dataset.
- Event labels: `alerts_csv/alerts_csv.zip` from the GitHub repository
  `ait-aecid/alert-data-set` (commit `5459b57`, 3,429,496 bytes; git blob
  SHA-1 `052151d3c05b2dc69da93290d56d97e29f572c39` verified; SHA-256
  `2bf1a81527a3fe15d92079a7834c9d77c5305546e15569657d2097d6294825c3`).
  **Repository licence: GNU General Public License v3.0 (`GPL-3.0`).** Only
  its data file is used; none of its code is copied into this repository.
- Detector types: Wazuh rule-based, Suricata signature-based (its alerts are
  collected inside the Wazuh files), AMiner anomaly-based (the dataset
  README: "we utilize these logs for anomaly detection with AMiner").
- Ground truth is a separate layer joined by alert id and never an agent or
  model input:
  - `time_label`: the attack phase from `labels.csv` whose half-open
    interval `[start, end)` contains the alert time, else `false_positive`.
    It labels *time*, not causation: a benign alert inside an attack window
    still gets the phase name.
  - `event_label`: the dataset authors' per-event label, linked to alerts by
    file position and verified per row; unavailable where the link fails.
- Excluded from evaluation variants by default (kept in the data, counted
  in the quality report): AMiner training-mode alerts, Wazuh `fast.log`
  copies of Suricata alerts, and (for investigation) AMiner aggregate
  alerts. Any variant that includes them must say so.
- The alerts carry no log-event IDs. Event-ID metrics need a log dataset
  with real IDs (AIT-LDSv2); IDs are never derived from alert content.

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
