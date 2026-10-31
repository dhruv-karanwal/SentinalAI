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
  records that have an `eve.json` twin (copies of a Suricata alert), and
  (for investigation) AMiner aggregate alerts (`CountData`/`FrequencyData`).
  Any variant that includes them must say so. A `fast.log` record *without*
  an `eve.json` twin is the only copy of that Suricata detection; it is a
  Suricata alert flagged `fast_log_unmatched` (16 in shaw, 0 in
  russellmitchell). AMiner `MatchValueAverageChangeDetector` alerts
  summarize a window but carry no aggregate data block; they are treated as
  ordinary event alerts.
- The alerts carry no log-event IDs and AIT-LDSv2 is deliberately not used
  (decision of 2026-10-31): `event_ids` stay empty, and the investigation
  verifier checks claims against fields of the alert record and the raw log
  lines it carries. IDs are never derived from alert content.

## Scenario split (frozen 2026-10-31)

| Split | Scenarios | Use |
|-------|-----------|-----|
| dev | russellmitchell, shaw | development, debugging, dev-only scoring |
| held-out | fox, harrison, santos, wardbeck, wheeler, wilson | final test runs only |

The split is decided before any test run and is stored in
`experiments/config/study.json`. Dev-only code (currently the `variants`
command and `dev_triage_report`) calls `ScenarioSplit.require_dev` and
refuses a held-out scenario; a test enforces this for every held-out
scenario. The dev scenarios were inspected during M2 for file structure and
label alignment only.

## Truth labels

- **Primary:** `event_label`. An alert is an attack when the dataset assigns
  it an event label (any value); benign when the label is `-`.
- **Sensitivity analysis:** `time_label` (attack when the alert falls inside
  an attack-phase interval). Every output (ground truth file, variant
  manifests, dev reports) carries both, so either can be computed.

## Alert-source variants

All variants are subsets of one pool per scenario: the investigation-
eligible alerts (no training-mode, duplicate or aggregate alerts).

- `wazuh`, `suricata`, `aminer`: one detector.
- `fused`: union of the three (the whole pool), time-ordered, each alert once.
- `oracle`: pool alerts with an attack `event_label` — a perfect detector
  restricted to what the detectors already raised.
- `random-<ref>`: seeded uniform draw from the pool with the count of
  variant `<ref>`. **Limitation:** because the pool is the union of the
  detectors, `random-fused` is the whole pool (flagged `degenerate` in its
  manifest). Size-matched random controls for each single detector
  (`random-wazuh`, ...) are the informative ones; a random control at the
  fused volume would need a population larger than the alert pool (e.g.
  raw log events), which is out of scope without AIT-LDSv2.

Detector-level triage (verdict = "alert is in the variant", over the pool)
uses `app/evaluation/metrics.py`. These scores describe the alert sources,
not the agent.

## Study sample and stratification (decision)

The study sample is drawn per scenario from a variant (default `fused`,
N = 20, seed 20261031, all in `experiments/config/study.json`) by
`study_sample`. Each manifest records the base seed, the derived seed, the
rule and the stratum sizes.

**Decision: proportional stratification on `event_label`, no
rebalancing.** The N alerts are allocated to the attack and benign strata
in proportion to their share in the source variant (largest-remainder
rounding), then drawn uniformly within each stratum. Justification:

- The study varies the alert source, and a source's attack share
  (precision) is the property under test. Rebalancing to, say, 50/50 would
  give every source the same attack share and erase that difference, and
  would overstate how often analysts see real attacks.
- With N = 20, a simple random draw can easily miss the few attack alerts
  of a low-precision source by chance; proportional allocation fixes the
  count to the expected value and removes that variance without changing
  the proportion.
- Using the label for allocation does not expose it to the agent; the
  agent sees only the `Alert` records.

Consequences that must be reported with results: the sample's attack share
equals the source's (to rounding), so a low-precision source yields very
few attack alerts per scenario (dev: fused gives 6/20 in russellmitchell and
2/20 in shaw). `class_balance_changed` is recorded as `false` in every
sample manifest. A balanced design, if ever wanted, must be a separate,
named option that sets it to `true`.

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
