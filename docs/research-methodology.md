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
  an attack-phase interval). Every output (ground truth file, variant and
  case manifests, dev reports) carries both, and every variant is reported
  under both.

### Limitation: Suricata event labels

The dataset authors did not label Suricata alerts the way they labelled
Wazuh and AMiner alerts. Wazuh and AMiner alerts get an `event_label` when
their raw log line matches a labelled line of AIT-LDSv2; Suricata alerts
get one only when their flow 5-tuple matches a labelled AIT-NDS netflow
within 2 s (and, for one `.biz` DNS rule in two scenarios, a labelled DNS
log line). In the dev scenarios only 44/9,186 (russellmitchell) and
0/16,708 (shaw) investigation-eligible Suricata alerts carry an attack
`event_label`, against 213 and 204 by `time_label`. Low Suricata precision
under `event_label` may therefore partly reflect this labelling method, not
only the detector. Suricata results must be reported under both labels,
with this caveat. The low Suricata base rate is accepted as it is; it is
not corrected.

## Alert-source variants

All variants are subsets of one pool per scenario: the investigation-
eligible alerts (no training-mode, duplicate or aggregate alerts).

- `wazuh`, `suricata`, `aminer`: one detector.
- `fused`: union of the three (the whole pool), time-ordered, each alert once.
- `oracle`: pool alerts with an attack `event_label`, i.e. a perfect detector
  restricted to what the detectors already raised.
- `random-wazuh`, `random-suricata`, `random-aminer` (the default random
  controls): a seeded uniform draw from the pool with the count of that
  detector's variant. `random-fused` would be the whole pool (the pool *is*
  the union of the detectors), so it is written only as a manifest, flagged
  `degenerate` and `experiment_variant: false`, and is never used as a
  variant. A random control at the fused volume would need a population
  larger than the alert pool (e.g. raw log events), which is out of scope.

Detector-level triage (verdict = "alert is in the variant", over the pool)
uses `app/evaluation/metrics.py`. These scores describe the alert sources,
not the agent.

## Study unit: cases (M4)

The unit of investigation is a **case**: a time window of one scenario plus
the alerts one variant raised in it. (The M3 per-variant 20-alert study
sample was retired in favour of cases; its stratification decision no
longer applies.)

- **Attack cases:** one per (scenario, attack phase) of `labels.csv`, window
  = the phase interval `[start, end)` widened by `padding_seconds` (default
  0) on both sides.
- **Benign cases:** per attack case, `benign_per_attack` (default 1) windows
  of the same length. Whole-second starts are drawn uniformly (seed
  20261031, derived per scenario) from every start whose padded window
  lies inside the observation range (first to last investigation-eligible
  alert), outside every attack interval widened by the padding, and
  disjoint from the benign windows already drawn. Attack cases are
  processed in time order. Cases that do not fit are listed as
  `unavailable`, never invented. Matching on length keeps attack and benign
  cases comparable in time span; their alert volumes differ, and that
  difference is part of what a source contributes.
- **Alerts per case:** the variant's alerts with
  `window_start <= timestamp < window_end`, time-ordered, capped at
  `max_alerts` (default 100) by the `earliest` rule (first 100 by time,
  the order an analyst queue shows them). Every case manifest records,
  per variant: the alerts in the window, those kept, those dropped, how
  many dropped alerts were attack-labelled (by event_label and by
  time_label), and the rule. The cap is not neutral: in the large web-scan
  phases (dirb, wpscan) it drops thousands of attack-labelled alerts. That
  is reported for every case.

### Case-level scores (deterministic, no LLM)

- Attack-step coverage by time (primary for cases, because a case is
  defined by its phase interval): the phase is covered if at least one
  cited alert of the case lies inside the phase interval.
- The same with `event_label` (sensitivity): only cited alerts with an
  attack event_label count.
- Unsupported-claim rate: `Claim(record_id=alert_id, field, value)`
  checked by exact (stripped) string match against the case's own alert
  records: canonical fields, `raw_alert.*`, and whole raw log lines
  (`evidence.log_lines.<i>`). Claims about alerts outside the case are
  unsupported.
- Investigation load: number of alerts in the case after the cap.

**Coverage ceilings** score each case as if the agent cited every alert it
was given. They bound what any agent can reach from a source and are
reported as ceilings, not agent results.

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
