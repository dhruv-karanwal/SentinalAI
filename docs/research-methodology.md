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
- `noise-wazuh`, `noise-suricata`, `noise-aminer` (**the random control**,
  decision of M4b): alerts whose `event_label` is benign, count-matched to
  the reference detector. In cases they are rebuilt per case: as many
  alerts as the detector has in the case window, drawn from event-benign
  alerts of the same window first, then from the scenario pool's other
  event-benign alerts (which then lie outside the window). Each case
  manifest records the split (`from_window`, `from_fallback`, `shortfall`).
  At scenario level (triage tables) it is a seeded draw of the detector's
  count from the pool's event-benign alerts. It measures what an agent does
  when its alert source is pure noise at a real detector's volume.
- `shuffled-wazuh`, `shuffled-suricata`, `shuffled-aminer` ("shuffled-pool"
  rows, the M3 random controls, kept for comparison): a seeded uniform draw
  from the whole pool with the detector's count. `shuffled-fused` would be
  the whole pool, so it is written only as a manifest, flagged `degenerate`
  and `experiment_variant: false`.

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
  of the same length. They are deliberately *not* matched on time of day;
  every case manifest records the UTC time of day of each window's start and
  end so the difference can be reported. Whole-second starts are drawn uniformly (seed
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
  `max_alerts` (default 100). Default rule `spread` (decision of M4b): keep
  the alerts at time ranks `floor((i + 0.5) * n / 100)`, i = 0..99, so the
  kept alerts are spread evenly over the window. `earliest` (first 100 by
  time) remains an option. Every case manifest records, per variant: the
  rule used, the alerts in the window, those kept, those dropped, and how
  many dropped alerts were attack-labelled (by event_label and by
  time_label). The cap is not neutral: in the large web-scan phases it
  drops thousands of attack-labelled alerts, and in the dev scenario shaw
  the `spread` rule drops all 3 event-labelled alerts of the 547-alert
  `cracking` case of the fused source (the `earliest` rule kept them).

### Case-level scores (deterministic, no LLM)

- Attack-step coverage by time (primary for cases, because a case is
  defined by its phase interval): the phase is covered if at least one
  cited alert of the case lies inside the phase interval.
- The same with `event_label` (sensitivity): only cited alerts with an
  attack event_label count.
- Coverage is reported over **all** attack phases and over the
  **alert-reachable** subset: phases where at least one investigation-
  eligible alert of any detector has an attack event_label inside the phase
  interval. Unreachable phases (dev: network_scans, reverse_shell, dnsteal
  in russellmitchell; dnsteal, service_scans, reverse_shell in shaw) are
  listed in every report; no alert source can cover them by event_label.
- Citation precision: fraction of the distinct cited ids that are case
  alerts with an attack event_label (primary), and the fraction inside the
  case's phase interval (time version; 0 for benign cases). Cited ids that
  are not alerts of the case count as wrong citations.
- Unsupported-claim rate, `Claim(record_id=alert_id, ...)` against the
  case's own alert records, two kinds (decision of M4b):
  - *field-value*: the flattened record (canonical fields, `raw_alert.*`,
    `evidence.log_lines.<i>`) has `field == value`, exact after stripping;
  - *quote*: `value` is an exact, case-sensitive substring of one of the
    alert's raw log lines (`evidence.log_lines`), at least 8 characters, no
    whitespace or case normalization.
  Claims about alerts outside the case are unsupported. Positional
  `Claim(id, field, value)` remains a field-value claim.
- Investigation load: number of alerts in the case after the cap.

**Coverage ceilings** score each case as if the agent cited every alert it
was given. They bound what any agent can reach from a source and are
reported as ceilings, not agent results.

**Time-label coverage can be reached by noise.** Event-benign alerts that
fall inside an attack interval count as "inside the phase", so noise
controls reach up to 5/10 (russellmitchell) and 6/10 (shaw) time coverage
with 0/10 event-label coverage. Event-label coverage on the reachable
phases is the measure noise cannot inflate.

### Deterministic baselines (M4b)

`app/study/baselines.py` defines non-LLM citers that see only what an
agent sees (the case's alerts) and never look at labels: `cite-all` (its
coverage is the ceiling), `cite-none`, `cite-top-k-wazuh-level` (Wazuh
alerts by `rule.level` descending, then the rest in time order; k = 5),
`cite-top-k-detector-order` (by detector in the order aminer, wazuh,
suricata, set from the M3 dev triage precision, a dev-derived choice; then
time; k = 5) and `cite-aminer-only`. Each cited alert gets one field-value
claim (`rule_id`, else `rule_name`) and one quote claim (first 60
characters of its first raw log line, if >= 8 characters), copied from the
record; their unsupported-claim rate is 0 by construction and checks the
claim machinery on real records. These baselines are the reference points
an LLM agent must beat and are reported as baselines, not agent results.

## Pilot

The pilot runs on the dev scenarios only (`pilot.scenarios` in
`study.json`, validated as a subset of `split.dev`). Held-out scenarios
stay untouched until the final runs.

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
