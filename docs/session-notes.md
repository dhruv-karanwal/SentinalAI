# Session notes — M2: alert schema and AIT-ADS loader

Date: 2026-10-31. Branch `phase2/alert-schema` (from `phase2/alert-foundation`
at `a6fecf7`). Code commit: `0ad0b50`. All numbers below are copied from
command output in this session; none are estimates.

## What was done

1. **Baseline (Step 0).** `phase2/alert-foundation`: 129 tests passed, mypy
   clean (15 source files).
2. **Downloads (each one authorized by the user; name and size listed
   first).**
   - Zenodo 8263181 `labels.csv`, 3,703 B, MD5
     `60ff33796c77fd2136c4d1a4bc841bd9`, matches the published checksum.
   - GitHub `ait-aecid/alert-data-set` `alerts_csv/alerts_csv.zip` at commit
     `5459b57`, 3,429,496 B. The repo publishes no MD5/SHA-256; its git blob
     SHA-1 `052151d3c05b2dc69da93290d56d97e29f572c39` was recomputed and
     matches. SHA-256 `2bf1a815…25c3`. Unpacked into
     `data/raw/ait_ads/alerts_csv/alerts_csv/` (8 files, `<scenario>_alerts.txt`).
   - The 16 `<scenario>_{wazuh,aminer}.json` files were already in
     `data/raw/ait_ads/` (unpacked by the user); they were not downloaded here.
3. **Inspection before code:** field structure of the first 20 records per
   detector, record variants across all 8 AMiner files, Suricata locations
   inside the Wazuh files, and the dataset authors' `analyze.py` (read only)
   to learn how alerts_csv rows are produced.
4. **Build (tests first):** `schemas/alert.py`, AIT-ADS section of
   `ingestion/mappings.py`, `ingestion/alert_normalizer.py`,
   `ingestion/ground_truth.py`, `services/alert_quality.py`,
   `alert_pipeline.py`, `ingest-alerts` CLI subcommand; synthetic fixtures in
   `data/samples/synthetic_ait_ads/`; tests `test_alert_schema.py`,
   `test_alert_normalizer.py`, `test_ground_truth.py`,
   `test_alert_pipeline.py`, `test_ait_ads_real.py`. No new dependency.
5. CLAUDE.md, `docs/architecture.md`, `docs/research-methodology.md`
   (licences) and `data/samples/README.md` updated in the code commit.

## Final test and type-check output

```
$ ../.venv/Scripts/python.exe -m pytest
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.1.1, pluggy-1.7.0
rootdir: D:\Projects\ERA\backend
configfile: pyproject.toml
testpaths: tests
collected 187 items

tests\test_ait_ads_real.py ..                                            [  1%]
tests\test_alert_normalizer.py .......................                   [ 13%]
tests\test_alert_pipeline.py ......                                      [ 16%]
tests\test_alert_schema.py ...........                                   [ 22%]
tests\test_data_quality.py ........                                      [ 26%]
tests\test_event_schema.py .................                             [ 35%]
tests\test_ground_truth.py ................                              [ 44%]
tests\test_ingestion.py .................................                [ 62%]
tests\test_metrics.py .....                                              [ 64%]
tests\test_normalizer.py ............................................... [ 89%]
............                                                             [ 96%]
tests\test_pipeline.py .......                                           [100%]

============================= 187 passed in 2.19s =============================

$ ../.venv/Scripts/python.exe -m mypy
Success: no issues found in 20 source files
```

`test_ait_ads_real.py` ran (not skipped) on the real russellmitchell files:
`test_real_scenario_ingest` took 1.74 s.

## Findings from the real files

**alerts_csv format and link.** Columns: `time,name,ip,host,short,time_label,event_label`.
`time` is whole epoch seconds; `name` is unquoted and may contain commas.
No alert id or line number. Per `analyze.py`, rows are written for every
Wazuh line, then every AMiner line, in file order (it skips Wazuh lines
containing `The average number`; all 8 Wazuh files have 0 such lines).
Verified on russellmitchell and shaw: row count = Wazuh lines + AMiner
lines (45,544 = 41,488 + 4,056; 70,782 = 68,539 + 2,243). Every row matches
its record on name and ip, and on time (Wazuh `int(@timestamp)` = CSV time
for all Wazuh rows; AMiner `int(DetectionTimestamp[-1])`). The loader
re-verifies every row on each run.

**fast.log ↔ eve.json** (key: timestamp to the microsecond, gid:sid:rev,
agent ip; also checked with src/dst ip:port, same result):

| Scenario | fast.log | eve.json | matched | rate | fast.log unmatched | eve.json without twin |
|---|---|---|---|---|---|---|
| russellmitchell | 9,186 | 9,186 | 9,186 | 100.0000% | 0 | 0 |
| shaw | 16,708 | 16,692 | 16,692 | 99.9042% | 16 | 0 |

The 16 unmatched shaw records are all `SURICATA TLS invalid handshake
message` (1:2230003:1) / `SURICATA TLS invalid record/traffic` (1:2230010:1),
agent 172.24.249.224, 2022-01-26T12:13:36.077052Z to 12:13:36.269702Z.
Suricata logged them to fast.log but not as eve.json alerts.

**Clock check.** All 10 attack intervals fall inside the alert time range
in both scenarios. With half-open intervals `[start, end)`, the
labels.csv-derived `time_label` equals the authors' alerts_csv `time_label`
for 45,544/45,544 (russellmitchell) and 70,782/70,782 (shaw) alerts. With
closed intervals, 1 and 231 boundary alerts disagreed. That is why the
intervals are half-open.

**AMiner records** (all 8 scenarios): every record has `TrainingMode`
(true/false). `CountData` (EventCountClusterDetector) and `FrequencyData`
(EventFrequencyDetector) records **do** contain a `RawLogData` line (the
line that closed the window). Following the policy, they get
`kind="aggregate"` and no evidence log line; the line is kept in
`raw_alert`.

## Real-data ingest counts (full files, `ingest-alerts`)

| | russellmitchell | shaw |
|---|---|---|
| input / normalized / rejected | 45,544 / 45,544 / 0 | 70,782 / 70,782 / 0 |
| wazuh alerts (of which fast.log duplicates) | 32,302 (9,186) | 51,847 (16,708) |
| wazuh evaluation = investigation eligible | 23,116 | 35,139 |
| suricata alerts = eligible | 9,186 | 16,692 |
| aminer alerts | 4,056 | 2,243 |
| aminer training_mode / aggregate | 400 / 73 | 408 / 122 |
| aminer evaluation-eligible / investigation-eligible | 3,656 / 3,630 | 1,835 / 1,798 |
| derived alert ids / duplicate alert ids | 4,056 / 0 | 2,243 / 0 |
| alert time range (UTC) | 2022-01-21T00:00:01 – 2022-01-24T23:39:13 | 2022-01-25T00:00:01 – 2022-01-30T23:31:06 |
| attack intervals inside alert range | 10/10 | 10/10 |
| event-label link | linked, 45,544 rows, 0 left over | linked, 70,782 rows, 0 left over |
| event label available / `-` (none) | 45,544 / 34,582 | 70,782 / 64,721 |
| run time (`time`, wall clock) | 3.18 s | 4.77 s |

Note: training and aggregate overlap for AMiner (4,056 − 400 − 73 = 3,583,
but 3,630 are investigation-eligible), so eligible counts are not simple
subtractions.

`time_label` distribution:

- russellmitchell: false_positive 33,529, wpscan 6,359, dirb 4,522, dnsteal
  711, service_scans 367, privilege_escalation 24, cracking 14,
  network_scans 8, webshell 5, reverse_shell 3, service_stop 2.
- shaw: false_positive 63,847, dirb 4,522, wpscan 1,478, cracking 753,
  dnsteal 105, privilege_escalation 54, network_scans 12, reverse_shell 5,
  service_scans 3, service_stop 2, webshell 1.

`event_label` distribution (labelled alerts only):

- russellmitchell: wpscan 6,355, dirb 4,522, service_scan 50,
  escalated_sudo_command 15, attacker_change_user 9, dnsteal 6,
  webshell_cmd 3, crack_passwords 2.
- shaw: dirb 4,522, wpscan 1,478, escalated_sudo_command 28,
  attacker_change_user 17, dns_scan 9, webshell_cmd 3, crack_passwords 2,
  dnsteal 2.

Attack phases with at least one investigation-eligible alert:

- russellmitchell: wazuh {cracking, dirb, dnsteal, network_scans,
  privilege_escalation, service_scans, wpscan}; suricata {cracking, dnsteal,
  service_scans, webshell, wpscan}; aminer {cracking, dirb,
  privilege_escalation, reverse_shell, service_scans, service_stop,
  webshell, wpscan}.
- shaw: wazuh {cracking, dirb, dnsteal, network_scans,
  privilege_escalation, reverse_shell, service_scans, wpscan}; suricata
  {cracking}; aminer {cracking, dirb, network_scans, privilege_escalation,
  reverse_shell, service_scans, service_stop, webshell, wpscan}.

These are descriptive dataset statistics from two scenarios, not
experimental results.

## Decisions in force

1. event_label comes from alerts_csv (downloaded with approval), linked by
   position and verified per row; linking stops at the first mismatch.
2. Detector split: suricata = `eve.json`; wazuh = all other Wazuh records;
   `fast.log` records kept as wazuh with `duplicate_of_suricata=True` and
   excluded from single-detector and fused variants by default.
3. `event_ids` stay empty; evidence holds the Wazuh id, raw log lines, log
   paths and timestamps. AMiner `alert_id` is a sha256 of
   scenario/file/line/content, with `alert_id_derived=True`.
4. AMiner `training_mode=True` alerts are kept and excluded from all
   evaluation variants by default (`AlertSelection`).
5. AMiner `CountData`/`FrequencyData` alerts are kept with `kind="aggregate"`
   and no evidence log line. They are excluded from investigation variants
   by default and counted in the report.
6. Ground truth (time_label from labels.csv, event_label from alerts_csv) is
   a separate file, never in `Alert`, never a feature.
7. Licences: dataset CC BY 4.0 (Zenodo page); repo GPL-3.0 (data file only
   used).

## Open questions for the user

1. **The 16 unmatched shaw fast.log records** are Suricata detections with
   no eve.json copy. Under the current rule they are flagged duplicates and
   excluded, so Suricata loses them. Should unmatched fast.log records be
   re-attributed to `suricata` (and not flagged)? Doing so would need
   two-pass matching, or matching done in M3.
2. **AMiner `MatchValueAverageChangeDetector`** ("Statistical data report",
   e.g. 38 in shaw) is also a statistic over a window, but has no
   `CountData`/`FrequencyData` key, so it is currently `kind="event"`.
   Should it count as aggregate too?
3. **`time_label` semantics:** benign alerts inside an attack window get the
   phase name (e.g. russellmitchell has 711 `dnsteal` time labels but 6
   `dnsteal` event labels). For triage scoring in M4, which is the positive
   class: time_label, event_label, or both reported?
4. **AIT-LDSv2 for real event IDs** before M6 (your call, as noted).
5. **Dev/held-out split:** russellmitchell and shaw were used here to verify
   formats only, not to look at results. If either is intended as held-out,
   say so; the verification touched only file structure and label
   alignment.
