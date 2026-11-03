# Sample data — SYNTHETIC

Every file in this directory is **synthetic**: hand-written for development
and automated tests. None of it is real network or host telemetry, none of
the labelled "attacks" happened, and nothing derived from these files is an
experimental result.

| File | Format | Purpose |
|------|--------|---------|
| `synthetic_cicids2017_format.csv` | CSV, CICIDS2017 column layout (subset of columns, leading spaces and a repeated `Fwd Header Length` header as in the original files) | Exercise the `cicids2017` mapping. 14 rows: 9 valid (one exact duplicate, `Infinity`/`NaN` values, one row with empty timestamp and label), 5 intentionally invalid (bad timestamp, bad IP, empty row, wrong column count, non-numeric feature). |
| `synthetic_security_events.json` | JSON object with a `records` array | Exercise the `generic` mapping across network, authentication, endpoint and application events. 10 records: 5 valid (one repeated `event_id`), 5 intentionally invalid. |
| `synthetic_security_events.jsonl` | JSON Lines | 4 records (plus one blank line): 3 valid, 1 malformed JSON line. |

IP addresses come from private (`192.168.0.0/16`, `10.0.0.0/8`) and
documentation (`203.0.113.0/24`, `198.51.100.0/24`, `2001:db8::/32`) ranges.
Labels such as `DoS Hulk` reuse CICIDS2017 class names only so that the
mapping can be tested; they do not describe real traffic.

When running the pipeline on the CSV sample, pass
`--dataset-name synthetic-cicids2017-format` so outputs are not attributed to
the real CICIDS2017 dataset.

## `synthetic_ait_ads/` — AIT-ADS shapes, scenario name `synthetic`

Hand-written records that copy the *shape* of the AIT Alert Data Set files
(field names and nesting observed in the real files); all values are
invented. Pass `--dataset-name synthetic-ait-ads-format` when ingesting them.

| File | Mimics | Content |
|------|--------|---------|
| `synthetic_wazuh.json` | `<scenario>_wazuh.json` | 8 lines: Wazuh syslog alert, Suricata `eve.json` alert, its `fast.log` twin (a duplicate), a `fast.log` record without twin (becomes a Suricata alert, `fast_log_unmatched`), Wazuh web alert whose description contains a comma, and 3 invalid (bad timestamp, bad agent IP, truncated JSON). |
| `synthetic_aminer.json` | `<scenario>_aminer.json` | 5 lines: training-mode alert, normal alert, `CountData` aggregate, `FrequencyData` aggregate, 1 invalid (non-boolean `TrainingMode`). |
| `synthetic_labels.csv` | `labels.csv` | 4 rows, deliberately not in time order, one for another scenario, two phases sharing a boundary second. |
| `synthetic_alerts.txt` | `alerts_csv/<scenario>_alerts.txt` | Header + 13 rows, one per input line (Wazuh then AMiner), unquoted name with a comma. |

Expected ingest: 13 input, 9 normalized, 4 rejected (asserted in
`backend/tests/test_alert_pipeline.py`).
