# Session notes

Newest milestone first. All numbers are copied from command output; none
are estimates.

---

# M5: model client, tool layer, single tool-using agent (+ M4b decisions)

Date: 2026-11-07. User decision: build the original SentinelAI plan
milestone by milestone (roadmap M5-M12 in CLAUDE.md); the paper measures
the detector-conditioned study on top of it.

- Part A: branch `phase2/pilot-decisions` (from `phase2/baselines` at
  `b01c6a4`), commit `48c0f17`, pushed.
- Part B: branch `phase2/agent-single` (from Part A), code commit `24ffb50`, pushed, no PR.
- **Model endpoint: none.** Asked at the start; the user chose "FakeClient
  only". Everything was built and tested with the scripted `FakeClient`. No
  model was downloaded, no API was called, and there is **no real agent
  output** in these notes. The 2-case real run is therefore not done; it
  is the first step once an endpoint is chosen (M6).
- No new dependency (the client uses stdlib `urllib`).

## Part A: decisions applied (M4b open questions)

1. **Noise fallback = nearest time outside the window.** Shortfalls are
   filled with the event-benign pool alerts nearest to the window
   (distance to the nearer edge; ties by time, source file, source line);
   no randomness in the fallback. Each case records
   `fallback_max_distance_seconds`, and the variant summary records the
   rule. Agents see only offsets (Part B).
2. **Headline coverage = event_label on alert-reachable phases**; time
   coverage is the sensitivity analysis. The methodology doc, CLAUDE.md,
   the report (`headline` key) and the CLI column order are updated.
3. **Truncation side by side**: `pilot.truncation: ["spread", "earliest"]`
   (validated). `run-agent --truncation` picks one rule per run.
4. **Baseline k**: `baselines.top_k: [5, 10]` gives rows `<name>@k5` and
   `<name>@k10`. Agent runs add `<name>@k<k>-matched`, where k = the
   agent's mean citations per case rounded half up, minimum 1
   (`matched_k`).
5. **Detector order frozen** (2026-11-07): `detector_order_frozen: true`.
   The loader rejects a frozen config whose order is not
   `FROZEN_DETECTOR_ORDER`, and `test_detector_order_is_frozen` pins it.

### DEV-SCENARIO CEILINGS after Part A (not agent results)

`cases` output, headline column first:

```
Headline: coverage by event_label, alert-reachable phases; time_label is the sensitivity analysis
variant          ceil event  ceil time  pre-cap e/t  mean att  mean ben  trunc  dropped  drop atk e/t ben w/ atk
wazuh               4/10       7/10        4/7        40.1000   21.5000      5     8136      2/3               0
suricata            1/10       5/10        1/5        14.9000   16.0000      1       64      0/1               0
aminer              6/10       8/10        6/8        28.8000    0.0000      2     3185      1/2               0
fused               7/10      10/10        7/10       45.0000   24.7000      6    11901      3/4               0
oracle              7/10       7/10        7/7        28.0000    0.0000      2    10677      2/2               0
shuffled-wazuh      7/10      10/10        7/10       43.5000   22.8000      6     7433      3/4               0
shuffled-suricata    5/10       8/10        5/8        38.8000   17.4000      4     2653      2/3               0
shuffled-aminer     5/10       6/10        5/6        28.2000    7.2000      2      953      2/2               0
noise-wazuh         0/10       4/10        0/5        40.1000   21.5000      5     8136      0/3               0
noise-suricata      0/10       5/10        0/5        14.9000   16.0000      1       64      0/1               0
noise-aminer        0/10       4/10        0/5        28.8000    0.0000      2     3185      0/2               0

Headline: coverage by event_label, alert-reachable phases; time_label is the sensitivity analysis
variant          ceil event  ceil time  pre-cap e/t  mean att  mean ben  trunc  dropped  drop atk e/t ben w/ atk
wazuh               3/10       8/10        3/8        42.6000   12.5000      5     5171      2/4               0
suricata            0/10       1/10        0/1        10.0000   10.0000      2      232      0/1               0
aminer              7/10       9/10        7/9        31.3000    0.0000      2      653      1/2               0
fused               6/10      10/10        7/10       47.6000   12.5000      5     6519      3/4               0
oracle              7/10       7/10        7/7        26.0000    0.0000      2     5800      2/2               0
shuffled-wazuh      6/10       9/10        6/9        42.5000   11.6000      4     4178      3/3               0
shuffled-suricata    5/10       9/10        5/9        35.7000   10.7000      4     1751      2/3               0
shuffled-aminer     3/10       5/10        3/5        16.6000    1.7000      1       43      1/1               0
noise-wazuh         0/10       6/10        0/6        42.6000   12.5000      5     5171      0/4               0
noise-suricata      0/10       1/10        0/1        10.0000   10.0000      2      232      0/1               0
noise-aminer        0/10       5/10        0/5        31.3000    0.0000      2      653      0/2               0
```

Compared with M4b, the ceilings are unchanged, and so are the noise
controls' coverage counts (russellmitchell noise-wazuh/-suricata/-aminer
time coverage 4/5/4 out of 10, event 0/10). What changed is where the
fallback alerts come from. They are now the nearest ones, but for the
dense web-scan windows the nearest event-benign alerts are still up to
31,970 s (russellmitchell) and 11,757 s (shaw) away (`noise-wazuh`).

### DEV-SCENARIO BASELINES on fused after Part A (not agent results)

russellmitchell:

```
fused            cite-all                                   7/7      7/10       7/7     10/10  0.3544  0.6456  0.0000    697   34.8500
fused            cite-none                                  0/7      0/10       0/7      0/10     n/a     n/a     n/a      0    0.0000
fused            cite-top-k-wazuh-level@k5                  5/7      5/10       7/7     10/10  0.2903  0.6613  0.0000     62    3.1000
fused            cite-top-k-wazuh-level@k10                 7/7      7/10       7/7     10/10  0.3273  0.6727  0.0000    110    5.5000
fused            cite-top-k-detector-order@k5               6/7      6/10       7/7     10/10  0.3387  0.6613  0.0000     62    3.1000
fused            cite-top-k-detector-order@k10              6/7      6/10       7/7     10/10  0.3273  0.6727  0.0000    110    5.5000
fused            cite-aminer-only                           6/7      6/10       7/7      8/10  0.5683  1.0000  0.0000    139    6.9500
```

shaw:

```
fused            cite-all                                   6/7      6/10       7/7     10/10  0.4276  0.7920  0.0000    601   30.0500
fused            cite-none                                  0/7      0/10       0/7      0/10     n/a     n/a     n/a      0    0.0000
fused            cite-top-k-wazuh-level@k5                  6/7      6/10       7/7     10/10  0.3065  0.6452  0.0000     62    3.1000
fused            cite-top-k-wazuh-level@k10                 6/7      6/10       7/7     10/10  0.3301  0.6796  0.0000    103    5.1500
fused            cite-top-k-detector-order@k5               6/7      6/10       7/7     10/10  0.3710  0.6452  0.0000     62    3.1000
fused            cite-top-k-detector-order@k10              6/7      6/10       7/7     10/10  0.4078  0.6796  0.0000    103    5.1500
fused            cite-aminer-only                           6/7      6/10       7/7      9/10  0.8226  1.0000  0.0000    124    6.2000
```

With k = 10, `cite-top-k-wazuh-level` on russellmitchell fused reaches 7/7
reachable phases by event_label (the same as cite-all), with 110 citations
against cite-all's 697.

## Part B: what was built (M5)

- `app/agent/config.py`: `ModelConfig` (base URL, model, temperature 0,
  max_tokens, timeout, max_retries <= 3, API-key variable name, prices) and
  `AgentConfig` (max_tool_calls 12, max_tokens_per_case 40,000,
  max_tool_output_chars 6,000, page size 25, repair_retries <= 1,
  run_token_budget 200,000). Both are new sections of `study.json`, with
  `SENTINEL_LLM_BASE_URL` / `SENTINEL_LLM_MODEL` environment overrides. A
  config that contains an `api_key` is rejected; the key comes only from
  the environment.
- `app/agent/client.py`: `OpenAICompatibleClient` (POST
  `/chat/completions`, injectable transport, retries only on
  timeout/connection/429/5xx and at most `max_retries`, the key only in the
  header and never in errors or repr). Token usage comes from the response,
  or is estimated and flagged `usage_reported=false`. Also `FakeClient`.
- `app/agent/tools.py`: `CaseToolkit` with `list_alerts`, `get_alert`,
  `search_alerts` and `get_raw_log`. Ids are opaque, times are offsets,
  dates in text are masked as `<TIME>`, and label-bearing or provenance
  fields are dropped. Errors come back as JSON, and long outputs are
  truncated with a marker.
- `app/agent/protocol.py`: system prompt (`m5-v1`) and strict parsing of
  one JSON object per reply.
- `app/agent/agent.py`: `investigate()`, the bounded loop with statuses
  `ok`, `failed` (unparseable after one repair), `tool_budget_exceeded`,
  `token_budget_exceeded` (checked before each request) and
  `request_failed`.
- `app/agent/runner.py` and the CLI `run-agent`:
  - dev-only guard, then attack and benign cases interleaved, first
    `--limit`;
  - run log in `data/processed/runs/<run_id>/` (manifest, transcripts with
    id maps, scores);
  - the agent's row and all baseline rows are scored on the same cases;
  - `--dry-run`, `--confirm` above the run budget, and `--fake-responses`
    for scripted demos.
- `cases.py`: `summarize_scores` and `baseline_summaries` work on any case
  subset, so agents and baselines share one table.

## Final test and type-check output

```
$ ../.venv/Scripts/python.exe -m pytest
rootdir: D:\Projects\ERA\backend
configfile: pyproject.toml
testpaths: tests
collected 296 items

tests\test_agent_client.py ........                                      [  2%]
tests\test_agent_loop.py ........                                        [  5%]
tests\test_agent_runner.py ..........                                    [  8%]
tests\test_agent_tools.py .........                                      [ 11%]
tests\test_ait_ads_real.py ...                                           [ 12%]
tests\test_alert_normalizer.py ........................                  [ 20%]
tests\test_alert_pipeline.py ......                                      [ 22%]
tests\test_alert_schema.py ............                                  [ 27%]
tests\test_baselines.py .....                                            [ 28%]
tests\test_case_scoring.py ......                                        [ 30%]
tests\test_cases.py ............                                         [ 34%]
tests\test_data_quality.py ........                                      [ 37%]
tests\test_event_schema.py .................                             [ 43%]
tests\test_ground_truth.py ................                              [ 48%]
tests\test_ingestion.py .................................                [ 59%]
tests\test_metrics.py ........                                           [ 62%]
tests\test_normalizer.py ............................................... [ 78%]
............                                                             [ 82%]
tests\test_pipeline.py .......                                           [ 84%]
tests\test_study_config.py ..................................            [ 96%]
tests\test_variants.py ...........                                       [100%]

============================ 296 passed in 16.33s =============================

$ ../.venv/Scripts/python.exe -m mypy
Success: no issues found in 33 source files
```

`test_agent_tools.py::test_real_dev_cases_do_not_leak` ran on the real
russellmitchell files (not skipped).

## Run output

**Dry runs** (no model called):

```
DEV-SCENARIO AGENT RUN - scenario russellmitchell, variant fused, truncation spread; 2 case(s): attack, benign
Budget: token bound 80000 (40000 per case), cost bound $0.0000 at $0.0/M tokens; first prompts ~1527 tokens; run budget 200000
DRY RUN: no model was called
exit 0
DEV-SCENARIO AGENT RUN - scenario shaw, variant fused, truncation spread; 2 case(s): attack, benign
Budget: token bound 80000 (40000 per case), cost bound $0.0000 at $0.0/M tokens; first prompts ~1520 tokens; run budget 200000
DRY RUN: no model was called
exit 0
```

The CLI's other guards behave as intended: a held-out scenario exits 2
with `scenario 'wilson' is held out and frozen`. A real run with no
endpoint configured exits 2 with `no model endpoint configured`.

**Plumbing check on real dev data with a scripted FakeClient.** This is
NOT an agent result: the script calls `list_alerts` once and then answers
"benign" with no findings, in both cases.

```
DEV-SCENARIO AGENT RUN - scenario russellmitchell, variant fused, truncation spread; 2 case(s): attack, benign
Budget: token bound 80000 (40000 per case), cost bound $0.0000 at $0.0/M tokens; first prompts ~1527 tokens; run budget 200000
  case 0: attack alerts   8 status ok parse ok verdict benign tokens 1538+30 (estimated) tool calls 1 latency 0.00 s
  case 1: benign alerts  41 status ok parse ok verdict benign tokens 2415+30 (estimated) tool calls 1 latency 0.00 s

Agent vs baselines on the same cases (DEV, not held-out); matched k = 1
cov = phases covered by event_label (headline) / time (sensitivity), over reachable phases | all phases; prec = citation precision (event_label / time); unsup = unsupported-claim rate
variant          citer                                cov e rch cov e all cov t rch cov t all  prec e  prec t   unsup  cited  per case
fused            agent (fake)                               0/0       0/1       0/0       0/1     n/a     n/a     n/a      0    0.0000
fused            cite-all                                   0/0       0/1       0/0       1/1  0.0000  0.1633  0.0000     49   24.5000
fused            cite-none                                  0/0       0/1       0/0       0/1     n/a     n/a     n/a      0    0.0000
fused            cite-top-k-wazuh-level@k5                  0/0       0/1       0/0       1/1  0.0000  0.5000  0.0000     10    5.0000
fused            cite-top-k-wazuh-level@k10                 0/0       0/1       0/0       1/1  0.0000  0.4444  0.0000     18    9.0000
fused            cite-top-k-wazuh-level@k1-matched          0/0       0/1       0/0       1/1  0.0000  0.5000  0.0000      2    1.0000
fused            cite-top-k-detector-order@k5               0/0       0/1       0/0       1/1  0.0000  0.5000  0.0000     10    5.0000
fused            cite-top-k-detector-order@k10              0/0       0/1       0/0       1/1  0.0000  0.4444  0.0000     18    9.0000
fused            cite-top-k-detector-order@k1-matched       0/0       0/1       0/0       1/1  0.0000  0.5000  0.0000      2    1.0000
fused            cite-aminer-only                           0/0       0/1       0/0       0/1     n/a     n/a     n/a      0    0.0000
Verdicts: 1/2 correct, 0 failed (tp 0, fp 0, fn 1, tn 1)
Wrote run log to D:\Projects\ERA\data\processed\runs\20261106T200125Z-1e7f17c5
```

This shows the real-data path end to end: tool calls, opaque-id mapping,
manifest and transcripts, scoring next to the baselines on the same cases,
verdict counts and the matched-k row (mean citations 0, so k = 1).

## Surprises

1. Real Wazuh alert ids start with an epoch timestamp (for example
   `1685715378.241`), so they would leak time. This is why ids are opaque.
2. Records and log lines carry dates in several formats (ISO, syslog,
   ctime, Suricata fast.log, `audit(<epoch>:n)`), all masked; the Apache
   access-log format is masked too (not yet seen in the inspected records). Masking keeps
   quote claims verifiable because only the masked spans change.
3. The first russellmitchell attack case in time order is
   `network_scans`, which is unreachable (8 Wazuh alerts in the fused view; the two first listed are ClamAV updates). So the
   default `--limit 2` pilot pair scores an attack case that no source can
   cover by event_label.
4. Nearest-time fallback still reaches far for high-volume sources
   (see the ceilings above): fallback alerts can still sit hours away, so
   their offsets fall far outside [0, window length) and still show they are
   outside the window, even without dates.

## Open questions for the user

1. **Endpoint for M6.** Which model and server: a local 7-9B model via
   Ollama or llama.cpp (you start it and pull the model), or a hosted API
   (you set the key in `SENTINEL_LLM_API_KEY`)? M6 starts with exactly 2
   dev cases.
2. **Offsets of out-of-window noise alerts.** Surprise 4 means agents can
   still reject fallback noise by its offset. Options: accept and report
   it, clip shown offsets to the window, or count only same-window noise.
3. **Case selection for small runs.** Should `--limit` skip unreachable
   phases (surprise 3), or take a seeded random order, instead of time
   order?
4. **Native tool calling.** M5 uses a plain-JSON protocol so any endpoint
   works. Should M6 also try the provider's native function calling, or
   keep one protocol for comparability?
5. **Budgets.** Are 12 tool calls and 40,000 tokens per case, and 200,000
   per run before `--confirm`, the right starting point for the pilot?

---

# M4b: noise controls, spread truncation, claim kinds, deterministic baselines

Date: 2026-10-31. Branch `phase2/baselines` (from `phase2/cases` at
`b7f929d`). Code commit: `c55881d`. No LLM code. No new dependency.

## What was done

1. **Decisions applied.**
   - **Noise control.** `noise-<det>` draws event_label-benign alerts,
     count-matched to the detector. In cases it is rebuilt per case: benign
     alerts from the same window first, then the scenario pool, with
     `from_window`, `from_fallback` and `shortfall` recorded per case and
     summed per variant. The old `random-<det>` rows are kept as
     `shuffled-<det>` with identical draws (the seed purpose string is
     unchanged).
   - **Truncation.** The default is now `spread` (evenly spaced time ranks);
     `earliest` remains an option. The rule and the drops are recorded.
   - **Time of day.** Every case records its UTC start and end time of day.
     Benign windows are not matched on it.
   - **Claim kinds.** `field_value` is the default, so positional
     `Claim(...)` calls are unchanged. `quote` requires an exact,
     case-sensitive substring of a raw log line, at least 8 characters, with
     no normalization. `unsupported_claims` returns the counts.
   - **Pilot.** `pilot.scenarios` in `study.json` must be dev scenarios; this
     is validated and tested.
2. **Case scoring.**
   - Citation precision by event_label and by time. Cited ids that are not
     alerts of the case count as wrong.
   - Coverage over all 10 phases and over the alert-reachable phases. The
     unreachable phases are listed in every report.
3. **Baselines** (`app/study/baselines.py`):
   - `cite-all`
   - `cite-none`
   - `cite-top-k-wazuh-level`: Wazuh alerts by `rule.level` descending, then
     the rest in time order.
   - `cite-top-k-detector-order`: aminer, wazuh, suricata, chosen from the
     M3 dev triage precision.
   - `cite-aminer-only`

   k = 5. Each cited alert gets one field-value claim and one quote claim,
   both copied from its record. All are scored on every variant.

## Final test and type-check output

```
$ ../.venv/Scripts/python.exe -m pytest
...
tests\test_ait_ads_real.py ...                                           [  1%]
tests\test_alert_normalizer.py ........................                  [ 10%]
tests\test_alert_pipeline.py ......                                      [ 13%]
tests\test_alert_schema.py ............                                  [ 18%]
tests\test_baselines.py ...                                              [ 19%]
tests\test_case_scoring.py ......                                        [ 21%]
tests\test_cases.py ...........                                          [ 26%]
tests\test_data_quality.py ........                                      [ 29%]
tests\test_event_schema.py .................                             [ 36%]
tests\test_ground_truth.py ................                              [ 42%]
tests\test_ingestion.py .................................                [ 55%]
tests\test_metrics.py ........                                           [ 59%]
tests\test_normalizer.py ............................................... [ 77%]
............                                                             [ 82%]
tests\test_pipeline.py .......                                           [ 85%]
tests\test_study_config.py .........................                     [ 95%]
tests\test_variants.py ...........                                       [100%]

============================ 249 passed in 11.44s =============================

$ ../.venv/Scripts/python.exe -m mypy
Success: no issues found in 26 source files
```

## DEV-SCENARIO NUMBERS: ceilings and baselines (not agent results)

Config: committed `study.json` (padding 0 s, cap 100 `spread`, 1 benign case
per attack case, case seed 20261031, variant seed 20261031, top_k 5, detector
order aminer, wazuh, suricata, quote 60 chars). Command:
`python -m app.main cases --scenario <s>`. Output copied verbatim.

How to read the tables:
- `ceil` columns count attack cases covered after the cap; `pre-cap t/e`
  gives the same counts before the cap.
- Baseline `cov` columns give phases covered, by time and by event_label,
  over all 10 phases and over the 7 reachable ones.
- `prec e/t` = citation precision, pooled over all 20 cases (attack and
  benign).
- `unsup` = unsupported-claim rate.

### russellmitchell

```
$ python -m app.main cases --scenario russellmitchell
DEV-SCENARIO CEILINGS - scenario russellmitchell (dev split; ceilings, not agent results)
Cases: 10 attack, 10 benign (0 benign unavailable); padding 0 s, cap 100 (spread), seed 20261031
variant           ceil time ceil event  pre-cap t/e  mean att  mean ben  trunc  dropped  drop atk e/t ben w/ atk
wazuh               7/10       4/10        7/4        40.1000   21.5000      5     8136      2/3               0
suricata            5/10       1/10        5/1        14.9000   16.0000      1       64      0/1               0
aminer              8/10       6/10        8/6        28.8000    0.0000      2     3185      1/2               0
fused              10/10       7/10       10/7        45.0000   24.7000      6    11901      3/4               0
oracle              7/10       7/10        7/7        28.0000    0.0000      2    10677      2/2               0
shuffled-wazuh     10/10       7/10       10/7        43.5000   22.8000      6     7433      3/4               0
shuffled-suricata    8/10       5/10        8/5        38.8000   17.4000      4     2653      2/3               0
shuffled-aminer     6/10       5/10        6/5        28.2000    7.2000      2      953      2/2               0
noise-wazuh         4/10       0/10        5/0        40.1000   21.5000      5     8136      0/3               0
noise-suricata      5/10       0/10        5/0        14.9000   16.0000      1       64      0/1               0
noise-aminer        4/10       0/10        5/0        28.8000    0.0000      2     3185      0/2               0
Phases: 10 attack phases, 7 alert-reachable; unreachable: network_scans, reverse_shell, dnsteal
  noise-wazuh: 8752 alerts matched, 1121 from the same window, 7631 from the scenario pool, 0 short
  noise-suricata: 373 alerts matched, 373 from the same window, 0 from the scenario pool, 0 short
  noise-aminer: 3473 alerts matched, 205 from the same window, 3268 from the scenario pool, 0 short

DEV-SCENARIO BASELINES - deterministic non-LLM citers, not agent results (top_k 5, detector order aminer, wazuh, suricata)
cov = phases covered (time / event_label) over all phases | over reachable phases; prec = citation precision (event_label / time); unsup = unsupported-claim rate
variant          baseline                   cov t all cov e all cov t rch cov e rch  prec e  prec t   unsup  cited  per case
wazuh            cite-all                        7/10      4/10       5/7       4/7  0.3442  0.6510  0.0000    616   30.8000
wazuh            cite-none                       0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
wazuh            cite-top-k-wazuh-level          7/10      3/10       5/7       3/7  0.2679  0.6250  0.0000     56    2.8000
wazuh            cite-top-k-detector-order       7/10      3/10       5/7       3/7  0.2679  0.6250  0.0000     56    2.8000
wazuh            cite-aminer-only                0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
suricata         cite-all                        5/10      1/10       4/7       1/7  0.1424  0.4822  0.0000    309   15.4500
suricata         cite-none                       0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
suricata         cite-top-k-wazuh-level          5/10      1/10       4/7       1/7  0.1667  0.5000  0.0000     30    1.5000
suricata         cite-top-k-detector-order       5/10      1/10       4/7       1/7  0.1667  0.5000  0.0000     30    1.5000
suricata         cite-aminer-only                0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
aminer           cite-all                        8/10      6/10       7/7       6/7  0.6493  1.0000  0.0000    288   14.4000
aminer           cite-none                       0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
aminer           cite-top-k-wazuh-level          8/10      6/10       7/7       6/7  0.7778  1.0000  0.0000     27    1.3500
aminer           cite-top-k-detector-order       8/10      6/10       7/7       6/7  0.7778  1.0000  0.0000     27    1.3500
aminer           cite-aminer-only                8/10      6/10       7/7       6/7  0.6493  1.0000  0.0000    288   14.4000
fused            cite-all                       10/10      7/10       7/7       7/7  0.3544  0.6456  0.0000    697   34.8500
fused            cite-none                       0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
fused            cite-top-k-wazuh-level         10/10      5/10       7/7       5/7  0.2903  0.6613  0.0000     62    3.1000
fused            cite-top-k-detector-order      10/10      6/10       7/7       6/7  0.3387  0.6613  0.0000     62    3.1000
fused            cite-aminer-only                8/10      6/10       7/7       6/7  0.5683  1.0000  0.0000    139    6.9500
oracle           cite-all                        7/10      7/10       7/7       7/7  1.0000  1.0000  0.0000    280   14.0000
oracle           cite-none                       0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
oracle           cite-top-k-wazuh-level          7/10      7/10       7/7       7/7  1.0000  1.0000  0.0000     26    1.3000
oracle           cite-top-k-detector-order       7/10      7/10       7/7       7/7  1.0000  1.0000  0.0000     26    1.3000
oracle           cite-aminer-only                6/10      6/10       6/7       6/7  1.0000  1.0000  0.0000     79    3.9500
shuffled-wazuh   cite-all                       10/10      7/10       7/7       7/7  0.3605  0.6561  0.0000    663   33.1500
shuffled-wazuh   cite-none                       0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
shuffled-wazuh   cite-top-k-wazuh-level         10/10      5/10       7/7       5/7  0.3103  0.6897  0.0000     58    2.9000
shuffled-wazuh   cite-top-k-detector-order      10/10      6/10       7/7       6/7  0.3448  0.6897  0.0000     58    2.9000
shuffled-wazuh   cite-aminer-only                8/10      6/10       7/7       6/7  0.5312  1.0000  0.0000    128    6.4000
shuffled-suricata cite-all                        8/10      5/10       6/7       5/7  0.3932  0.6904  0.0000    562   28.1000
shuffled-suricata cite-none                       0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
shuffled-suricata cite-top-k-wazuh-level          8/10      5/10       6/7       5/7  0.3636  0.6364  0.0000     44    2.2000
shuffled-suricata cite-top-k-detector-order       8/10      4/10       6/7       4/7  0.3182  0.6364  0.0000     44    2.2000
shuffled-suricata cite-aminer-only                5/10      4/10       5/7       4/7  0.5182  1.0000  0.0000    110    5.5000
shuffled-aminer  cite-all                        6/10      5/10       5/7       5/7  0.5876  0.7966  0.0000    354   17.7000
shuffled-aminer  cite-none                       0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
shuffled-aminer  cite-top-k-wazuh-level          6/10      5/10       5/7       5/7  0.4000  0.6571  0.0000     35    1.7500
shuffled-aminer  cite-top-k-detector-order       6/10      4/10       5/7       4/7  0.3714  0.6571  0.0000     35    1.7500
shuffled-aminer  cite-aminer-only                5/10      4/10       5/7       4/7  0.7703  1.0000  0.0000     74    3.7000
noise-wazuh      cite-all                        4/10      0/10       2/7       0/7  0.0000  0.3166  0.0000    616   30.8000
noise-wazuh      cite-none                       0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
noise-wazuh      cite-top-k-wazuh-level          4/10      0/10       2/7       0/7  0.0000  0.3571  0.0000     56    2.8000
noise-wazuh      cite-top-k-detector-order       4/10      0/10       2/7       0/7  0.0000  0.3571  0.0000     56    2.8000
noise-wazuh      cite-aminer-only                1/10      0/10       1/7       0/7  0.0000  0.9464  0.0000     56    2.8000
noise-suricata   cite-all                        5/10      0/10       4/7       0/7  0.0000  0.4822  0.0000    309   15.4500
noise-suricata   cite-none                       0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
noise-suricata   cite-top-k-wazuh-level          5/10      0/10       4/7       0/7  0.0000  0.5000  0.0000     30    1.5000
noise-suricata   cite-top-k-detector-order       5/10      0/10       4/7       0/7  0.0000  0.5000  0.0000     30    1.5000
noise-suricata   cite-aminer-only                1/10      0/10       1/7       0/7  0.0000  1.0000  0.0000     32    1.6000
noise-aminer     cite-all                        4/10      0/10       3/7       0/7  0.0000  0.3646  0.0000    288   14.4000
noise-aminer     cite-none                       0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
noise-aminer     cite-top-k-wazuh-level          4/10      0/10       3/7       0/7  0.0000  0.3704  0.0000     27    1.3500
noise-aminer     cite-top-k-detector-order       4/10      0/10       3/7       0/7  0.0000  0.3704  0.0000     27    1.3500
noise-aminer     cite-aminer-only                2/10      0/10       1/7       0/7  0.0000  0.9487  0.0000     78    3.9000
```

### shaw

```
$ python -m app.main cases --scenario shaw
DEV-SCENARIO CEILINGS - scenario shaw (dev split; ceilings, not agent results)
Cases: 10 attack, 10 benign (0 benign unavailable); padding 0 s, cap 100 (spread), seed 20261031
variant           ceil time ceil event  pre-cap t/e  mean att  mean ben  trunc  dropped  drop atk e/t ben w/ atk
wazuh               8/10       3/10        8/3        42.6000   12.5000      5     5171      2/4               0
suricata            1/10       0/10        1/0        10.0000   10.0000      2      232      0/1               0
aminer              9/10       7/10        9/7        31.3000    0.0000      2      653      1/2               0
fused              10/10       6/10       10/7        47.6000   12.5000      5     6519      3/4               0
oracle              7/10       7/10        7/7        26.0000    0.0000      2     5800      2/2               0
shuffled-wazuh      9/10       6/10        9/6        42.5000   11.6000      4     4178      3/3               0
shuffled-suricata    9/10       5/10        9/5        35.7000   10.7000      4     1751      2/3               0
shuffled-aminer     5/10       3/10        5/3        16.6000    1.7000      1       43      1/1               0
noise-wazuh         6/10       0/10        6/0        42.6000   12.5000      5     5171      0/4               0
noise-suricata      1/10       0/10        1/0        10.0000   10.0000      2      232      0/1               0
noise-aminer        5/10       0/10        5/0        31.3000    0.0000      2      653      0/2               0
Phases: 10 attack phases, 7 alert-reachable; unreachable: dnsteal, service_scans, reverse_shell
  noise-wazuh: 5722 alerts matched, 524 from the same window, 5198 from the scenario pool, 0 short
  noise-suricata: 432 alerts matched, 432 from the same window, 0 from the scenario pool, 0 short
  noise-aminer: 966 alerts matched, 119 from the same window, 847 from the scenario pool, 0 short

DEV-SCENARIO BASELINES - deterministic non-LLM citers, not agent results (top_k 5, detector order aminer, wazuh, suricata)
cov = phases covered (time / event_label) over all phases | over reachable phases; prec = citation precision (event_label / time); unsup = unsupported-claim rate
variant          baseline                   cov t all cov e all cov t rch cov e rch  prec e  prec t   unsup  cited  per case
wazuh            cite-all                        8/10      3/10       5/7       3/7  0.3811  0.7731  0.0000    551   27.5500
wazuh            cite-none                       0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
wazuh            cite-top-k-wazuh-level          8/10      3/10       5/7       3/7  0.2593  0.5926  0.0000     54    2.7000
wazuh            cite-top-k-detector-order       8/10      3/10       5/7       3/7  0.2407  0.5926  0.0000     54    2.7000
wazuh            cite-aminer-only                0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
suricata         cite-all                        1/10      0/10       1/7       0/7  0.0000  0.5000  0.0000    200   10.0000
suricata         cite-none                       0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
suricata         cite-top-k-wazuh-level          1/10      0/10       1/7       0/7  0.0000  0.5000  0.0000     10    0.5000
suricata         cite-top-k-detector-order       1/10      0/10       1/7       0/7  0.0000  0.5000  0.0000     10    0.5000
suricata         cite-aminer-only                0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
aminer           cite-all                        9/10      7/10       7/7       7/7  0.6805  1.0000  0.0000    313   15.6500
aminer           cite-none                       0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
aminer           cite-top-k-wazuh-level          9/10      7/10       7/7       7/7  0.8387  1.0000  0.0000     31    1.5500
aminer           cite-top-k-detector-order       9/10      7/10       7/7       7/7  0.8387  1.0000  0.0000     31    1.5500
aminer           cite-aminer-only                9/10      7/10       7/7       7/7  0.6805  1.0000  0.0000    313   15.6500
fused            cite-all                       10/10      6/10       7/7       6/7  0.4276  0.7920  0.0000    601   30.0500
fused            cite-none                       0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
fused            cite-top-k-wazuh-level         10/10      6/10       7/7       6/7  0.3065  0.6452  0.0000     62    3.1000
fused            cite-top-k-detector-order      10/10      6/10       7/7       6/7  0.3710  0.6452  0.0000     62    3.1000
fused            cite-aminer-only                9/10      6/10       7/7       6/7  0.8226  1.0000  0.0000    124    6.2000
oracle           cite-all                        7/10      7/10       7/7       7/7  1.0000  1.0000  0.0000    260   13.0000
oracle           cite-none                       0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
oracle           cite-top-k-wazuh-level          7/10      7/10       7/7       7/7  1.0000  1.0000  0.0000     26    1.3000
oracle           cite-top-k-detector-order       7/10      7/10       7/7       7/7  1.0000  1.0000  0.0000     26    1.3000
oracle           cite-aminer-only                7/10      7/10       7/7       7/7  1.0000  1.0000  0.0000    105    5.2500
shuffled-wazuh   cite-all                        9/10      6/10       6/7       6/7  0.4455  0.7856  0.0000    541   27.0500
shuffled-wazuh   cite-none                       0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
shuffled-wazuh   cite-top-k-wazuh-level          9/10      5/10       6/7       5/7  0.3393  0.6429  0.0000     56    2.8000
shuffled-wazuh   cite-top-k-detector-order       9/10      6/10       6/7       6/7  0.3929  0.6429  0.0000     56    2.8000
shuffled-wazuh   cite-aminer-only                8/10      6/10       6/7       6/7  0.8000  1.0000  0.0000    110    5.5000
shuffled-suricata cite-all                        9/10      5/10       6/7       5/7  0.4763  0.7694  0.0000    464   23.2000
shuffled-suricata cite-none                       0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
shuffled-suricata cite-top-k-wazuh-level          9/10      5/10       6/7       5/7  0.4000  0.7333  0.0000     45    2.2500
shuffled-suricata cite-top-k-detector-order       9/10      5/10       6/7       5/7  0.4000  0.7333  0.0000     45    2.2500
shuffled-suricata cite-aminer-only                7/10      5/10       6/7       5/7  0.8023  1.0000  0.0000     86    4.3000
shuffled-aminer  cite-all                        5/10      3/10       4/7       3/7  0.8033  0.9071  0.0000    183    9.1500
shuffled-aminer  cite-none                       0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
shuffled-aminer  cite-top-k-wazuh-level          5/10      3/10       4/7       3/7  0.4231  0.8077  0.0000     26    1.3000
shuffled-aminer  cite-top-k-detector-order       5/10      3/10       4/7       3/7  0.4231  0.8077  0.0000     26    1.3000
shuffled-aminer  cite-aminer-only                3/10      3/10       3/7       3/7  1.0000  1.0000  0.0000     26    1.3000
noise-wazuh      cite-all                        6/10      0/10       3/7       0/7  0.0000  0.3920  0.0000    551   27.5500
noise-wazuh      cite-none                       0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
noise-wazuh      cite-top-k-wazuh-level          6/10      0/10       3/7       0/7  0.0000  0.3333  0.0000     54    2.7000
noise-wazuh      cite-top-k-detector-order       6/10      0/10       3/7       0/7  0.0000  0.3333  0.0000     54    2.7000
noise-wazuh      cite-aminer-only                3/10      0/10       1/7       0/7  0.0000  0.8261  0.0000     23    1.1500
noise-suricata   cite-all                        1/10      0/10       1/7       0/7  0.0000  0.5000  0.0000    200   10.0000
noise-suricata   cite-none                       0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
noise-suricata   cite-top-k-wazuh-level          1/10      0/10       1/7       0/7  0.0000  0.5000  0.0000     10    0.5000
noise-suricata   cite-top-k-detector-order       1/10      0/10       1/7       0/7  0.0000  0.5000  0.0000     10    0.5000
noise-suricata   cite-aminer-only                1/10      0/10       1/7       0/7  0.0000  1.0000  0.0000     18    0.9000
noise-aminer     cite-all                        5/10      0/10       3/7       0/7  0.0000  0.3674  0.0000    313   15.6500
noise-aminer     cite-none                       0/10      0/10       0/7       0/7     n/a     n/a     n/a      0    0.0000
noise-aminer     cite-top-k-wazuh-level          4/10      0/10       2/7       0/7  0.0000  0.3226  0.0000     31    1.5500
noise-aminer     cite-top-k-detector-order       4/10      0/10       2/7       0/7  0.0000  0.3226  0.0000     31    1.5500
noise-aminer     cite-aminer-only                3/10      0/10       1/7       0/7  0.0000  0.7200  0.0000     25    1.2500
```

Triage tables with the new rows (`python -m app.main variants --scenario
<s>`): the `shuffled-*` rows reproduce M3's `random-*` rows exactly.

- `noise-*` has precision 0 under event_label in both scenarios, by
  construction.
- Under time_label, noise precision is 0.0334, 0.0334 and 0.0344
  (wazuh/suricata/aminer, russellmitchell) and 0.0141, 0.0144 and 0.0089
  (shaw).

Unsupported claims: `cite-all` on `fused` made 1,280 (russellmitchell) and
1,104 (shaw) record-copied claims, field-value and quote. Every baseline row
reports an unsupported-claim rate of 0.0000, so the claim machinery accepts
every copied field and quote on the real records.

Benign-window times of day (UTC start), from `<scenario>.cases.json`:
- russellmitchell: 20:29:56, 23:59:25, 13:22:34, 08:29:01, 13:44:48,
  06:38:17, 21:52:35, 07:23:57, 15:40:04, 07:08:25.
- shaw: 18:27:27, 09:14:52, 14:33:00, 14:59:19, 11:23:27, 15:23:44,
  05:59:16, 21:26:21, 05:01:21, 12:13:35.

## Surprises

1. **Noise reaches time coverage, not event-label coverage.** With purely
   event-benign alerts, noise controls cover up to 5/10 phases by time in
   russellmitchell (`noise-suricata`) and 6/10 in shaw (`noise-wazuh`), and
   0/10 by event_label everywhere. Time-based coverage counts any alert
   inside the window, so it can be gamed by volume. Event-label coverage on
   the reachable phases is the measure noise cannot inflate.
2. **Noise mostly comes from outside the window for high-volume sources.**
   The attack windows of the web-scan phases hold almost no event-benign
   alerts. In russellmitchell, `noise-wazuh` took 7,631 of 8,752 alerts from
   the scenario pool and `noise-aminer` 3,268 of 3,473. `noise-suricata`
   found all 373 in the same windows. Shaw shows the same pattern (5,198 of
   5,722; 847 of 966; 0 of 432). So "noise" alerts are often visibly
   out-of-window: an agent could reject them on time alone.
3. **`spread` truncation cost one event-label ceiling.** Shaw's fused
   `cracking` case has 547 alerts in its window, 3 of them event-labelled;
   the spread cap kept 100 and dropped all 3. The fused event ceiling is
   6/10 after the cap vs 7/10 before (with `earliest` in M4 it was 7/10).
   All other ceilings are unchanged from M4.
4. **Top-k baselines nearly match cite-all on coverage at about a tenth of
   the citations.** On `fused`, cite-top-k-detector-order covers 10/10 by
   time and 6/10 by event_label in both scenarios with 62 citations (3.1
   per case), against cite-all's 697 and 601 citations. On `aminer`,
   top-k is more precise than cite-all (event precision 0.78 vs 0.65 in
   russellmitchell; 0.84 vs 0.68 in shaw).
5. **On `fused`, `cite-aminer-only` is the most precise baseline:** event
   precision 0.57 (russellmitchell) and 0.82 (shaw), vs 0.29-0.43 for the
   other fused baselines, while still covering 6/10 phases by event_label.
   It cites 6.95 and 6.2 alerts per case.
6. **Unreachable phases are the same as in M4:** network_scans,
   reverse_shell and dnsteal in russellmitchell; dnsteal, service_scans and
   reverse_shell in shaw. 7 phases per scenario are reachable.

## Open questions for the user

1. **Noise fallback visibility.** Fallback noise alerts lie outside the case
   window (surprise 2). Should fallback draw from the *nearest* time outside
   the window rather than uniformly from the scenario pool? Or should cases
   hide absolute timestamps from the agent? The latter is an agent-design
   choice for M5.
2. **Headline coverage measure.** Given surprise 1, should the paper's
   headline be event_label coverage on reachable phases, with time coverage
   as the sensitivity analysis (the reverse of the M4 framing)?
3. **Truncation.** `spread` dropped the only event-labelled alerts of one
   case (surprise 3). Keep `spread` as the default, or report both rules
   side by side for the pilot?
4. **Baseline k.** k = 5 is a fixed choice, not tuned. Should the pilot also
   report k = 10 (or a k equal to an LLM agent's mean citation count) so the
   comparison is at matched citation volume?
5. **Detector order** for `cite-top-k-detector-order` was set from dev
   triage precision. This is a dev-derived choice, so it is legitimate for
   the pilot, but it should be frozen before held-out runs. Freeze it now?

---

# M4: cases and deterministic case-level scoring

Date: 2026-10-31. Branch `phase2/cases` (from `phase2/alert-sources` at
`7ec4d3c`). Code commit: `e622661`. No LLM code. No new dependency.

## What was done

1. **Decisions applied.**
   - Per-detector random controls (`random-wazuh`, `random-suricata`,
     `random-aminer`) are the default. `random-fused` is written only as a
     manifest with `degenerate: true` and `experiment_variant: false`.
   - The M3 20-alert study sample is retired (code, config and tests
     removed; the methodology doc says so).
   - The Suricata labelling limitation is in the methodology doc.
   - CICIDS2017 baselines are marked optional and off the critical path in
     the CLAUDE.md status table.
2. **Cases** (`app/study/cases.py`).
   - One attack case per labels.csv phase.
   - One matched benign window of equal length per attack case: seeded,
     whole-second start, inside the observation range, outside attack
     intervals plus padding, disjoint from other benign windows, and
     logged in the case manifest.
   - Per variant, the case's alerts are those in `[window_start, window_end)`,
     time-ordered and capped at 100 (`earliest`). Each case manifest records
     the truncation: alerts dropped, dropped alerts that are attack-labelled
     by each label, and the rule.
   - `dev_case_report` refuses held-out scenarios (tested for all six; the
     CLI exits with code 2 for `harrison`).
3. **Case scoring** (`app/evaluation/case_scoring.py`).
   - Coverage by time (headline) and by event_label (sensitivity), using
     `attack_step_coverage` with alert ids.
   - Unsupported-claim rate using `Claim(record_id=alert_id, ...)` against
     the case's own flattened alert records and raw log lines.
   - Load = alerts in the case after the cap.
   - `metrics.py` is backward compatible: positional `Claim(...)`,
     `.event_id` and the existing tests are unchanged, and one new test
     covers the change.

## Final test and type-check output

```
$ ../.venv/Scripts/python.exe -m pytest
...
tests\test_ait_ads_real.py ...                                           [  1%]
tests\test_alert_normalizer.py ........................                  [ 11%]
tests\test_alert_pipeline.py ......                                      [ 14%]
tests\test_alert_schema.py ............                                  [ 19%]
tests\test_case_scoring.py ....                                          [ 21%]
tests\test_cases.py ........                                             [ 24%]
tests\test_data_quality.py ........                                      [ 27%]
tests\test_event_schema.py .................                             [ 35%]
tests\test_ground_truth.py ................                              [ 42%]
tests\test_ingestion.py .................................                [ 56%]
tests\test_metrics.py ......                                             [ 58%]
tests\test_normalizer.py ............................................... [ 78%]
............                                                             [ 84%]
tests\test_pipeline.py .......                                           [ 87%]
tests\test_study_config.py ...................                           [ 95%]
tests\test_variants.py ...........                                       [100%]

============================ 233 passed in 10.74s =============================

$ ../.venv/Scripts/python.exe -m mypy
Success: no issues found in 25 source files
```

## DEV-SCENARIO CEILINGS (not agent results)

A ceiling scores each case as if the agent cited every alert it was given:
the best any agent could do from that alert source. Config: committed
`study.json` (padding 0 s, cap 100, `earliest`, 1 benign case per attack
case, seed 20261031). Command: `python -m app.main cases --scenario <s>`.

Columns:
- `ceil time` / `ceil event`: attack cases covered, after the cap.
- `pre-cap t/e`: the same two counts before the cap.
- `mean att` / `mean ben`: mean alerts per case (after the cap) for attack
  and benign cases.
- `trunc`: cases truncated.
- `dropped`: alerts dropped by the cap.
- `drop atk e/t`: cases where the cap dropped an alert that is
  attack-labelled by event_label / by time_label.
- `ben w/ atk`: benign cases containing an event-labelled attack alert.

```
DEV-SCENARIO CEILINGS - scenario russellmitchell (dev split; ceilings, not agent results)
Cases: 10 attack, 10 benign (0 benign unavailable); padding 0 s, cap 100 (earliest), seed 20261031
variant           ceil time ceil event  pre-cap t/e  mean att  mean ben  trunc  dropped  drop atk e/t ben w/ atk
wazuh               7/10       4/10        7/4        40.1000   21.5000      5     8136      2/3               0
suricata            5/10       1/10        5/1        14.9000   16.0000      1       64      0/1               0
aminer              8/10       6/10        8/6        28.8000    0.0000      2     3185      1/2               0
fused              10/10       7/10       10/7        45.0000   24.7000      6    11901      3/4               0
oracle              7/10       7/10        7/7        28.0000    0.0000      2    10677      2/2               0
random-wazuh       10/10       7/10       10/7        43.5000   22.8000      6     7433      3/4               0
random-suricata     8/10       5/10        8/5        38.8000   17.4000      4     2653      2/3               0
random-aminer       6/10       5/10        6/5        28.2000    7.2000      2      953      2/2               0

DEV-SCENARIO CEILINGS - scenario shaw (dev split; ceilings, not agent results)
Cases: 10 attack, 10 benign (0 benign unavailable); padding 0 s, cap 100 (earliest), seed 20261031
variant           ceil time ceil event  pre-cap t/e  mean att  mean ben  trunc  dropped  drop atk e/t ben w/ atk
wazuh               8/10       3/10        8/3        42.6000   12.5000      5     5171      2/4               0
suricata            1/10       0/10        1/0        10.0000   10.0000      2      232      0/1               0
aminer              9/10       7/10        9/7        31.3000    0.0000      2      653      1/2               0
fused              10/10       7/10       10/7        47.6000   12.5000      5     6519      3/4               0
oracle              7/10       7/10        7/7        26.0000    0.0000      2     5800      2/2               0
random-wazuh        9/10       6/10        9/6        42.5000   11.6000      4     4178      3/3               0
random-suricata     9/10       5/10        9/5        35.7000   10.7000      4     1751      2/3               0
random-aminer       5/10       3/10        5/3        16.6000    1.7000      1       43      1/1               0
```

Benign sampling:
- russellmitchell: observation range 2022-01-21T00:02:27Z to
  2022-01-24T23:39:13Z, 334,771 free seconds, derived seed
  9459804069692567179.
- shaw: 2022-01-25T00:06:19Z to 2022-01-30T23:31:06Z, 510,033 free
  seconds, derived seed 2028203960259707288.
- No benign case was unavailable in either scenario.

Per attack phase, fused variant (from `<scenario>.cases.json`). "ev-labelled"
is the count of event-labelled attack alerts in the phase before the cap,
per detector:

| scenario | phase | length (s) | alerts in window | kept | dropped (attack by event_label) | ev-labelled wazuh/suricata/aminer |
|---|---|---|---|---|---|---|
| russellmitchell | network_scans | 3346 | 8 | 8 | 0 | 0/0/0 |
| | service_scans | 39 | 321 | 100 | 221 (46) | 6/44/0 |
| | dirb | 23 | 4522 | 100 | 4422 (4422) | 4459/0/63 |
| | wpscan | 31 | 6357 | 100 | 6257 (6255) | 3168/0/3187 |
| | webshell | 63 | 3 | 3 | 0 | 0/0/1 |
| | cracking | 2254 | 12 | 12 | 0 | 0/0/3 |
| | reverse_shell | 43 | 1 | 1 | 0 | 0/0/0 |
| | privilege_escalation | 34 | 24 | 24 | 0 | 6/0/18 |
| | service_stop | 2 | 2 | 2 | 0 | 0/0/2 |
| | dnsteal | 3600 | 547 | 100 | 447 (0) | 0/0/0 |
| shaw | service_stop | 2 | 2 | 2 | 0 | 0/0/2 |
| | dnsteal | 3600 | 105 | 100 | 5 (0) | 0/0/0 |
| | network_scans | 97 | 12 | 12 | 0 | 0/0/9 |
| | service_scans | 13 | 3 | 3 | 0 | 0/0/0 |
| | wpscan | 24 | 1478 | 100 | 1378 (1378) | 729/0/749 |
| | dirb | 26 | 4522 | 100 | 4422 (4422) | 4459/0/63 |
| | webshell | 21 | 1 | 1 | 0 | 0/0/1 |
| | cracking | 2409 | 547 | 100 | 447 (1) | 0/0/3 |
| | reverse_shell | 40 | 4 | 4 | 0 | 0/0/0 |
| | privilege_escalation | 22 | 54 | 54 | 0 | 10/0/35 |

## Surprises

1. **Random controls reach high case ceilings.** By time, `random-wazuh`
   covers 10/10 phases in russellmitchell, more than `wazuh` (7/10).
   `random-suricata` covers 9/10 in shaw against Suricata's 1/10. The
   random draws come from the fused pool, which is densest exactly in the
   attack phases and includes the other detectors' attack alerts. At the
   case level, a random control mostly measures alert volume. The contrast
   between sources shows up in precision, benign-case load and event-label
   coverage, not in time coverage.
2. **AMiner raises no alerts in any benign window** in either dev scenario
   (mean benign load 0.0), while covering 8/10 and 9/10 phases by time.
   Wazuh averages 21.5 and 12.5 alerts per benign case.
3. **The event-label ceiling tops out at 7/10** in both scenarios. Three
   phases per scenario contain no event-labelled alert from any detector:
   network_scans, reverse_shell and dnsteal in russellmitchell; dnsteal,
   service_scans and reverse_shell in shaw. dnsteal has 547 and 105 alerts
   in its window, none of them event-labelled.
4. **The cap is heavy but did not change any ceiling here.** The dirb and
   wpscan cases hold 1,478 to 6,357 alerts; the earliest-100 rule drops
   thousands of attack-labelled alerts. The kept 100 are still in-phase, so
   coverage is the same before and after the cap. The cap does make
   investigation load uniform (100) for exactly the cases with the most
   evidence.
5. **No benign case contains an event-labelled attack alert** in any
   variant. Benign windows are clean by both labels.

## Open questions for the user

1. **What should the random control be at the case level?** Drawn from the
   fused pool, it inherits the other detectors' attack alerts (surprise 1).
   Is that the intended control? A detector-independent alternative would
   need a population that isn't detector output, such as raw log lines,
   which is out of scope.
2. **Truncation rule.** `earliest` keeps the first 100 alerts. For long
   phases (cracking ~2,300 s, dnsteal 3,600 s) a time-spread rule would show
   more of the phase. Keep `earliest` (analyst-queue order) or add a
   time-spread rule as an option?
3. **Benign matching.** Benign windows match attack cases on length only.
   Should they also match on time of day, since traffic volume differs by
   hour?
4. **Claim matching on raw log lines** is exact whole-line comparison.
   Agents usually quote fragments. Before M6, should claims on
   `evidence.log_lines` allow substring matching, or stay exact?
5. **Pilot scenarios (M7).** The original plan was "6 scenarios × 20 alerts".
   With cases and a frozen split, should the pilot run on the 2 dev
   scenarios only (10 attack + 10 benign cases × 8 variants each), keeping
   all six held-out scenarios for the final runs?

---

# M3: alert-source variants, study sampler, frozen split

Date: 2026-10-31. Branch `phase2/alert-sources` (from `phase2/alert-schema`
at `531bb44`). Code commit: `429ee76`.

## What was done

1. **fast.log re-attribution (decision 1).** A first pass over the Wazuh
   file builds a `SuricataTwinIndex`. Each fast.log record claims one
   eve.json twin, greedily in file order. With a twin it is a `wazuh`
   duplicate (excluded); without one it becomes a `suricata` alert flagged
   `fast_log_unmatched` (kept). This supersedes the M2 rule below, which
   flagged every fast.log record as a duplicate.
2. **MatchValueAverageChangeDetector** stays `kind="event"`. This is
   documented in `mappings.py`, CLAUDE.md and the methodology doc.
3. **Frozen split** in `experiments/config/study.json`: dev = russellmitchell,
   shaw; held-out = fox, harrison, santos, wardbeck, wheeler, wilson. It is
   also written into `docs/research-methodology.md`. `ScenarioSplit.require_dev`
   guards dev-only code. `test_study_config.py` checks, for each of the six
   held-out scenarios, that `dev_triage_report` raises `HeldOutScenarioError`.
   The CLI refuses them too (`variants --scenario fox` exits with code 2).
4. **Variants** (`app/study/variants.py`) over the pool of
   investigation-eligible alerts: `wazuh`, `suricata`, `aminer`, `fused`,
   `oracle`, `random-<ref>`. Each variant has a manifest: rule, seeds,
   counts, counts by detector, attack share by event_label and by
   time_label, selection, and the sha256 of the source alerts file. Variant
   alert files are byte-identical copies of the ingested lines.
5. **Study sampler:** `study_sample`, N=20 from `fused`, seed 20261031,
   proportional stratification on event_label, never rebalanced. The
   decision and its justification are in the methodology doc.
6. **Triage:** `triage_by_truth` uses `app/evaluation/metrics.py`. The
   verdict is "alert is in the variant", scored over the pool.
   `event_label` is the primary truth; `time_label` is the sensitivity
   analysis.
7. No new dependency.

## Final test and type-check output

```
$ ../.venv/Scripts/python.exe -m pytest
...
tests\test_ait_ads_real.py ...                                           [  1%]
tests\test_alert_normalizer.py ........................                  [ 12%]
tests\test_alert_pipeline.py ......                                      [ 15%]
tests\test_alert_schema.py ............                                  [ 20%]
tests\test_data_quality.py ........                                      [ 24%]
tests\test_event_schema.py .................                             [ 31%]
tests\test_ground_truth.py ................                              [ 39%]
tests\test_ingestion.py .................................                [ 54%]
tests\test_metrics.py .....                                              [ 56%]
tests\test_normalizer.py ............................................... [ 78%]
............                                                             [ 83%]
tests\test_pipeline.py .......                                           [ 86%]
tests\test_study_config.py ................                              [ 94%]
tests\test_variants.py .............                                     [100%]

============================= 219 passed in 8.75s =============================

$ ../.venv/Scripts/python.exe -m mypy
Success: no issues found in 23 source files
```

## Re-ingest after decision 1 (dev scenarios)

| | russellmitchell | shaw |
|---|---|---|
| wazuh alerts (fast.log duplicates) | 32,302 (9,186) | 51,831 (16,692) |
| suricata alerts (of which fast_log_unmatched) | 9,186 (0) | 16,708 (16) |
| aminer alerts | 4,056 | 2,243 |
| investigation pool / excluded by selection | 35,932 / 9,612 | 53,645 / 17,137 |
| event label link | linked, 0 rejected | linked, 0 rejected |

## DEV-SCENARIO NUMBERS — detector-level triage

These are dev-scenario numbers, not held-out results. They score the alert
sources, not the agent. Verdict = alert is in the variant; universe = the
scenario's investigation pool; "share" = the variant's attack share.
Command (once per scenario):

```
python -m app.main variants --scenario <s> --random-reference fused \
    --random-reference wazuh --random-reference suricata --random-reference aminer
```

The config default for random controls is `fused` only. I added the
per-detector random references on the command line for this report.
Seed 20261031 (from `study.json`).

### russellmitchell — truth: event_label (primary)

```
variant           alerts   share     TP     FP     FN     TN    prec  recall      F1     FNR
wazuh              23116  0.3305   7639  15477   3318   9498  0.3305  0.6972  0.4484  0.3028
suricata            9186  0.0048     44   9142  10913  15833  0.0048  0.0040  0.0044  0.9960
aminer              3630  0.9019   3274    356   7683  24619  0.9019  0.2988  0.4489  0.7012
fused              35932  0.3049  10957  24975      0      0  0.3049  1.0000  0.4674  0.0000
oracle             10957  1.0000  10957      0      0  24975  1.0000  1.0000  1.0000  0.0000
random-fused       35932  0.3049  10957  24975      0      0  0.3049  1.0000  0.4674  0.0000  (degenerate: = pool)
random-wazuh       23116  0.3049   7047  16069   3910   8906  0.3049  0.6432  0.4136  0.3568
random-suricata     9186  0.3052   2804   6382   8153  18593  0.3052  0.2559  0.2784  0.7441
random-aminer       3630  0.3196   1160   2470   9797  22505  0.3196  0.1059  0.1590  0.8941
```

### russellmitchell — truth: time_label (sensitivity)

```
variant           alerts   share     TP     FP     FN     TN    prec  recall      F1     FNR
wazuh              23116  0.3509   8111  15005   3686   9130  0.3509  0.6875  0.4646  0.3125
suricata            9186  0.0232    213   8973  11584  15162  0.0232  0.0181  0.0203  0.9819
aminer              3630  0.9567   3473    157   8324  23978  0.9567  0.2944  0.4502  0.7056
fused              35932  0.3283  11797  24135      0      0  0.3283  1.0000  0.4943  0.0000
oracle             10957  1.0000  10957      0    840  24135  1.0000  0.9288  0.9631  0.0712
random-fused       35932  0.3283  11797  24135      0      0  0.3283  1.0000  0.4943  0.0000  (degenerate: = pool)
random-wazuh       23116  0.3270   7559  15557   4238   8578  0.3270  0.6408  0.4330  0.3592
random-suricata     9186  0.3278   3011   6175   8786  17960  0.3278  0.2552  0.2870  0.7448
random-aminer       3630  0.3402   1235   2395  10562  21740  0.3402  0.1047  0.1601  0.8953
```

### shaw — truth: event_label (primary)

```
variant           alerts   share     TP     FP     FN     TN    prec  recall      F1     FNR
wazuh              35139  0.1479   5198  29941    862  17644  0.1479  0.8578  0.2523  0.1422
suricata           16708  0.0000      0  16708   6060  30877  0.0000  0.0000     n/a  1.0000
aminer              1798  0.4794    862    936   5198  46649  0.4794  0.1422  0.2194  0.8578
fused              53645  0.1130   6060  47585      0      0  0.1130  1.0000  0.2030  0.0000
oracle              6060  1.0000   6060      0      0  47585  1.0000  1.0000  1.0000  0.0000
random-fused       53645  0.1130   6060  47585      0      0  0.1130  1.0000  0.2030  0.0000  (degenerate: = pool)
random-wazuh       35139  0.1144   4020  31119   2040  16466  0.1144  0.6634  0.1952  0.3366
random-suricata    16708  0.1135   1896  14812   4164  32773  0.1135  0.3129  0.1665  0.6871
random-aminer       1798  0.1057    190   1608   5870  45977  0.1057  0.0314  0.0484  0.9686
```

### shaw — truth: time_label (sensitivity)

```
variant           alerts   share     TP     FP     FN     TN    prec  recall      F1     FNR
wazuh              35139  0.1582   5558  29581   1170  17336  0.1582  0.8261  0.2655  0.1739
suricata           16708  0.0122    204  16504   6524  30413  0.0122  0.0303  0.0174  0.9697
aminer              1798  0.5373    966    832   5762  46085  0.5373  0.1436  0.2266  0.8564
fused              53645  0.1254   6728  46917      0      0  0.1254  1.0000  0.2229  0.0000
oracle              6060  1.0000   6060      0    668  46917  1.0000  0.9007  0.9478  0.0993
random-fused       53645  0.1254   6728  46917      0      0  0.1254  1.0000  0.2229  0.0000  (degenerate: = pool)
random-wazuh       35139  0.1267   4452  30687   2276  16230  0.1267  0.6617  0.2127  0.3383
random-suricata    16708  0.1250   2088  14620   4640  32297  0.1250  0.3103  0.1782  0.6897
random-aminer       1798  0.1162    209   1589   6519  45328  0.1162  0.0311  0.0490  0.9689
```

### Study sample (N=20 from fused, proportional on event_label, seed 20261031)

| | russellmitchell | shaw |
|---|---|---|
| derived seed | 4516658805501130058 | 1560837036131065743 |
| strata available → taken | attack 10,957 → 6; benign 24,975 → 14 | attack 6,060 → 2; benign 47,585 → 18 |
| by detector | wazuh 13, suricata 6, aminer 1 | wazuh 15, suricata 5, aminer 0 |
| attack by time_label | 8/20 | 2/20 |

## Surprises

1. **`random-fused` is degenerate.** The pool is the union of the three
   detectors, so a random draw at the fused volume is the whole pool. The
   manifest flags it (`degenerate: true`). The size-matched single-detector
   random controls are the informative ones, and they show differences:
   AMiner beats its random control by a wide margin (precision 0.90 vs 0.32
   in russellmitchell, 0.48 vs 0.11 in shaw), Wazuh slightly (0.33 vs 0.30;
   0.15 vs 0.11), and Suricata scores *below* random (0.005 vs 0.31; 0.000
   vs 0.11).
2. **Suricata has almost no attack event labels.** In the pool, 44/9,186
   (russellmitchell) and 0/16,708 (shaw) Suricata alerts carry one. By
   time_label the figures are 213 and 204. Per the authors' `analyze.py`,
   Suricata event labels come from AIT-NDS netflow matching (DNS-log
   matching for one .biz rule), not log-line matching. Whether this is
   Suricata's real behaviour or a limit of the labelling method is open.
   It decides how the Suricata condition can be interpreted.
3. **The fused sample is dominated by Wazuh** (13/20 and 15/20). AMiner
   contributes 1 and 0 alerts. Sampling from `fused` alone therefore says
   little about the AMiner condition.
4. **Few attacks per sample:** 6/20 and 2/20. That is the honest base rate
   of the fused source, but recall-type agent metrics on 2 positives per
   scenario will be very noisy.
5. **Oracle recall under time_label is below 1** (0.929 and 0.901): 840 and
   668 alerts fall inside attack windows but have no event label. This is
   the expected gap between the two truths, and it is why time_label is
   only a sensitivity analysis.

## Open questions for the user

1. **Random control at fused volume.** Keep `random-fused` (degenerate, =
   pool) as the default, or make the per-detector random controls the
   default in `study.json`? A non-degenerate fused-volume control would
   need a population larger than the alert pool (raw log lines), which is
   out of scope without AIT-LDSv2.
2. **Sample per variant.** For a detector-conditioned study, the agent
   should probably investigate N alerts drawn *from each variant* (wazuh,
   suricata, aminer, fused, oracle, random-*), not only from fused. The
   sampler already supports any variant; should M7 sample every variant
   (and is N=20 per variant per scenario right, given finding 4)?
3. **Suricata labels.** Given finding 2, should the Suricata condition be
   reported with time_label alongside event_label as a co-primary truth,
   or carry a stated limitation?
4. **Empty Suricata attack stratum.** In shaw, `sample-suricata` would have
   no attack alerts at all, so proportional allocation gives 0 attacks.
   Accept that as the true base rate?

---

# M2: alert schema and AIT-ADS loader

Date: 2026-10-31. Branch `phase2/alert-schema` (from `phase2/alert-foundation`
at `a6fecf7`). Code commit: `0ad0b50`.

> Superseded in M3: fast.log records without an eve.json twin are now
> Suricata alerts (`fast_log_unmatched`), not duplicates; AIT-LDSv2 will not
> be added; MatchValueAverageChangeDetector stays an event alert.

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


# 2026-11-07: pace change, M6 selection, Wave A, Wave B1

User decision: build the whole SentinelAI architecture in waves (A-E)
instead of one milestone at a time; inside a wave each sub-milestone is its
own tested, committed unit. Commits and PRs carry no Claude attribution; at
the end of a wave or work day: push, open a PR to `main`, merge it.

## Approved downloads and what actually arrived

One approval batch ("approve all") covered: Ollama + `qwen2.5:7b-instruct`
(fallback `qwen2.5:3b-instruct`), the Python and npm packages, the Docker
images, MITRE ATT&CK enterprise STIX, SigmaHQ `rules/linux` + `rules/web`,
`BAAI/bge-small-en-v1.5` (ONNX), and optionally CICIDS2017. Downloads ran at
about 100 kB/s; the user then paused all downloads.

| Item | Status | Details |
|------|--------|---------|
| Python packages | **Installed** | fastapi 0.162.0, uvicorn 0.54.0, httpx 0.28.1, PyJWT 2.15.1, bcrypt 5.0.0, psycopg 3.3.8, langgraph 1.2.20, langchain-core 1.7.6, numpy 2.4.6, scipy 1.17.1, scikit-learn 1.9.1, xgboost 3.2.0, fastembed 0.9.1, onnxruntime 1.31.1, pySigma 2.0.2, reportlab 5.1.0, prometheus_client 0.26.0, confluent-kafka 2.16.1, opensearch-py 3.2.0, minio 7.2.20 (the first attempt hit a read timeout; the retry with `--timeout 180 --retries 10` succeeded) |
| MITRE ATT&CK | **Downloaded** | `data/raw/mitre/enterprise-attack.json`, 55,277,605 bytes, sha256 `539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5`, 26,699 objects, collection `x_mitre_version` 20.1 (modified 2026-11-05); latest commit on that path in `mitre-attack/attack-stix-data` at download: `f59b03e`. MITRE publishes no checksum for this file, so the sha256 is recorded, not verified against a published value |
| SigmaHQ rules | **Downloaded** | sparse clone of `rules/linux` + `rules/web` at commit `53423dac8742ef6a44fb73f23f049e84594a66ce`, 256 `.yml` rules, 1.1 MB, in `data/raw/sigma/repo/` |
| Embedding model | **Downloaded** | `Qdrant/bge-small-en-v1.5-onnx-Q` via fastembed into `data/models/fastembed/`; a test embedding has 384 dimensions; the download took about 9 minutes |
| Ollama + LLM | **Not installed** | `winget install Ollama.Ollama` was still downloading when the user paused downloads; it was stopped. No model is pulled |
| npm packages | Not started | needed for the Wave D dashboard |
| Docker images | Not started | Docker Desktop is installed at `D:\Docker` but not running; `docker compose` (the plugin) was not found, so `docker compose config` has not been run |
| CICIDS2017 | **Not available** | `http://cicresearch.ca/.../MachineLearningCSV.zip` returned HTTP 200 with a 98,455-byte HTML registration page, not the zip. The file was deleted. Per the user's fallback, ML baselines will use the AIT-ADS dev scenarios only |

Machine: 15.6 GB RAM, RTX 4060 Laptop GPU with 8 GB, Node 22.19.0, Python 3.11.9.

## What was built

**M6 (partial).** `select_cases(cases, limit, mode, reachable, case_ids)`:
`interleaved` (as before), `reachable` (attack cases on alert-reachable
phases plus the benign cases matched to them, interleaved), or explicit case
ids. CLI `run-agent --select`, `--case-id` (repeatable). The 2-case smoke
test and the gated mini-pilot need a local model and have **not** been run.

**Wave A, merged as PR #3.**

- `app/platform`: `DatasetReplayCollector` (dev only: `require_dev` before
  the file is opened; Beats / Logstash / Fluentd are documented production
  adapters, not built), `InMemoryStream` / `KafkaStream` on topic
  `sentinel.alerts.raw`, `enrich()` (event type, source, time, network with
  IP class from `ipaddress`, geo only from Wazuh `GeoLocation`; missing =
  None), `consume()` (validated, idempotent by `alert_id`, rejected messages
  counted with their error, transactions of 1000), `bootstrap.open_stores` /
  `ingest_scenario`.
- `app/storage`: `SqliteDatabase` / `PostgresDatabase` behind one
  `Database` protocol; templated, append-only migrations with sha256 check
  (`core/0001_core.sql`: alerts, cases, runs, agent_transcripts, incidents,
  reports, feedback, approvals, audit_log, users, memory;
  `truth/0001_truth.sql`: ground_truth). Truth is a separate SQLite file or
  PostgreSQL schema `truth`, which the `sentinel_agent` role cannot read.
  `Repository` (core), `AlertReader` (read-only, for agent tools),
  `TruthStore`. `SqliteFtsIndex` / `OpenSearchIndex`, `LocalObjectStore` /
  `MinioObjectStore` (keys validated so they cannot escape the root).
- `app/api`: FastAPI routes for health, login, me, users, alerts (list,
  search, stats, get), cases, runs, incidents (list, get, status), reports,
  feedback, audit, metrics. JWT HS256 with the secret only from
  `SENTINEL_JWT_SECRET` (>= 32 chars), bcrypt passwords, roles analyst /
  manager / admin / executive (read-only, no raw records), every write and
  every denial written to `audit_log`.
- `app/ops/metrics.py`: Prometheus registry (HTTP requests and latency,
  agent tokens, requests, latency, parse failures, dropped claims).
- `docker-compose.yml` (`lite` = PostgreSQL 16 + pgvector; `full` = + Kafka
  KRaft, OpenSearch 2.17 with 512 MB heap, MinIO, Prometheus, Grafana), all
  ports on 127.0.0.1, every secret `${VAR:?}` from a git-ignored `.env`
  (`.env.example` lists the names). `infra/postgres/init/01-roles.sh`.
- CLI: `platform-ingest`, `create-user` (password from
  `SENTINEL_NEW_USER_PASSWORD`), `serve`.
- Nested `backend/CLAUDE.md` and `infra/CLAUDE.md`.

**Wave B1 (on branch `phase3/wave-b`).** `app/intel/attack.py`:
`AttackKB.from_stix` (techniques, tactics, groups; revoked and deprecated
skipped), `map_alert` (Wazuh native `rule.mitre.id` first, then
`RULE_TABLE`, which has one row: Suricata category "Web Application Attack"
-> T1190; anything else unmapped; ids missing from the loaded version are
flagged `known=False`). `app/intel/ioc.py`: `IocStore` (exact ip / domain
with subdomains / url / md5 / sha256 matching over enrichment fields,
Suricata http/tls/dns fields and log-line tokens), disabled OTX / MISP /
VirusTotal adapters whose `offline_sample()` is SYNTHETIC (TEST-NET-3 and
`.example` values). Test sample: `data/samples/synthetic_attack_stix.json`.

## Descriptive dev-scenario statistics used for design decisions

From `data/processed/{russellmitchell,shaw}.alerts.jsonl` (all alerts, both
dev scenarios together; descriptive, not results):

- Wazuh native ATT&CK ids (`rule.mitre.id`): T1078 on 42,540 alerts,
  T1595.002 on 918, T1110.001 on 196, T1110 on 32, T1055 on 18, T1021.004
  on 11, [T1078, T1021] on 9, T1548.003 on 5, [T1055, T1083, T1190] on 4,
  T1190 on 2. All of these ids exist in the downloaded ATT&CK 20.1 bundle
  (`test_real_attack_bundle_has_the_dev_native_ids`).
- Suricata `alert.category`: Generic Protocol Command Decode 24,887, Not
  Suspicious Traffic 826, Potentially Bad Traffic 136, Web Application
  Attack 27, none 16, Misc activity 2. No Suricata alert carries an ATT&CK id
  in its metadata, so only "Web Application Attack" is mapped.
- AMiner component types: NewMatchPathValueDetector 4,613,
  NewMatchPathDetector 676, NewMatchPathValueComboDetector 411,
  CharsetDetector 264, EventCountClusterDetector 122, EventFrequencyDetector
  73, EntropyDetector 60, MatchValueAverageChangeDetector 46,
  ValueRangeDetector 34. Not mapped to techniques.
- russellmitchell raw-record shapes: 3,385 Wazuh records carry
  `GeoLocation` (the only geo source used by enrichment).
- Sigma: pySigma 2.0.2 parsed all 256 rules with 0 errors. Log sources:
  linux/process_creation 123, linux/auditd 53, proxy 29, linux (generic) 15,
  webserver 13, linux/file_event 8, linux/network_connection 5, linux/syslog
  2, apache 2, one each for clamav, cron, guacamole, sshd, vsftpd, nginx.

## Final test and type-check output (end of day)

```
$ ../.venv/Scripts/python.exe -m pytest -q
SKIPPED [1] tests\test_infra_integration.py:28: SENTINEL_TEST_DB_URL not set (docker-compose services not configured)
SKIPPED [1] tests\test_infra_integration.py:28: SENTINEL_TEST_AGENT_DB_URL not set (docker-compose services not configured)
SKIPPED [1] tests\test_infra_integration.py:28: SENTINEL_TEST_SEARCH_URL not set (docker-compose services not configured)
SKIPPED [1] tests\test_infra_integration.py:28: SENTINEL_TEST_KAFKA not set (docker-compose services not configured)
327 passed, 4 skipped in 17.72s
$ ../.venv/Scripts/python.exe -m mypy
Success: no issues found in 53 source files
```

No frontend exists yet, so there is no frontend test output.

## Decisions taken (conservative options, recorded)

1. Search backend in `full` is OpenSearch (Apache-2.0), not Elasticsearch.
2. Embeddings via fastembed + ONNX (CPU, no PyTorch).
3. CICIDS2017 unavailable -> ML baselines on AIT-ADS dev scenarios only.
4. ATT&CK mapping uses detector-native ids plus a one-row rule table; no
   keyword or LLM mapping.
5. The 13 earlier branch commits had a Claude co-author trailer. M2-M4b were
   already on `main` (PR #1) with the trailer; those cannot change without
   rewriting `main`, which was not done. The 4 later commits were rebuilt on
   top of `main` without it (PR #3); PR #2 was closed as superseded.
6. Secret scan before opening the PRs: no keys, tokens, private keys or
   `.env` files anywhere in the history of any branch; only `.env.example`
   (empty values) and a deliberate dummy `sk-test-not-a-real-key` in
   `tests/test_agent_client.py`.

## Where we left off

State at the end of the day: `main` has Wave A (PR #3); this note,
B1 and the CLAUDE.md updates are on `phase3/wave-b` and are merged in the
end-of-day PR.

Not done / not verified:

- **Real dev replay into the platform stores was interrupted** (by the user,
  part-way through russellmitchell). `data/platform/` holds a partial
  `core.db`; delete `data/platform/` and re-run
  `platform-ingest --scenario russellmitchell` and `--scenario shaw`
  (batched writes; expected to take minutes, not measured yet). No real
  replay counts exist yet.
- `docker compose config` not run; no memory measurements of the profiles.
- M6 smoke test and mini-pilot not run (no model).

Next steps, in order:

1. **B2 Sigma engine** (`app/detection/sigma_engine.py`): evaluate pySigma's
   parsed conditions over events built from alert evidence log lines
   (Apache combined -> webserver fields; auditd key=value; syslog
   keyword-only rules); emit `Alert` records with detector `sigma` as an
   additional source (study detectors unchanged; the `Detector` enum and
   `DETECTOR_TYPES` need a new member, so check every place that iterates
   detectors). Report real hit counts per rule on the dev scenarios.
2. **B3 triage and correlation**: dedup (exists), grouping by host / IP /
   time gap, a documented deterministic Low/Medium/High rule, incidents
   written through `Repository.put_incident`, plus an API route to build
   them.
3. **B4 ML baselines**: IsolationForest + a supervised scikit-learn /
   XGBoost model on documented alert features, leakage-safe split by time
   inside the dev scenarios, labels only from the truth area at training
   time; report metrics labelled "detection baselines, dev scenarios".
4. Wave B session notes, PR, merge.
5. **Wave C code** (no model needed for the code): ATT&CK chunks embedded
   with the local bge-small model (SQLite fallback vector table, pgvector in
   `lite`), retrieval tool with a hand-written relevance test set, LangGraph
   supervisor with the six agents, evidence verifier, matched-budget runner;
   FakeClient tests for the graph control flow.
6. **When the internet allows**: resume Ollama (`winget install
   Ollama.Ollama`) and `ollama pull qwen2.5:7b-instruct`; npm packages;
   Docker images. Then: M6 2-case smoke test, gated mini-pilot, Wave C pilot,
   and **stop at the Wave C gate** with the exact numbers.

## Open questions for the user

1. The CICIDS2017 site needs a registration form; if you want CICIDS2017
   baselines, download `MachineLearningCSV.zip` yourself into
   `data/raw/cicids2017/` (otherwise ML stays AIT-ADS dev only).
2. Start Docker Desktop (and install the compose plugin if it is missing)
   when you want the `lite`/`full` profiles tested and measured.

# 2026-11-09: offline build, Waves B2-B4 and Wave C code

Network: none, except `git push` / `gh` for the PR steps. Every process ran
with `HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1`. No downloads, installs or
model calls. All numbers below are pasted from command output; every dev
number is **dev scenario, not a paper result**.

## Pre-flight

- `git status`: clean, on `main`, up to date with `origin/main` (fetch worked).
- Baseline: `pytest -q` -> `327 passed, 4 skipped in 14.76s`; `mypy` ->
  `Success: no issues found in 53 source files`.
- Offline import check (versions printed by `importlib.metadata`):
  pySigma==2.0.2 (no pySigma backends or pipelines installed: none are used,
  the evaluator is ours), scikit-learn==1.9.1, xgboost==3.2.0,
  langgraph==1.2.20, langchain-core==1.7.6, fastembed==0.9.1,
  onnxruntime==1.31.1, pgvector==0.5.1, psycopg==3.3.8, numpy==2.4.6,
  scipy==1.17.1, joblib==1.6.0. All imports ok.
  `TextEmbedding("BAAI/bge-small-en-v1.5", cache_dir=data/models/fastembed,
  local_files_only=True)` -> `bge-small offline load ok, dim 384`.
  **Nothing missing; nothing blocked by the pre-flight.**
- Branch `phase3/wave-b-rest` from `main` (9630c81).
- `data/platform/` confirmed git-ignored (`.gitignore:46: data/platform/`,
  0 tracked files), 126 MB partial store deleted, replay re-run in the
  background (`platform-ingest`, russellmitchell then shaw):
  - russellmitchell: published 45,544, stored 45,544, duplicates 0,
    rejected 0, by detector aminer 4,056 / suricata 9,186 / wazuh 32,302,
    ground_truth_rows 45,544; **wall clock 351 s**.
  - shaw: see the B3 checkpoint (it was still running at the B2 commit).

## B2 checkpoint: Sigma engine (committed on `phase3/wave-b-rest`)

Done: `app/detection/sigma_engine.py` (log-type parsers + our evaluator over
pySigma's parsed conditions; mapping table and skip reasons in the module
docstring), `sigma_report.py`, the label door `app/detection/labels.py`
(`dev_labels`, truth area only, `require_dev` first),
`TruthStore.for_scenario`, `Detector.SIGMA` (rule-based) and
`AIT_ADS_DETECTORS`, CLI `sigma`. Study code iterates `AIT_ADS_DETECTORS`;
a `sigma` variant exists only if `variants.extra_detectors` lists it (it
does not). Frozen-sections hash test added
(`FROZEN_SECTIONS_SHA256 = 3421f54b...93cd`).

Real output, `python -m app.main sigma --scenario russellmitchell`:

```
rules: 256 total, 90 compiled, 166 skipped
  skipped logsource_not_derivable:file_event: 8
  skipped logsource_not_derivable:network_connection: 5
  skipped logsource_not_derivable:process_creation: 123
  skipped logsource_not_derivable:proxy: 29
  skipped logsource_not_in_evidence:nginx: 1
compiled by log type: {'apache_access': 13, 'apache_error': 2, 'auditd': 53, 'syslog': 22}
source alerts 35932, without lines 9186, lines 26746, unclassified lines 86
events by log type: {'apache_access': 10906, 'apache_error': 92, 'auditd': 97, 'syslog': 15613}
sigma alerts: 6387 from 2 rules; runtime load 0.18 s, evaluate 19.33 s
     6386 hits /   10906 events  Suspicious User-Agents Related To Recon Tools  (rules/web/webserver_generic/web_susp_useragents.yml)
        1 hits /   10906 events  Source Code Enumeration Detection by Keyword  (rules/web/webserver_generic/web_source_code_enumeration.yml)

dev detection baseline (dev scenario, not a paper result): verdict = pool alert flagged by some Sigma rule
pool 35932, flagged 6387, event_label unavailable 0
  event_label TP 6348 FP 39 FN 4609 TN 24936 prec 0.9939 recall 0.5794 F1 0.7320 FNR 0.4206
  time_label  TP 6387 FP 0 FN 5410 TN 24135 prec 1.0000 recall 0.5414 F1 0.7025 FNR 0.4586
```

`python -m app.main sigma --scenario shaw --no-score` (engine only; the
shaw dev baseline is in the B3 checkpoint):

```
source alerts 53645, without lines 16692, lines 36953, unclassified lines 65
events by log type: {'apache_access': 6034, 'apache_error': 41, 'auditd': 234, 'syslog': 30587}
sigma alerts: 1468 from 2 rules; runtime load 0.18 s, evaluate 35.21 s
     1467 hits /    6034 events  Suspicious User-Agents Related To Recon Tools  (rules/web/webserver_generic/web_susp_useragents.yml)
        1 hits /    6034 events  Source Code Enumeration Detection by Keyword  (rules/web/webserver_generic/web_source_code_enumeration.yml)
```

Caveat for every Sigma number: Sigma sees only the evidence lines of alerts
another detector already raised, so it is a re-detection rate over the
pool, never a detector comparison.

Detector-iteration sites checked (grep `Detector`): `study/variants.py`
(changed: `AIT_ADS_DETECTORS` + `extra_detectors`), `services/alert_quality.py`
(changed: `AIT_ADS_DETECTORS`, so quality reports keep 3 detector keys),
`study/baselines.py` (changed: a detector outside the frozen order ranks
last instead of raising), `intel/attack.py` (changed: Sigma `attack.tNNNN`
tags are native ids), unchanged and safe: `platform/enrichment.py`,
`ingestion/ground_truth.py`, `ingestion/mappings.py`,
`ingestion/alert_normalizer.py`, `agent/tools.py` (counts by value),
`api/app.py` (string filter, GROUP BY), `evaluation/case_scoring.py` (no
detector logic). No report code exists yet (Wave D).

Decisions taken (B2):

- `cs-uri-query` = the whole request target (path + query), raw, not
  URL-decoded: SigmaHQ's webserver rules match path patterns in that field.
- Keywords match as case-insensitive substrings of the whole line.
- `product: linux` keyword rules and `service: syslog` run on syslog-format
  lines only; `service: apache` on Apache error lines; other services on
  syslog lines whose program tag equals the service name.
- `proxy` rules skipped: the Apache reverse-proxy access log does not carry
  forward-proxy fields (full `c-uri` with host).
- Sigma runs over the investigation-eligible pool (no training-mode,
  duplicate or aggregate alerts), the same pool the study uses.
- One Sigma alert per (rule, source alert); `severity=None` (levels are words).
- `Detector.SIGMA` is typed rule-based.

Next: B3 triage and correlation.
