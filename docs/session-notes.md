# Session notes

Newest milestone first. All numbers are copied from command output; none
are estimates.

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
