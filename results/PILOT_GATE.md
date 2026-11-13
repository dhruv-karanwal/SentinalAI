# Pilot gate review (2026-11-13)

**PILOT material: dev scenarios russellmitchell and shaw only. Not paper results.**
Model `sentinel-qwen2.5-7b-32k` (Ollama 0.40.15, temperature 0), single prompt m5-v2, graph prompts
wave-c-v1, retrieval hybrid, truncation spread, `select reachable`. 12 runs x 14 cases x 2 arms =
336 case runs, all finished (`data/processed/runs/pilot-progress.jsonl`: 12/12 `done`).
No held-out file was read or ingested; no study code was changed.

## Verdict: **FAIL**

1. **Stop rule tripped.** Two scenario x variant x arm cells have 3/14 = **21.4 %** parse failures
   (> 20 %): russellmitchell `aminer` graph and russellmitchell `wazuh` graph. Pooled per arm the
   rates are 11/168 = 6.5 % (single) and 17/168 = 10.1 % (graph), under the threshold. With 14
   cases per cell one case is 7.1 points, so the cell-level reading is the strict one; I applied it.
2. **A defect is proven** in the graph arm's repair path (below). Per the task brief it is reported,
   not fixed. Do not freeze the protocol until it is decided: the fix changes `graph.py`, which is
   in the frozen code and the matched config, so the pilot has to be re-run after it.

## 1. Cases per scenario x variant x arm

Counts from `cases/*.checkpoint.json` (`results/pilot_gate/gate_table.py`). parse-failed =
`status failed, parse_status unparseable` (after the one repair). Budget hits are not parse failures.

| scenario | variant | arm | cases | ok | parse-failed | tool-budget | token-budget | repairs | parse-fail rate |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| russellmitchell | wazuh | single | 14 | 12 | 2 | 0 | 0 | 4 | 14.3 % |
| russellmitchell | wazuh | graph | 14 | 11 | **3** | 0 | 0 | 6 | **21.4 %** |
| russellmitchell | suricata | single | 14 | 14 | 0 | 0 | 0 | 0 | 0.0 % |
| russellmitchell | suricata | graph | 14 | 12 | 2 | 0 | 0 | 3 | 14.3 % |
| russellmitchell | aminer | single | 14 | 13 | 1 | 0 | 0 | 1 | 7.1 % |
| russellmitchell | aminer | graph | 14 | 11 | **3** | 0 | 0 | 3 | **21.4 %** |
| russellmitchell | fused | single | 14 | 13 | 1 | 0 | 0 | 1 | 7.1 % |
| russellmitchell | fused | graph | 14 | 11 | 1 | 1 | 1 | 1 | 7.1 % |
| russellmitchell | oracle | single | 14 | 13 | 1 | 0 | 0 | 1 | 7.1 % |
| russellmitchell | oracle | graph | 14 | 11 | 1 | 0 | 2 | 1 | 7.1 % |
| russellmitchell | noise-wazuh | single | 14 | 13 | 1 | 0 | 0 | 1 | 7.1 % |
| russellmitchell | noise-wazuh | graph | 14 | 13 | 1 | 0 | 0 | 4 | 7.1 % |
| shaw | wazuh | single | 14 | 12 | 2 | 0 | 0 | 4 | 14.3 % |
| shaw | wazuh | graph | 14 | 12 | 2 | 0 | 0 | 2 | 14.3 % |
| shaw | suricata | single | 14 | 14 | 0 | 0 | 0 | 0 | 0.0 % |
| shaw | suricata | graph | 14 | 13 | 1 | 0 | 0 | 1 | 7.1 % |
| shaw | aminer | single | 14 | 13 | 1 | 0 | 0 | 1 | 7.1 % |
| shaw | aminer | graph | 14 | 12 | 2 | 0 | 0 | 3 | 14.3 % |
| shaw | fused | single | 14 | 12 | 1 | 0 | 1 | 1 | 7.1 % |
| shaw | fused | graph | 14 | 14 | 0 | 0 | 0 | 2 | 0.0 % |
| shaw | oracle | single | 14 | 13 | 1 | 0 | 0 | 2 | 7.1 % |
| shaw | oracle | graph | 14 | 13 | 0 | 1 | 0 | 1 | 0.0 % |
| shaw | noise-wazuh | single | 14 | 14 | 0 | 0 | 0 | 0 | 0.0 % |
| shaw | noise-wazuh | graph | 14 | 12 | 1 | 0 | 1 | 3 | 7.1 % |

Totals: single 156 ok / 11 parse / 0 tool / 1 token (6.5 % parse); graph 145 ok / 17 parse / 2 tool /
4 token (10.1 % parse). No `request_failed` or other status.

## 2. Failure analysis

### russellmitchell fused, graph arm (3 of 14 failed, 2 budget hits)

| case | phase | status | where | class | cause |
|---|---|---|---|---|---|
| 000 | service_scans (100 alerts) | tool_budget_exceeded | investigation | **budget setting** | log_analysis, correlation and knowledge_retrieval each used their 4-call turn limit (12 = the whole case budget). anomaly_analysis got the one budget notice and complied; investigation then made one tool call, which by design stops the case. 6 agents x `max_turn_tool_calls` 4 = 24 > `max_tool_calls` 12, so the first three agents can spend the whole budget. |
| 008 | cracking (12 alerts) | failed / unparseable | report_generation | **format (model)** | First reply: malformed JSON (the `findings` array is never closed: `...]}}` instead of `...]}]}`). Repair used. Second reply: valid JSON but a claim with `"kind": "rule_id"` (only `field_value` / `quote` are allowed), rejected correctly. Its quote claim also copied note text, not a log line. Parser behaved as specified. |
| 010 | privilege_escalation (24 alerts) | token_budget_exceeded | report_generation | **budget setting** | 36,814 input + 1,638 output tokens used by the five agents before the report; the report request's bound (used + prompt at 3 chars/token + `max_tokens` 1024) was 40,957 > 40,000. The case never reached the report. |

So: one model format problem (prompt-sensitive, parser correct) and two budget-setting problems. Not
a context overflow (num_ctx 32,768; the largest request in any pilot transcript was 11,700 tokens, input + output) and not a tool loop.

### All 34 non-ok case runs (pilot)

`results/pilot_gate/classify.py`, by the last failing request:

| class | single | graph | kind of problem |
|---|---:|---:|---|
| output cut at `max_tokens` 1024 (`finish_reason=length`, reply ends mid-list) | 8 | 0 | **budget setting** (the model cites up to ~100 alert ids, one claim each; the repair repeats the same long answer) |
| malformed JSON (unclosed `findings` array, arithmetic like `66.655 - 2254`) | 2 | 8 | format; 7 of 8 graph cases in report_generation |
| several JSON objects in one reply (parallel tool calls) | 1 | 3 | format / prompt |
| **non-report agent replies `final` after the repair message** | 0 | **5** | **defect (below)** |
| invalid claim schema | 0 | 1 | format |
| token budget | 1 | 4 | budget setting (graph uses ~2x the tokens of single under the same 40k cap) |
| tool budget | 0 | 2 | budget / pacing setting |

### Proven defect: graph repair message names the wrong reply forms

`backend/app/agent/graph.py:246` reuses the single agent's `REPAIR_MESSAGE`
(`backend/app/agent/protocol.py:72`), which says the valid forms are `call_tool` or `final`. For the
five note-ending agents the valid forms are `call_tool` or `note` (and `route` for the supervisor).
Observed sequence (russellmitchell aminer case 000, anomaly_analysis): the agent writes
`{"action": "note", text: ...}` (unquoted key), gets the repair message listing `final`, replies
`{"action": "final", ...}` and is rejected with `"action" must be one of call_tool, note`, which
fails the case. Across the pilot, note-agent repairs: 9; 5 of them ended exactly this way
(russellmitchell aminer 000 and 004, shaw aminer 004, shaw suricata 011, shaw wazuh 003), 1 recovered,
3 hit another error. This accounts for 5 of the 17 graph parse failures. A contributing prompt issue:
every graph agent's brief (`CaseToolkit.brief()`, shared with the single agent) ends with "then give
your final JSON answer".

Removing these 5 cases would bring russellmitchell aminer graph to 1/14, but russellmitchell wazuh
graph stays at 3/14 (two malformed report JSONs, one multi-object reply), so the defect fix alone
does not clear the stop rule.

### Recommended fixes (each changes the protocol; the pilot must be re-run on dev after them)

1. **Defect (required):** a repair message per node that lists that node's forms (route / call_tool +
   note / call_tool + final); the graph agents' brief without "then give your final JSON answer".
   Bump `GRAPH_PROMPT_VERSION`; FakeClient test: a note-agent repair offers `note`, never `final`.
   Evidence: the 5 cases above.
2. **Output cap (recommended):** 8 of 11 single-arm parse failures are replies cut at 1,024 output
   tokens. Prefer a prompt cap ("cite at most 20 alert ids and 10 claims") over a higher
   `max_tokens`: a higher `max_tokens` also raises the per-request reserve in the token check and
   would add token-budget hits. Bump `PROMPT_VERSION`.
3. **JSON syntax (option, verify first):** 14 format failures (11 graph, 3 single) are syntax errors.
   Ollama's OpenAI-compatible endpoint accepts `response_format: {"type": "json_object"}`; it would
   remove syntax errors but not schema or truncation errors. Needs a smoke test before adoption; it
   is a client change for both arms.
4. **Graph pacing (your call):** `max_turn_tool_calls` 2 (6 agents x 2 = the 12-call budget) would
   stop the first three agents from spending the whole case budget. The per-case budgets stay equal
   across arms (matched-budget design); only pacing inside the graph changes.

## 3. Controls

Event-label coverage on reachable phases (covered / reachable attack cases), from `scores.json`
(`results/pilot_gate/controls.py`):

| scenario | variant | single | single+verifier | graph | graph+verifier | cite-all | cite-none | top-k det-order@k10 |
|---|---|---|---|---|---|---|---|---|
| russellmitchell | wazuh | 3/7 | 3/7 | 3/7 | 3/7 | 4/7 | 0/7 | 4/7 |
| russellmitchell | suricata | 1/7 | 1/7 | 1/7 | 1/7 | 1/7 | 0/7 | 1/7 |
| russellmitchell | aminer | 2/7 | 2/7 | 0/7 | 0/7 | 6/7 | 0/7 | 6/7 |
| russellmitchell | fused | 5/7 | 5/7 | 2/7 | 2/7 | 7/7 | 0/7 | 6/7 |
| russellmitchell | oracle | 5/7 | 5/7 | 1/7 | 1/7 | 7/7 | 0/7 | 7/7 |
| russellmitchell | noise-wazuh | 0/7 | 0/7 | 0/7 | 0/7 | 0/7 | 0/7 | 0/7 |
| shaw | wazuh | 2/7 | 2/7 | 2/7 | 2/7 | 3/7 | 0/7 | 3/7 |
| shaw | suricata | 0/7 | 0/7 | 0/7 | 0/7 | 0/7 | 0/7 | 0/7 |
| shaw | aminer | 2/7 | 2/7 | 0/7 | 0/7 | 7/7 | 0/7 | 7/7 |
| shaw | fused | 5/7 | 5/7 | 2/7 | 2/7 | 6/7 | 0/7 | 6/7 |
| shaw | oracle | 4/7 | 4/7 | 1/7 | 1/7 | 7/7 | 0/7 | 7/7 |
| shaw | noise-wazuh | 0/7 | 0/7 | 0/7 | 0/7 | 0/7 | 0/7 | 0/7 |

As predicted: `noise-wazuh` is 0/7 for every arm and baseline on both scenarios; `cite-none` is 0/7;
`cite-all` reaches the ceiling (7/7 on oracle); Suricata is near zero (the documented labelling
limitation). Baselines present in every run: cite-all, cite-none, cite-aminer-only,
cite-top-k-wazuh-level and cite-top-k-detector-order at k5, k10 and matched k.

Flags:
- **Oracle, graph arm: 1/7 on both scenarios** (single 5/7 and 4/7). The oracle view holds only
  attack-labelled alerts, so this is the agent, not the control: of 14 oracle attack runs the graph
  failed 4 (3 budget, 1 parse) and answered `benign` with no citations on 7. In one case
  (russellmitchell webshell) it cited an invented id (`1234567890abcdef...`), scored as a wrong
  citation outside the case, which is correct. The H7 pilot difference (oracle minus fused,
  graph+verifier) is negative (-0.14), the opposite of the protocol's expectation.
- **Graph aminer 0/7 on both scenarios** with no citations; 3 of its 5 failures are the repair defect.
- `shuffled-<det>` rows are not part of the pilot (`pilot.variants` lists only noise-wazuh as a
  control), so they could not be checked here.
- No agent arm beats `cite-top-k-detector-order@k10` on coverage in any cell (pilot, n = 7 per cell).
- Coverage is identical before and after the verifier in every cell: the verifier drops claims and
  out-of-case citations only, so this is expected.

## 4. Statistics tooling (PILOT)

`python -m app.main study-stats --part pilot` ran end to end in ~1 s over the 10 declared
comparisons (paired bootstrap, 10,000 resamples, stratified by scenario, Holm). Output with the
PILOT label: `results/pilot_gate/study_stats_PILOT.txt`. These numbers are not paper results and
are not interpreted here. Notes for the final study: H3 (graph claims before vs after the verifier)
has n = 2 paired cases, because the graph rarely ends with claims; H2 has n = 10. Expect wide
intervals there unless the fixes raise the graph completion rate.

## 5. Held-out runtime (extrapolation)

Measured: per-case wall time summed from the checkpoints is 1,760 s (single) + 4,051 s (graph) for
168 cases, i.e. 34.6 s per case for both arms. Per dev scenario (6 variants x 14 cases):
russellmitchell 3,281 s, shaw 2,529 s, mean 2,905 s (48 min).

Extrapolation, assuming 14 reachable-selected cases per held-out scenario and dev-like alert
density (neither is known before ingest), same model and GPU:

| phase | content | estimate |
|---|---|---|
| i | spread, repeat 1, 6 scenarios | ~4.8 h (4.2-5.5 h) |
| ii | spread, repeats 2 and 3 | ~9.7 h (8.4-10.9 h) |
| iii | earliest, repeat 1 (not measured in the pilot; same cap of 100, assumed equal) | ~4.8 h (4.2-5.5 h) |
| total | | ~19 h (17-22 h) |

The range uses the shaw and russellmitchell per-scenario times. Fixes 2 and 4 would change timings;
re-measure on the re-run pilot. Held-out ingest time is not included.

## 6. Next commands

Gate is FAIL: first decide the fixes above, implement them test-first on a branch, and re-run the dev
pilot (resumable; a changed config hash starts new run directories):

```bash
cd backend
../.venv/Scripts/python.exe -m pytest
../.venv/Scripts/python.exe -m mypy
../.venv/Scripts/python.exe -m app.main run-pilot --truncations spread --dry-run
../.venv/Scripts/python.exe -m app.main run-pilot --truncations spread --confirm
```

Then re-run this review. Only after a PASS (in this order; held-out only with your go):

```bash
cd backend
# 1. freeze (digest of the model in use: `ollama list` shows id 27d8d9d16c31 for sentinel-qwen2.5-7b-32k)
../.venv/Scripts/python.exe -m app.main protocol-freeze --model-digest 27d8d9d16c31
# 2. ingest the held-out scenarios (raw files are in data/raw/ait_ads/)
for s in fox harrison santos wardbeck wheeler wilson; do
  ../.venv/Scripts/python.exe -m app.main ingest-alerts --data-dir ../data/raw/ait_ads --scenario $s
done
# 3. plan and bound, then the phases in order (resumable)
../.venv/Scripts/python.exe -m app.main run-final --allow-held-out --dry-run
../.venv/Scripts/python.exe -m app.main run-final --allow-held-out --confirm --phases i
../.venv/Scripts/python.exe -m app.main run-final --allow-held-out --confirm --phases ii
../.venv/Scripts/python.exe -m app.main run-final --allow-held-out --confirm --phases iii
# 4. statistics and paper assets
../.venv/Scripts/python.exe -m app.main study-stats --part held-out
../.venv/Scripts/python.exe -m app.main export-paper-assets
```

Not checked here: whether `ingest-alerts` on the held-out scenarios needs any other preparation for
`run-final` (it reads `data/processed/<scenario>.alerts.jsonl` and `labels.csv`; confirm with the
`--dry-run` first); the `json_object` response format against Ollama 0.40.15.
