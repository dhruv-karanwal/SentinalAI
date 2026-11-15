# SentinelAI: detector-conditioned, evidence-verified AI investigation of security alerts

**Status: DRAFT (2026-11-15).** Sections marked **PENDING** need runs that have not happened. Every
number here comes from a recorded run (`results/PILOT_GATE.md`, `docs/session-notes.md`) and is
labelled with where it came from. Pilot numbers are dev-scenario material, **not results**. No
held-out run exists. Do not submit before the PENDING sections are filled from real runs.

## Abstract

PENDING (write last, from the held-out results). It must state: the question (does investigation
quality depend on the detector feed, the investigation architecture and evidence verification), the
data (AIT-ADS, two dev and six held-out scenarios), the design (matched-budget single agent vs
LangGraph multi-agent, each before and after a deterministic verifier, six alert-source conditions),
the measures (event-label coverage of attack phases, citation precision, unsupported claims) and the
held-out findings with their confidence intervals.

## 1. Introduction and problem statement

Security operations teams receive alerts from several detectors that disagree, repeat each other and
rarely explain themselves. LLM agents are proposed as investigators, but their conclusions are hard
to check and their quality may depend more on what they are fed than on how they are built.
SentinelAI is a prototype that turns alerts into evidence-backed investigations under a fixed rule:
**autonomous investigation, controlled response** (agents read and explain; any state-changing
action needs a second person's approval and is simulated).

## 2. Objectives

1. A working alert-to-report pipeline (ingest, detect, correlate, investigate, verify, report, approve).
2. A deterministic evidence verifier that removes citations and claims the alert data does not support.
3. A controlled study of three factors: alert source, investigation architecture, verification.

## 3. Related work

PENDING. Write from sources you have read; this draft cites none it has not verified. Topics to cover:
alert correlation and triage, LLM agents for security operations, retrieval-augmented generation,
multi-agent orchestration, evaluation of factual grounding.

## 4. Architecture (implemented)

`docs/architecture.md` holds the full description. In short: replay collector -> stream -> consumer ->
SQLite or PostgreSQL stores (labels in a separate truth area the agents cannot reach) -> detection
(Wazuh, Suricata, AMiner as recorded in the dataset; Sigma over the alerts' log lines; ML scores) ->
triage and union-find correlation with a stated reason per incident -> investigation (single agent or
LangGraph supervisor with six role agents; ATT&CK v20.1 hybrid BM25 + bge-small retrieval for both)
-> deterministic verifier -> report (JSON, CSV, PDF) -> four-eyes approval -> audit. FastAPI with JWT
and role-based access; React console.

## 5. Methodology (frozen design, `docs/research-methodology.md`)

- Data: AIT Alert Data Set (Landauer, Skopik, Wurzenberger; Zenodo DOI 10.5281/zenodo.8263181,
  CC BY 4.0). Split frozen 2026-10-31: dev russellmitchell, shaw; held-out fox, harrison, santos,
  wardbeck, wheeler, wilson.
- Unit: case = an attack phase window or a matched benign window, at most 100 alerts.
- Factors: alert source (wazuh, suricata, aminer, fused, oracle, noise-wazuh control); arm (single
  m5-v5, graph wave-c-v2; same model, temperature 0, budgets, evidence and ATT&CK tools; the graph
  adds shared notes and role prompts); verifier (before / after).
- Measures (deterministic, no LLM judge): event-label coverage of alert-reachable phases (headline),
  citation precision, unsupported-claim rate, verdict accuracy; parse failures, budget hits, tokens,
  time.
- Baselines: cite-all, cite-none, top-k by Wazuh level, top-k by frozen detector order, AMiner only.
- Statistics: paired bootstrap (10,000 resamples, stratified by scenario), Holm over ten declared
  comparisons (`experiments/config/statistics.json`).
- Gate: the pilot fails if any scenario x variant x arm cell has > 20 % parse failures.

## 6. Implementation

See `docs/PRODUCT_READINESS_REPORT.md` for the verified feature list and tests (567 backend tests,
87 frontend tests, strict typing, an automated end-to-end test on the synthetic sample).

## 7. Experimental setup

Model `sentinel-qwen2.5-7b-32k` (qwen2.5:7b-instruct, 32k context) on Ollama 0.40.15, digest
`27d8d9d16c31`, local GPU. Final plan (`experiments/config/final_study.json`): phase i spread repeat 1,
phase ii spread repeats 2-3, phase iii earliest repeat 1.

## 8. Results

### 8.1 Pilot history (dev scenarios; NOT results)

| pilot | prompts | gate | evidence |
|---|---|---|---|
| 2026-11-12/13 | m5-v2 / wave-c-v1 | FAIL: two graph cells 3/14 parse failures | `results/PILOT_GATE.md` |
| 2026-11-13 | m5-v3 / wave-c-v2 | FAIL: one single cell 3/14 (claim `kind` = field name) | same |
| PENDING | m5-v5 / wave-c-v2 | not run | |

### 8.2 Detection, retrieval, correlation (dev; descriptive)

Recorded earlier (2026-11-09/10, dev scenarios, "dev detection baseline"): Sigma 256 rules, 90
compiled, 2 rules fired; HistGB cross-scenario event-label F1 0.896 (rm->shaw) and 0.970 (shaw->rm),
dominated by the 60-second per-host alert rate; ATT&CK retrieval on the frozen 25-query set, hybrid
recall@1/3/5 0.48 / 0.68 / 0.68. PENDING: Sigma coverage funnel, four-model comparison with and
without the rate features, RAG outcomes / MRR, correlation strength distribution (commands in
`docs/windows-guide.md` section 3).

### 8.3 Held-out study

PENDING (after a PASS, the freeze and your go): per-arm and per-source tables, the ten comparisons
with effect sizes, 95 % CIs and Holm-adjusted p-values, from `export-paper-assets` only.

## 9. Discussion

PENDING (from the held-out results).

## 10. Limitations (known now)

- Two dev and six held-out scenarios from one testbed family; one local 7B model.
- Suricata alerts almost never carry event labels (dataset limitation), so its coverage is near zero.
- Sigma re-detects lines other detectors already alerted on; ML scores are in-sample on training
  scenarios and uncalibrated.
- The architecture factor bundles control flow, role prompts and shared notes.
- The verifier checks claims against alert records and log lines only, not ATT&CK statements.
- Repeated pilot iterations on the dev scenarios tuned prompts; held-out scenarios were never used.

## 11. Conclusion and future work

PENDING conclusion. Future work already identified: component ablation of the graph (no notes / no
roles), raw-event ingestion (AIT-LDSv2) for Sigma and correlation, calibrated ML scores, more models.

## References

Only sources already verified in this repository are listed; add the related-work sources you cite.

1. M. Landauer, F. Skopik, M. Wurzenberger. *AIT Alert Data Set*, v1, 2023. Zenodo,
   doi:10.5281/zenodo.8263181.
2. MITRE ATT&CK Enterprise, STIX bundle v20.1 (local copy, `data/raw/mitre/`).
3. SigmaHQ rule repository (approved local copy, `data/raw/sigma/repo/`).

## Presentation / demo outline (matches what is implemented)

1. Problem and philosophy (1 slide). 2. Architecture (pipeline diagram from About). 3. Live demo
(`DEMO.md`): Overview -> incident -> "Why these alerts are together" -> Investigate (graph run, agent
steps, ATT&CK retrieved, verifier) -> report with the investigation -> approval by a second user ->
audit. 4. Study design (factors, measures, gate). 5. Pilot history, honestly (two FAILs, fixes,
C1 correction). 6. Held-out results (PENDING). 7. Limitations and future work.
