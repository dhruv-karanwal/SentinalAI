# Implementation log

One entry per milestone of the product-finalization plan. Details and command output live in
`docs/session-notes.md`; this file is the short index.

## 2026-11-15 — Milestone 1: repository and product audit

- Inspected the whole repository at `090a780`; no code changed.
- Ran: backend pytest 525 passed / 12 skipped, mypy clean (90 files), frontend 80/80 tests,
  typecheck ok, build ok; synthetic end-to-end API walk (reports, approvals, RBAC, audit) all as
  expected.
- Output: `docs/PRODUCT_READINESS_AUDIT.md` (status per feature, critical issues C1-C8, roadmap).
- Open decision for the user: C1, single vs graph arms differ in RAG / memory tool access.

## 2026-11-15 — Milestone 2: research comparison (C1, option a)

- `agent/protocol.py`: m5-v5 (single prompt lists `search_attack`); m5-v4 kept as
  `SYSTEM_PROMPT_M5_V4`, `SINGLE_PROMPTS` by version. `agent/tools.py`: `CaseToolkit(attack=)`.
  `agent/runner.py`, `agent/matched.py`: single arm gets `AttackSearchTool(retriever)`; manifest
  `tool_access`. `study/preflight.py` + CLI `pilot-preflight`.
- Methodology: new section "Investigation arms and tool access" (held constant / differs / what the
  comparison can and cannot establish; shuffled controls not in the plan).
- Found and fixed: `test_run_pilot_cli_resumes_and_logs_progress` wrote into the repo's
  `data/platform/`; session guard fixture in `tests/conftest.py`.
- Tests: `tests/test_prompt_m5_v5.py` (5), `tests/test_preflight.py` (5); pytest 535 passed,
  12 skipped; mypy clean (91 files). `pilot-preflight` here: 3 checks fail as expected (no data,
  no ATT&CK bundle, no model).
- Not done here: the m5-v5 dev re-pilot (Windows + Ollama).

## 2026-11-15 — Milestone 3: multi-agent investigation in the product (C2)

- Backend: `agent/investigation.py` (layered result: observed facts = verified claims, detections of
  kept alerts, ATT&CK knowledge retrieved, hypotheses = unverified model text, conclusion after the
  verifier, playbook recommendations only from verified evidence; steps without system prompts),
  `api/investigations.py` (start 202 / poll / list; 404, 422, 503, 409, 429, 403), migration
  `0004_investigations.sql`, `Repository` investigation methods, permission `investigation.run`,
  ATT&CK retriever in `services_from_env` over an existing index only, `retrieval` in `/copilot/status`.
- Frontend: Incidents tab "Investigate" (workspace + copilot below), `lib/investigation.ts` (+6 tests),
  data-source label no longer calls the synthetic sample a dev scenario.
- Tests: `tests/test_investigation.py` (9: single, graph, retrieval, malformed output, model
  timeout + crash, errors / RBAC, one running + one model job, restart -> interrupted, injected
  instructions cannot act). pytest 544 passed / 12 skipped; mypy clean (93 files); frontend 86/86.
- Browser walk (headless, 1440 / 1366 / 390 px) against the real API with a scripted OpenAI-compatible
  stub (scratchpad, not committed; plumbing only): graph and single runs completed and rendered, 0
  console errors. Not done: a run against the real model (Windows + Ollama).

## 2026-11-15 — Milestone 4: detection (C5 Sigma coverage, C4 ML in the platform)

- Sigma: `CompiledRule.fields`; `detection/sigma_coverage.py` (`rule_coverage`: per-rule status
  matched / evaluated_no_match / no_events_of_log_type / skipped with reason, required vs available
  fields, events evaluated, matches; funnel). `sigma_report.rule_usefulness` (labels, dev only).
  The `sigma` CLI prints the funnel and per-rule usefulness. No rule or mapping changed.
- ML: `ml_baselines` comparison (`COMPARISON_MODELS`, `COMPARISON_FEATURE_SETS` with `no_host_counts`),
  extra metrics in the per-label dicts (accuracy, fpr, pr_auc, roc_auc) and timing; default output
  unchanged. `train_bundle` + `detection/ml_model.py` + CLI `ml-train` / `ml-score`, migration
  `0005_ml_scores.sql`, `Repository.put_ml_scores` / `ml_scores`, `GET /incidents/{id}/ml`, console
  line "ML detection (not used for severity)".
- Tests: `test_sigma_coverage.py` (2), 3 new in `test_ml_baselines.py`, `test_ml_model.py` (4),
  frontend `mlLine` test. pytest 553 passed / 12 skipped; mypy clean (95 files); frontend 87/87.
- Not run here (no real data): `sigma` on the real rules and dev scenarios (funnel numbers),
  `ml-baselines` comparison numbers, `ml-train` on russellmitchell + shaw. Commands in CLAUDE.md.

## 2026-11-15 — Milestone 5: explainable correlation (C6)

- `detection/triage.py`: `correlation(members, config, segment)` re-derives the grouping links inside
  each incident; `detail.correlation` (reason sentence, links by kind, shared indicators, source IPs,
  max link gap, cross-detector links, strength label, method, confidence note). Grouping unchanged.
- Console: incident header "Why these alerts are together" (strength tag + reason + shared entities).
- Tests: `tests/test_correlation.py` (8: single, strong, weak host-only with two sources, moderate without
  source IP, unrelated / missing fields, time boundary, cross-detector, span segments). pytest 561 / 12
  skipped; mypy clean; frontend 87/87.
- Real-data check pending: re-run `triage` on russellmitchell / shaw (Windows) and read the strength
  distribution.
