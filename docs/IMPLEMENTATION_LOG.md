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
