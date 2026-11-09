# PROGRESS — SentinelAI handoff (one page)

Read this first every session; update it in every commit that changes project state.
Detailed evidence (command output, decisions) lives in `docs/session-notes.md`.

**Last update:** 2026-11-10, branch `phase3/wave-b-fixes`.

## Done
- M1-M5, Wave A (platform), B1-B4 (detection layer), Wave C code (RAG, LangGraph graph,
  verifier, matched runner): merged on `main` (PR #6). 422 passed, 4 skipped, mypy clean.

- `phase3/wave-b-fixes` B4 fix (cross-scenario primary, leave-one-phase-out, permutation
  importances, `no_detector_rule_id` ablation) and B3 fix (span cap 3600 s, chain ids,
  largest-incident description). Numbers: `docs/session-notes.md` (2026-11-10).

## In progress
- `phase3/wave-b-fixes`: C1 (hybrid retrieval), pilot config + resumable `run-matched`
  with the `single+verifier` arm.

## Downloads (background, approved 2026-11-10)
| item | status | log |
|------|--------|-----|
| Ollama (winget) + `qwen2.5:7b-instruct` | started 2026-11-10 | `data/processed/downloads/ollama.log`, `pull-7b.log` |
| Docker Desktop + `pgvector/pgvector:pg16` (lite only) | started 2026-11-10 | `data/processed/downloads/docker.log` |
| npm (frontend) | not started: only when the dashboard starts (after the pilot gate) | — |

Docker: the CLI at `D:\Docker\Docker\resources\bin` has no `compose` plugin wired in; the
standalone `docker-compose.exe` (v5.1.3) runs `--profile lite config` and `--profile full
config` cleanly (with placeholder env values).

## Blocked
- Model smoke test (M6) and the matched pilot: waiting for the model download.
- Wave E: only after the user says go. React frontend: only after the pilot report and a go.

## Next steps (in order)
1. Finish `phase3/wave-b-fixes`, PR, merge.
2. `phase3/wave-d-offline`: reports, approvals, feedback, copilot route, Grafana JSON,
   security notes, Jira stub.
3. When `ollama list` shows the model: smoke test, throughput, pilot estimate, pilot, GATE.

## Resume commands (from `backend/`)
```bash
bash <scratchpad>/dl_ollama.sh   # or: winget install Ollama.Ollama ; ollama pull qwen2.5:7b-instruct
ollama list
../.venv/Scripts/python.exe -m pytest -q
../.venv/Scripts/python.exe -m mypy
```
