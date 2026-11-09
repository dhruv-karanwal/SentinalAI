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

- C1 fix: hybrid BM25 + dense retrieval, recall@1/3/5 0.28/0.48/0.56 -> 0.48/0.68/0.68
  (frozen 25-query set, already tried against). Pilot config in study.json, resumable
  `run-matched --resume` and `run-pilot`; pilot-estimate: 336 case runs, 13.44M token bound.

## In progress
- PR for `phase3/wave-b-fixes`, then `phase3/wave-d-offline`.

## Downloads (background, approved 2026-11-10)
| item | status | log |
|------|--------|-----|
| Ollama installer (curl -C -, sha256-checked) then `qwen2.5:7b-instruct` | running, ~65 kB/s (installer ~7 h) | `data/processed/downloads/ollama.log`, `curl-ollama.err`, `pull-7b.log` |
| Docker Desktop + `pgvector/pgvector:pg16` (lite only) | **blocked**: Docker Desktop not registered (`cannot find registry key "SOFTWARE\Docker Inc.\Docker Desktop"`); reinstall needs admin (you) | `data/processed/downloads/docker.log` |
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
# Ollama: re-run the resumable script (curl -C - continues the partial installer), or by hand:
curl -L -C - -o ../data/processed/downloads/ollama-installer/OllamaSetup.exe https://github.com/ollama/ollama/releases/download/v0.40.15/OllamaSetup.exe
sha256sum ../data/processed/downloads/ollama-installer/OllamaSetup.exe   # must be 106ef3d2a02437810fba6f574914b1413c512ea84ddd4f184c8e7f434b6f5564
ollama pull qwen2.5:7b-instruct   # re-running resumes a partial pull
ollama list
../.venv/Scripts/python.exe -m pytest -q
../.venv/Scripts/python.exe -m mypy
```
