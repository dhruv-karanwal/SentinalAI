# PROGRESS — SentinelAI handoff (one page)

Read this first every session; update it in every commit that changes project state.
Detailed evidence (command output, decisions) lives in `docs/session-notes.md`.

**Last update:** 2026-11-12, branch `phase3/wave-d-ui-v2`.

## Done
- M1-M5, Wave A (platform), B1-B4 (detection layer), Wave C code (RAG, LangGraph graph,
  verifier, matched runner): merged on `main` (PR #6). 422 passed, 4 skipped, mypy clean.

- `phase3/wave-b-fixes` B4 fix (cross-scenario primary, leave-one-phase-out, permutation
  importances, `no_detector_rule_id` ablation) and B3 fix (span cap 3600 s, chain ids,
  largest-incident description). Numbers: `docs/session-notes.md` (2026-11-10).

- C1 fix: hybrid BM25 + dense retrieval, recall@1/3/5 0.28/0.48/0.56 -> 0.48/0.68/0.68
  (frozen 25-query set, already tried against). Pilot config in study.json, resumable
  `run-matched --resume` and `run-pilot`; pilot-estimate: 336 case runs, 13.44M token bound.
  Merged: PR #7.
- Wave D offline parts (`phase3/wave-d-offline`): reports JSON/CSV/PDF, playbooks, approvals +
  simulated gated executor, copilot route, feedback report, Grafana JSON, security notes, Jira stub.
  465 passed, 4 skipped; mypy clean (80 files). Merged: PR #8.

- Analyst console (branch `phase3/wave-d-ui`, 2026-11-10, user's go before the pilot gate):
  `frontend/DESIGN.md` then the React console: Incidents (split pane, time strip, evidence),
  Alerts, Approvals, Reports, Ask, Audit, Sign in; dark + light, keyboard, windowed tables.
  Backend: `GET /scenarios`, verifier detail in copilot answers. 466 passed, 4 skipped; mypy
  clean; frontend 17 tests, tsc clean, build 311 kB. Per-screen checklist: `docs/session-notes.md`.
  Open: colour-blind simulation, Findings/Ask with a real model answer, report downloads.

- Console v2 (branch `phase3/wave-d-ui-v2`, 2026-11-12): DESIGN.md section 11 first, then an own
  SVG chart module (no library), sign-in with pipeline schematic, Overview, Entity, incident summary
  strip + ATT&CK lanes + entity graph, Alerts facets / saved filters / CSV export, report preview and
  d2 PDF charts, Approvals rules + audit trail, Audit chart, Executive, Study (empty until a real
  run), Settings, Users (env-supplied passwords), notifications, global search. Backend
  `app/api/console.py`, `app/outputs/analytics.py`, `graph_layout.py`, migration 0003.
  482 passed, 4 skipped; mypy clean (83 files); frontend 32 tests, tsc clean, build 421 kB.
  Screenshots in `docs/ui/`; per-screen loop in `docs/session-notes.md`.
  Open: Study with real results, Findings with a real model answer, paper printing, CVD simulation.

## In progress
- Waiting for the model: Ollama installer download (background, resumable), then the 7B pull.

## Downloads (background, approved 2026-11-10)
| item | status | log |
|------|--------|-----|
| Ollama installer (curl -C -, sha256-checked) then `qwen2.5:7b-instruct` | running: 56 MB of 1,690 MB at 02:58 IST, 40-85 kB/s (installer alone 6-11 h) | `data/processed/downloads/ollama.log`, `curl-ollama.err`, `pull-7b.log` |
| Docker Desktop + `pgvector/pgvector:pg16` (lite only) | **blocked**: Docker Desktop not registered (`cannot find registry key "SOFTWARE\Docker Inc.\Docker Desktop"`); reinstall needs admin (you) | `data/processed/downloads/docker.log` |
| npm (frontend) | done 2026-11-10: 23 packages, 69 MB | — |

Docker: the CLI at `D:\Docker\Docker\resources\bin` has no `compose` plugin wired in; the
standalone `docker-compose.exe` (v5.1.3) runs `--profile lite config` and `--profile full
config` cleanly (with placeholder env values).

## Blocked
- Model smoke test (M6) and the matched pilot: waiting for the model download.
- Wave E: only after the user says go.

## Fallback rule (user decision)
If `qwen2.5:7b-instruct` is not usable 3 h after the download started (started 2026-11-10 02:27
IST), pull `qwen2.5:3b-instruct` instead and record that the pilot used the smaller model. The
installer alone will take longer than 3 h at this speed, so check the rule as soon as Ollama is
installed: if the 7B pull would still take hours, start the 3B pull.

## Next steps (in order)
1. When `ollama list` shows the model: M6 smoke test (run-agent, run-matched, limit 2),
   transcripts failure analysis, throughput -> pilot wall-time estimate.
2. If the estimate is <= 8 h: `run-pilot --truncations spread --confirm` in the background
   (resumable); else stop and report options.
3. Pilot report, then GATE (no Wave E until you say go). With a model: check the console's
   Findings and Ask views against a real answer.
4. Docker: reinstall Docker Desktop (admin) if you want the `lite` profile.

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
