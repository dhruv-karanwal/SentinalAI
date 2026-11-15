# PROGRESS — SentinelAI handoff (one page)

Read this first every session; update it in every commit that changes project state.
Detailed evidence (command output, decisions) lives in `docs/session-notes.md`.

**Last update:** 2026-11-15, branch `claude/amazing-edison-ns3q8m` (fix 3, m5-v4; demo PR #22 merged).

## Demo (2026-11-16)
- Follow `DEMO.md`. Cold start walked end to end on 2026-11-15: 7 steps ok, 0 console errors, chat
  answered by the local model in 1.7 s, report PDF 29 KB. Study shows pilot rows of the latest prompt
  revision, labelled "not final results".

## RAG evaluation + security controls (2026-11-15)
- `rag-eval`: per-query outcomes, MRR, latency. Failed-login limit (429). Security tests for SQL and log
  injection. pytest 565 passed, 12 skipped.

## C6 correlation reasons (2026-11-15)
- Every newly built incident carries `detail.correlation` (why grouped, shared indicators, gaps, strength
  label); shown in the incident header. Rebuild incidents (`triage`) to add it to stored ones.

## C4 / C5 detection (2026-11-15, code; real-data numbers pending on Windows)
- Sigma: per-rule coverage funnel in the `sigma` report and CLI; per-rule usefulness (attack event_label
  share of hits) in the dev baseline file.
- ML: `ml-baselines` adds a four-model comparison (+ logistic regression, random forest; PR-AUC, ROC-AUC,
  FPR, accuracy, timing) and a `no_host_counts` ablation; `ml-train` / `ml-score` put scores on stored
  alerts (migration 0005), shown per incident, never used for severity.
- pytest 553 passed, 12 skipped; mypy clean (95 files); frontend 87/87, build ok.

## C2 resolved: investigations in the product (2026-11-15)
- Incidents > Investigate: start a single-agent or graph investigation; steps, supervisor route, ATT&CK
  retrieved, verifier, unverified hypotheses and playbook recommendations are stored (migration 0004)
  and shown. Copilot (one question) stays below it. Browser walk vs the real API + scripted stub model:
  0 console errors, no horizontal scroll at 390 px, tabs fit at 1366 px.
- pytest 544 passed, 12 skipped; mypy clean (93 files); frontend 86/86, typecheck + build ok.

## C1 resolved, m5-v5 (2026-11-15, user's option a)
- Single agent now has `search_attack` (same tool and retriever as the graph); prompt m5-v5, m5-v4 text
  preserved. Shared notes stay graph-only (documented in `docs/research-methodology.md`).
- New `pilot-preflight` (+ `--smoke`). Fixed a test that wrote into `data/platform/`; guard fixture added.
- pytest 535 passed, 12 skipped; mypy clean (91 files). **Next (Windows):** preflight, m5-v5 dev re-pilot, gate.

## Product readiness audit (2026-11-15, Milestone 1)
- `docs/PRODUCT_READINESS_AUDIT.md` (status per feature, issues C1-C8, roadmap) and
  `docs/IMPLEMENTATION_LOG.md`. No code changed. Cloud container: pytest 525 passed, 12 skipped;
  mypy clean; frontend 80/80, typecheck + build ok; synthetic API walk as expected.
- **Decision needed before the re-pilot (C1):** the single agent has no `search_attack` / note
  tools, the graph has them, so single vs graph confounds architecture with RAG access.
- Recommended first build milestone: product investigation route + workspace + synthetic e2e test.

## Pilot gate (2026-11-13): FAIL, held-out blocked
- Dev pilot finished 12/12 runs (336 case runs). Gate review in `results/PILOT_GATE.md`.
- Stop rule (> 20 % parse failures in any arm) tripped in 2 cells: russellmitchell aminer graph and
  russellmitchell wazuh graph, 3/14 each (pooled: single 6.5 %, graph 10.1 %).
- Proven defect, not fixed (task rule): `agent/graph.py` reuses the single agent's `REPAIR_MESSAGE`,
  which tells note-ending agents to answer with `final`; 5 of 17 graph parse failures.
- 8 of 11 single parse failures are replies cut at `max_tokens` 1024.
- Fixes 1 and 2 done (user's go, test-first; pytest 523 passed, 4 skipped; mypy clean): per-node
  graph repair message, graph brief without "final answer" for workers / supervisor, output cap
  20 ids / 10 claims (m5-v3, wave-c-v2). Fixes 3 (json_object) and 4 (graph pacing) not applied.
- Re-pilot done (12/12, exit 0): still **FAIL in one cell**, russellmitchell wazuh single 3/14 = 21.4 %,
  all three a claim `kind` set to a field name. Pooled single 6.0 %, graph 4.8 % (was 10.1 %); the
  repair defect is gone (0 rejected `final` retries). Held-out extrapolation ~18.5 h.
- Waiting for the user: fix 3 (`kind` prompt line, m5-v4, re-pilot ~1.6 h) or accept the cell as a
  documented deviation. Stats/export now pick one prompt revision (`--prompt-version`, default latest; warns on a mix), 2026-11-15.
  No protocol freeze, no held-out ingest until then.
- **Fix 3 applied 2026-11-15** (user's go): single prompt m5-v4 adds one line under the final-answer
  form: `kind is always "field_value" or "quote"; put the field name in field.` Graph prompts stay
  wave-c-v2 (hash pinned by a test). pytest 525 passed, 12 skipped (cloud container: no real data);
  mypy clean (90 files). **Next:** dev re-pilot on m5-v4 on the Windows machine (resume command in
  `docs/session-notes.md`, "Prompt fix 3"), then re-gate with `--prompt-version m5-v4`. No freeze.

## Done
- Premium console (`phase3/wave-h-premium`, 2026-11-14/15, user's go; pilot untouched): restraint
  pass (no grain / glass / glow / pulse / tilt / count-up), ink accent, Geist type, base components on
  every screen, grouped rail, Ctrl+K command palette, About as a product page, phone layouts, style
  guard test. Frontend 78 tests, tsc clean, build ok; 12 screens x (dark, light, 390 px): 0 console
  errors, no horizontal scroll. Screenshots `docs/ui/wave-h/`. DESIGN.md rewritten.
  2026-11-15 finish: two read-only reviews (visual, a11y), concrete defects fixed (Audit phone rows and
  chart unit, KPI truncation, unit wrapping, report timestamps, dialog / chat / tour focus); list of
  what was not fixed in `docs/session-notes.md`. Open: phone layouts of Users / Alerts / Approvals,
  screen-reader check, frame time on the 11,208-alert incident.
- Palette (`phase3/wave-g-palette`, 2026-11-13, user's go; pilot untouched): blue replaced by "warm
  graphite + phosphor lime" (tokens.css only; lime on logo, active nav, primary button, focus, chat
  button, links), warm grain instead of the blue grid, glows only on High and the chat button, PDF
  detector colours = light tokens. New `lib/palette.test.ts` (CVD OKLab distances, raw-colour and
  blue-hue guards). Frontend 57 tests, tsc clean, build ok; backend 520 passed, 4 skipped, mypy clean.
  Screenshots both themes in `docs/ui/wave-g/` (0 console errors, no horizontal scroll). DESIGN.md 14.
- README rewritten for the whole project (status per wave, architecture, quick start, study design)
  with a screenshot gallery; Wave F screenshots copied into `docs/ui/wave-f/` (19 files). Launch
  config: `api` entry via `.claude/serve-api.ps1` (secrets from `.env.ui-dev`, UI-dev data copy).
- Motion console (`phase3/wave-f-motion-ui`, 2026-11-13, user's go; pilot untouched): mission-control
  layer + motion system (DESIGN.md 13), About as a scroll story, Overview counters / chart draw-in /
  glowing look-first cards, floating help chat with `GET /copilot/status` (probe, no generation).
  Backend 520 passed, 4 skipped, mypy clean; frontend 54 tests, tsc clean, build ok. One real chat call
  after the pilot finished: 10.0 s incl. cold model load, answer grounded in the glossary.
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
  482 passed, 4 skipped on the branch; after merging main (PR #11, final-study tooling): 504 passed,
  4 skipped, mypy clean (88 files); frontend 32 tests, tsc clean, build 421 kB.
  Screenshots in `docs/ui/`; per-screen loop in `docs/session-notes.md`.
  Open: Study with real results, Findings with a real model answer, paper printing, CVD simulation.

- Explainable console (branch `phase3/wave-e-explainable-ui`, 2026-11-13, while the dev pilot ran;
  no study, agent, experiments or data file touched): glossary + `<Term>` tooltips, About page
  (Professor demo mode landing), 6-stop tour, help chat (explain mode of `/copilot/ask`, glossary
  fallback), Overview in two layers, "What happened", folded alert repeats, distinct incident labels,
  graph labels without overlap (console + PDF), data / created dates, Study explained (pilot / final /
  ad hoc). pytest 517 passed, 4 skipped; mypy clean (89 files); frontend 41 tests, tsc clean, build ok.
  Screenshots in `docs/ui/`; checks in `docs/session-notes.md` (2026-11-13).
  Open: help chat against the real model (only mocked: pilot running), report PDF graph labels not
  looked at in a rendered PDF, CVD simulation.

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

## Final runs agent (branch `phase3/final-runs`, worktree `D:\Projects\ERA-final`)
**Last update:** 2026-11-12 IST.
- Built (tests first): `app/study/stats.py` (paired bootstrap + Holm), `app/study/freeze.py`
  (`protocol-freeze`, `--allow-held-out` permit, access log), `app/study/final_runs.py` (plan of
  `experiments/config/final_study.json`, per-scenario checkpoints, per-case rows),
  `app/study/paper_assets.py` (`export-paper-assets` -> `results/`), CLI `app/cli_final.py`
  (`protocol-freeze`, `final-plan`, `run-final`, `study-stats`, `export-paper-assets`).
  Matched runs now write `per_case` scores and `study_part` (pilot / held-out / adhoc).
- Model: segmented download `data/processed/downloads/final_fetch.py` (log `final-fetch.log`).
- Decisions: `docs/session-notes.md`, "Final runs agent, 2026-11-12".
- Model ready 2026-11-12 21:30: `sentinel-qwen2.5-7b-32k` (42 tok/s, 7.2/8.2 GB VRAM). Smoke test
  done; prompt revision 1 (m5-v2). Next: pilot (spread) in the background.
- 2026-11-13: pilot crashed after 5/12 runs (`cid` UnboundLocalError in the hybrid retriever when
  a query has no BM25 match); fixed test-first, nothing the model saw changed; pilot resumed
  from its checkpoints (`data/processed/downloads/run_pilot.ps1`, log `runs/pilot-console.log`).
