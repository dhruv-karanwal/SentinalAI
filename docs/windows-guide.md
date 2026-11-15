# Windows guide: run, validate and finish the study

For the Windows machine that holds the data, the model and Docker (`D:\Projects\ERA`). Everything
here was written in a cloud container that had **none** of those, so every step below that needs them
is **pending** until run on Windows. `DEMO.md` stays the short demo path; this file is the full
procedure. PowerShell from the repository root unless a step says `backend\` or `frontend\`.

## 1. Prerequisites

| item | where | check |
|---|---|---|
| Python 3.11+ venv | `.venv\` | `.\.venv\Scripts\python.exe --version` |
| backend deps | `pip install -r backend\requirements-dev.txt` | `python -c "import fastapi, sklearn, joblib, langgraph"` |
| Node 22.18+ | `frontend\` | `npm --prefix frontend ci` |
| Ollama 0.40.15 + `sentinel-qwen2.5-7b-32k` | `%LOCALAPPDATA%\Programs\Ollama` | `ollama list` (digest `27d8d9d16c31`) |
| AIT-ADS files | `data\raw\ait_ads\` (layout in CLAUDE.md, "Gotchas") | `russellmitchell_wazuh.json`, `labels.csv`, `alerts_csv\...` |
| ATT&CK v20.1 bundle | `data\raw\mitre\enterprise-attack.json` | file exists |
| SigmaHQ rules | `data\raw\sigma\repo\rules\{linux,web}` | 256 `.yml` |
| bge-small (fastembed cache) | `data\models\fastembed\` | `rag-eval` runs offline |
| Docker Desktop (optional infra) | | `docker compose version` |

Environment variables (never as arguments, never committed):

| variable | used by | example |
|---|---|---|
| `SENTINEL_JWT_SECRET` (>= 32 chars) | API | from `.env.ui-dev` |
| `SENTINEL_NEW_USER_PASSWORD` | `create-user` | set only for that command |
| `SENTINEL_LLM_BASE_URL`, `SENTINEL_LLM_MODEL` | agents, copilot, investigations | `http://127.0.0.1:11434/v1`, `sentinel-qwen2.5-7b-32k` |
| `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1` | RAG | always |
| `SENTINEL_DATA_DIR` | API stores | `data\processed\ui-dev` for UI work |
| `SENTINEL_RAG_DIR` | API ATT&CK search | folder with `vectors.db` (default `data\platform`) |
| `SENTINEL_DB_URL`, `SENTINEL_SEARCH_URL`, `SENTINEL_KAFKA`, `SENTINEL_OBJECTS` + `SENTINEL_MINIO_*` | optional infra | from `.env` |
| `SENTINEL_TEST_DB_URL`, `SENTINEL_TEST_AGENT_DB_URL`, `SENTINEL_TEST_SEARCH_URL`, `SENTINEL_TEST_KAFKA` | the 4 infra tests | the running compose services |

## 2. Checks (record the real output)

```powershell
cd backend
..\.venv\Scripts\python.exe -m pytest -q        # expect all data tests to run: only the 4 infra tests skip
..\.venv\Scripts\python.exe -m mypy
cd ..\frontend; npm test; npm run typecheck; npm run build; cd ..
```

## 3. Bring the stores up to date (dev scenarios only)

The code since 2026-11-15 adds migrations 0004 (investigations) and 0005 (ML scores); they apply on
the next start. Incidents built before C6 have no correlation reason: rebuild them.

```powershell
cd backend
$env:HF_HUB_OFFLINE="1"; $env:TRANSFORMERS_OFFLINE="1"
..\.venv\Scripts\python.exe -m app.main triage --scenario russellmitchell      # adds detail.correlation
..\.venv\Scripts\python.exe -m app.main triage --scenario shaw
..\.venv\Scripts\python.exe -m app.main sigma --scenario russellmitchell        # coverage funnel + usefulness
..\.venv\Scripts\python.exe -m app.main sigma --scenario shaw
..\.venv\Scripts\python.exe -m app.main ml-baselines --scenarios russellmitchell shaw   # + model comparison
..\.venv\Scripts\python.exe -m app.main ml-train --scenarios russellmitchell shaw
..\.venv\Scripts\python.exe -m app.main ml-score --scenario russellmitchell
..\.venv\Scripts\python.exe -m app.main ml-score --scenario shaw
..\.venv\Scripts\python.exe -m app.main rag-eval                                 # recall, MRR, outcomes, latency
```

For the console, run `triage` and `ml-score` with `--data-dir ..\data\processed\ui-dev` too (the UI copy).

## 4. Start the product

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .claude\serve-api.ps1   # API on 127.0.0.1:8000
npm --prefix frontend run dev                                              # console on 127.0.0.1:5173
```

`GET /copilot/status` shows the model state and `retrieval` (on only when `SENTINEL_RAG_DIR` holds
`vectors.db` and the ATT&CK bundle is present).

## 5. Optional infrastructure validation (pending; never run so far)

```powershell
copy .env.example .env   # fill it
docker compose --profile lite up -d        # PostgreSQL + pgvector
docker compose --profile full up -d        # + OpenSearch, Kafka, MinIO, Prometheus, Grafana
docker compose ps                          # every service healthy
$env:SENTINEL_TEST_DB_URL="postgresql://..."; $env:SENTINEL_TEST_AGENT_DB_URL="postgresql://..."
$env:SENTINEL_TEST_SEARCH_URL="http://127.0.0.1:9200"; $env:SENTINEL_TEST_KAFKA="127.0.0.1:9092"
cd backend; ..\.venv\Scripts\python.exe -m pytest -q -m infra
```

Then once with `SENTINEL_DB_URL` / `SENTINEL_SEARCH_URL` / `SENTINEL_KAFKA` / `SENTINEL_OBJECTS=minio`
set: `platform-ingest --scenario russellmitchell` into a fresh database, `serve`, sign in, open an
incident, write a report; stop a service and check the API answers with an error, not a hang. Record
each result; until then report these backends as "interface present, not validated".

## 6. Research: m5-v5 pilot, gate, freeze, held-out (in this order)

```powershell
cd backend
$env:SENTINEL_LLM_BASE_URL="http://127.0.0.1:11434/v1"; $env:SENTINEL_LLM_MODEL="sentinel-qwen2.5-7b-32k"
ollama ps                                                       # nothing else uses the model
ollama run sentinel-qwen2.5-7b-32k --keepalive 60m "Reply OK"  # pre-warm
..\.venv\Scripts\python.exe -m app.main pilot-preflight --smoke    # must print "result: ready"
..\.venv\Scripts\python.exe -m app.main run-pilot --truncations spread --dry-run
powershell -File ..\data\processed\downloads\run_pilot.ps1         # detached; same command resumes
```

Gate on the m5-v5 runs only (stop rule: > 20 % parse failures in any scenario x variant x arm cell):

```powershell
..\.venv\Scripts\python.exe ..\results\pilot_gate\gate_table.py ..\data\processed\runs m5-v5
..\.venv\Scripts\python.exe ..\results\pilot_gate\classify.py   ..\data\processed\runs m5-v5
..\.venv\Scripts\python.exe ..\results\pilot_gate\controls.py   ..\data\processed\runs m5-v5
..\.venv\Scripts\python.exe -m app.main study-stats --part pilot --prompt-version m5-v5
```

Append PASS / FAIL with the evidence to `results/PILOT_GATE.md` (never delete earlier sections). On a
FAIL: classify, fix the cause, new prompt version, re-pilot. Only after a PASS and your go:

```powershell
..\.venv\Scripts\python.exe -m app.main protocol-freeze --model-digest 27d8d9d16c31
foreach ($s in "fox","harrison","santos","wardbeck","wheeler","wilson") {
  ..\.venv\Scripts\python.exe -m app.main ingest-alerts --data-dir ..\data\raw\ait_ads --scenario $s }
..\.venv\Scripts\python.exe -m app.main run-final --allow-held-out --dry-run      # recompute the runtime here
..\.venv\Scripts\python.exe -m app.main run-final --allow-held-out --confirm --phases i
..\.venv\Scripts\python.exe -m app.main run-final --allow-held-out --confirm --phases ii
..\.venv\Scripts\python.exe -m app.main run-final --allow-held-out --confirm --phases iii
..\.venv\Scripts\python.exe -m app.main study-stats --part held-out
..\.venv\Scripts\python.exe -m app.main export-paper-assets
```

The earlier ~18.5 h estimate was measured on m5-v3 / wave-c-v2; m5-v5 adds ATT&CK search to the single
arm, so take the per-case time from the m5-v5 pilot (`results/pilot_gate/finish.py`) before planning.

## 7. Troubleshooting

| symptom | cause / fix |
|---|---|
| `pilot-preflight`: inputs missing | run `ingest-alerts` for russellmitchell and shaw first |
| `pilot-preflight`: ATT&CK retrieval FAIL | `rag-index` (needs the bundle and the bge-small cache) |
| `pilot-preflight`: model not listed | `ollama list`; the name must match `SENTINEL_LLM_MODEL` |
| Investigate tab: 503 | the API was started without `SENTINEL_LLM_*` |
| Investigate tab: 429 | the help chat or another investigation holds the model; wait |
| login 429 | 5 failed logins for that user in 5 minutes; wait |
| ML line "no scores" | `ml-train`, then `ml-score` for that scenario on the store the API serves |
| "Why these alerts are together: not recorded" | incidents built before C6: run `triage` again |
| pytest fails with "a test wrote to data\platform" | a test called a CLI without `--data-dir tmp_path` (guard fixture) |
