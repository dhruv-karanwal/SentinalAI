# DEMO.md — SentinelAI console, 7-minute demo

Windows, PowerShell, from the repository root (`D:\Projects\ERA`). Everything runs on this machine:
no internet, no paid API.

## What is loaded

- Data: the **UI-dev copy** of the stores, `data\processed\ui-dev\` (never `data\platform\`), so
  approvals, reports and audit rows made during the demo do not touch the study stores.
- Scenarios: **russellmitchell** (45,544 alerts, the default data source) and **shaw** (70,782).
  Both are AIT-ADS **dev** scenarios, replayed. Held-out scenarios are not loaded.
- Model: `sentinel-qwen2.5-7b-32k` on Ollama (qwen2.5:7b-instruct with a 32k context), local.

## Accounts

| Username | Role | Use in the demo |
|---|---|---|
| `ui-admin` | admin | **demo account**: sees every screen |
| `ui-manager` | manager | decides approvals (four-eyes: not the requester) |
| `ui-analyst` | analyst | triage, ask, request actions |
| `ui-exec` | executive | read-only |

All four share one password: `SENTINEL_UI_DEV_PASSWORD` in the git-ignored `.env.ui-dev` at the repo
root (with `SENTINEL_JWT_SECRET`). Open that file to read it; it is never printed or committed. A page
reload signs you out (the token is kept in memory only).

## 0. Before the demo (5 minutes)

Close anything already on ports 8000 and 5173 (an earlier API or `npm run dev`).

**Ollama.** The Ollama tray app normally starts it at sign-in. Check and pre-warm the model with one
short call, kept loaded for 60 minutes (the first call after a cold start takes ~10 s):

```powershell
& "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe" list
& "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe" run sentinel-qwen2.5-7b-32k "Reply with OK." --keepalive 60m
```

If `list` fails with a connection error, start the server in its own window and repeat:

```powershell
Start-Process "$env:LOCALAPPDATA\Programs\Ollama\ollama app.exe"
```

**Terminal 1, API** (127.0.0.1:8000; reads `.env.ui-dev`, serves the UI-dev copy, points the copilot
at the local model):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .claude\serve-api.ps1
```

**Terminal 2, console** (http://127.0.0.1:5173, proxies `/api` to the API):

```powershell
npm --prefix frontend run dev
```

Open http://127.0.0.1:5173 in the browser, sign in as `ui-admin`, and open Overview once: the first
call after an API start builds the alert index (2-5 s); afterwards pages are instant. Check the chat
button (bottom right) shows a green dot: hover or open it, it should say "Local model online".

## 1. Demo path (7 minutes)

| Min | Screen | What to show and say |
|---|---|---|
| 0:00 | **About** (rail: Understand > About) | One sentence: replayed alerts go through detection, triage, an AI investigation that must cite evidence, an evidence verifier, and a human approval. "How it works": click a stage. The study diagram: same agent, different alert sources. |
| 1:00 | **Overview** | KPI row (open incidents by severity, 45,544 alerts, oldest unopened High, waiting approvals). Alerts over time by detector: the 11k spike on 2022-01-24 is one burst. "Incidents to look at first". |
| 2:00 | **Incidents** | Top row: **High, 140 alerts**, last seen 2022-01-24T10:21:50Z (`inc-3ce9cb2540cf1ee3d7fa355c`, host 172.19.130.4). Read the "What happened" sentence (built from data, not by the AI) and "Why this severity: triage rule H2". Scroll to the time strip and the tabs: Alerts and evidence (select a row: raw log lines), ATT&CK, Graph. |
| 3:30 | **Help chat** (round button, bottom right) | Type **what is rule H2?**. The answer comes from the local model, grounded in the glossary (offline it answers from the glossary and says so). ~5-10 s. |
| 4:30 | **Approvals** | The queue and the rules above the controls: only state-changing playbook actions, the requester cannot decide, a reason is required, execution once, executor simulated. The one row (`lock_account` on 172.19.130.4, from the 140-alert incident) shows the whole trail: requested by ui-analyst, approved by ui-manager with a reason, executed (simulated). |
| 5:15 | **Reports** | Open the report of the 140-alert incident (Incident column ends `…d7fa355c`). Preview tab: executive summary, timeline, techniques. Click **PDF**: the file downloads with the charts. |
| 6:00 | **Study** | Banner: dev scenarios, pilot numbers, not paper results. Pilot tab: "Pilot runs on the dev scenarios: not final results", prompt revision `m5-v3+wave-c-v2` (latest; 12 earlier-revision runs hidden, switchable). Coverage per source and arm, before and after the verifier. Say: the pilot gate failed one cell, so the held-out study has not run; no number here is a final result. |

## 2. If something goes wrong

- **Blank page or "signed out"**: a reload signs out; sign in again.
- **Overview spins for a few seconds**: first call after an API start builds the index; wait.
- **Chat dot grey / "glossary answers only"**: Ollama is not reachable. Run the `list` and `run ... --keepalive 60m` commands above; the chat probes again when reopened. The glossary answer to "what is rule H2?" is still correct.
- **Chat says busy (429)**: one model request at a time; wait for the previous answer.
- **Port already in use**: an earlier API or Vite is still running; close its terminal window.
- **Stop everything**: Ctrl+C in both terminals. Ollama can keep running.

## 3. What not to do during the demo

- Do not run `run-pilot`, `run-matched`, `run-final` or `platform-ingest`: no study runs, no held-out data.
- Do not point `SENTINEL_DATA_DIR` at `data\platform\`.
