# SentinelAI — Autonomous AI-Powered Security Operations Center

SentinelAI is a research platform for AI-assisted security investigation.
It replays real IDS alert data (AIT-ADS: Wazuh, Suricata, AMiner), groups
alerts into incidents, maps them to MITRE ATT&CK, lets a single LLM agent or
a multi-agent graph investigate each case, checks every claim with an
evidence verifier, and puts the result in front of an analyst in a web
console with reports and a four-eyes approval workflow.

On top of the platform sits a **detector-conditioned study**: the same cases
are investigated under different alert sources (each detector, fused,
oracle, noise controls) and scored against deterministic baselines, with no
LLM judge.

![Overview screen (dark)](docs/ui/wave-f/overview-dark.png)

## Status

| Part | State |
|------|-------|
| Data foundation (CSV/JSON/JSONL loaders, canonical schema, quality report) | Done |
| Study foundation (metrics, AIT-ADS loader, alert-source variants, frozen dev/held-out split, cases, baselines) | Done |
| Wave A: platform (replay, stream, SQLite/PostgreSQL, search, objects, FastAPI + JWT + RBAC + audit, Prometheus) | Done |
| Wave B: detection (ATT&CK mapping, IOC store, Sigma engine, triage/correlation, ML baselines) | Done |
| Wave C: investigation (ATT&CK RAG, verifier, LangGraph supervisor with six agents, matched-budget runner) | Code done; real pilot not run yet |
| Wave D: outputs (reports JSON/CSV/PDF, approvals, feedback, copilot, React console) | Done |
| Waves E-UI / F-UI: explainable console, motion console, help chat | Done |
| Final runs tooling (statistics, protocol freeze, held-out plan, paper assets) | Done; held-out runs not done yet |

The local model is `qwen2.5:7b-instruct` on Ollama (`sentinel-qwen2.5-7b-32k`,
num_ctx 32768). No paid API is used. **No study numbers are reported here:**
results appear only after real runs, in `results/`, exported from run files.

Day-by-day progress is in [PROGRESS.md](PROGRESS.md); design decisions and
measured numbers are in [docs/session-notes.md](docs/session-notes.md).

## Architecture

```text
AIT-ADS files ─► replay collector ─► stream (in-memory | Kafka) ─► enrichment ─► storage
                                                                   (SQLite | PostgreSQL, search, objects)
                                                                              │
     ┌────────────────────────────────────────────────────────────────────────┘
     ▼
detection layer: ATT&CK mapping · IOC match · Sigma · ML baselines
     ▼
triage: dedup → entities → union-find grouping (gap 300 s, span cap 3600 s) → incidents
     ▼
investigation: single agent | multi-agent graph  ◄── ATT&CK RAG (bge-small + BM25 hybrid)
     ▼
evidence verifier (drops unsupported citations and claims)
     ▼
reports (JSON/CSV/PDF) · approvals (four-eyes, simulated executor) · console · copilot
```

Ground truth lives in a separate truth area and never reaches the agent
tools; leak tests scan every tool output. See
[docs/architecture.md](docs/architecture.md) and
[docs/research-methodology.md](docs/research-methodology.md).

## The analyst console

React 19 + TypeScript + Vite, plain CSS tokens, own SVG charts (no UI kit).
Design authority: [frontend/DESIGN.md](frontend/DESIGN.md). The screenshots
below use the dev scenario `russellmitchell` (dataset replay, demo data).
They were taken before the Wave G palette change, so colours differ slightly
from the current branch.

### Sign in and About

| | |
|---|---|
| ![Sign in, dark](docs/ui/login-dark.png) | ![Sign in, light](docs/ui/login-light.png) |
| ![About scroll story, hero](docs/ui/wave-f/about-dark-hero.png) | ![About, light](docs/ui/wave-f/about-light-hero.png) |
| ![About, the screens](docs/ui/wave-f/about-dark-screens.png) | ![About, the study diagram](docs/ui/wave-f/about-dark-study.png) |
| ![About, verifier demo on a labelled sample](docs/ui/wave-f/about-dark-verify.png) | ![About, reduced motion](docs/ui/wave-f/about-light-reduced.png) |
| ![About (Wave E), dark](docs/ui/about-dark.png) | ![About (Wave E), light](docs/ui/about-light.png) |

### Overview

| | |
|---|---|
| ![Overview, dark](docs/ui/wave-f/overview-dark.png) | ![Overview, light](docs/ui/wave-f/overview-light.png) |
| ![Overview (Wave E), dark](docs/ui/overview-dark.png) | ![Overview (Wave E), light](docs/ui/overview-light.png) |
| ![Guided tour on Overview](docs/ui/tour-overview-dark.png) | ![Glossary term tooltip](docs/ui/term-tooltip-dark.png) |

### Incidents

| | |
|---|---|
| ![Incidents, dark](docs/ui/incidents-dark.png) | ![Incidents, light](docs/ui/incidents-light.png) |
| ![Largest incident (11,208 alerts), dark](docs/ui/wave-f/incidents-dark-11208.png) | ![Largest incident, light](docs/ui/wave-f/incidents-light-11208.png) |
| ![Entity graph, dark](docs/ui/incident-graph-dark.png) | ![Entity graph, light](docs/ui/incident-graph-light.png) |
| ![Dense entity graph](docs/ui/incident-graph-dense-dark.png) | |

### Alerts

| | |
|---|---|
| ![Alerts, dark](docs/ui/wave-f/alerts-dark.png) | ![Alerts, light](docs/ui/wave-f/alerts-light.png) |
| ![Alerts (Wave E), dark](docs/ui/alerts-dark.png) | ![Alerts (Wave E), light](docs/ui/alerts-light.png) |
| ![Folded alert repeats, expanded](docs/ui/alerts-expanded-dark.png) | |

### Reports, approvals, executive

| | |
|---|---|
| ![Report preview, dark](docs/ui/report-preview-dark.png) | ![Report preview, light](docs/ui/report-preview-light.png) |
| ![Approvals, dark](docs/ui/approvals-dark.png) | ![Approvals, light](docs/ui/approvals-light.png) |
| ![Executive, dark](docs/ui/executive-dark.png) | ![Executive, light](docs/ui/executive-light.png) |

### Study and settings

The Study page shows only results files of real (non-fake) runs; it stays
empty until a real pilot run exists.

| | |
|---|---|
| ![Study, dark](docs/ui/wave-f/study-dark.png) | ![Study, light](docs/ui/wave-f/study-light.png) |
| ![Study (Wave E), dark](docs/ui/study-dark.png) | ![Study (Wave E), light](docs/ui/study-light.png) |
| ![Settings](docs/ui/settings-dark.png) | |

### Help chat

The floating help chat answers from the glossary and the current screen
through `POST /copilot/ask` (`mode: "explain"`), and falls back to the
glossary when the model is offline.

| | |
|---|---|
| ![Help chat with a local model answer](docs/ui/wave-f/chat-real-answer-dark.png) | ![Help chat open, light](docs/ui/wave-f/chat-open-light.png) |
| ![Help chat open, dark](docs/ui/wave-f/chat-open-dark.png) | ![Help chat minimised](docs/ui/wave-f/chat-minimised-light.png) |
| ![Help chat, model offline](docs/ui/chat-offline-dark.png) | ![Help chat, mocked online answer](docs/ui/chat-online-mock-light.png) |
| ![Help chat as a bottom sheet on a phone](docs/ui/wave-f/chat-mobile-sheet.png) | |

## Quick start

Prerequisites: Python 3.11+, Node 20+ (for the console). Docker is optional
(PostgreSQL/pgvector, OpenSearch, Kafka, MinIO, Grafana); every service has
an in-process fallback.

```bash
python -m venv .venv
pip install -r backend/requirements-dev.txt
```

Tests and type checks (synthetic data, no network):

```bash
cd backend
../.venv/Scripts/python.exe -m pytest
../.venv/Scripts/python.exe -m mypy
```

The real AIT-ADS files go in `data/raw/ait_ads/` (git-ignored, never
downloaded automatically; layout in [CLAUDE.md](CLAUDE.md)). Then, from
`backend/`:

```bash
../.venv/Scripts/python.exe -m app.main ingest-alerts --data-dir ../data/raw/ait_ads --scenario russellmitchell
../.venv/Scripts/python.exe -m app.main platform-ingest --scenario russellmitchell
../.venv/Scripts/python.exe -m app.main triage --scenario russellmitchell --gap-seconds 300
```

Create a user (password only from `SENTINEL_NEW_USER_PASSWORD`) and start the
API (needs `SENTINEL_JWT_SECRET`):

```bash
../.venv/Scripts/python.exe -m app.main create-user --username alice --role analyst
../.venv/Scripts/python.exe -m app.main serve
```

Console, from `frontend/` (127.0.0.1:5173, proxies `/api` to 127.0.0.1:8000):

```bash
npm install
npm run dev
```

Optional infrastructure: copy `.env.example` to `.env`, fill it, then
`docker compose --profile lite up -d` (or `--profile full`). See
[infra/CLAUDE.md](infra/CLAUDE.md).

The full command list (variants, cases, Sigma, ML baselines, RAG index and
evaluation, matched-budget pilot, protocol freeze, final runs, paper assets)
is in [CLAUDE.md](CLAUDE.md#commands).

## Study design in short

- **Data:** AIT-ADS. Frozen split: dev = russellmitchell, shaw; held-out =
  fox, harrison, santos, wardbeck, wheeler, wilson. Held-out scenarios are
  reachable only with a protocol-freeze permit.
- **Unit:** a case = one attack phase window or a matched benign window,
  capped at 100 alerts.
- **Variants:** wazuh, suricata, aminer, fused, oracle, and count-matched
  noise controls.
- **Headline metric:** event-label coverage of the alert-reachable attack
  phases; time coverage, citation precision and unsupported-claim rate next
  to it. Scored from ids and field values only (no LLM judge).
- **Comparison:** single agent vs multi-agent graph on the same cases under
  the same budgets, each before and after the verifier, next to
  deterministic baselines (cite-all, cite-none, top-k rules).
- **Statistics:** paired bootstrap with Holm correction.

## Repository layout

```text
backend/app/     CLI, ingestion, schemas, study, agent, rag, detection, platform, storage, api, outputs, ops
backend/tests/   pytest suite (synthetic data; real-data tests skip when files are absent)
frontend/        analyst console (DESIGN.md, src/, scripts/shots.mjs for screenshots)
experiments/     study.json (frozen split, seeds, budgets), statistics and final-study plans, RAG relevance set
data/samples/    committed SYNTHETIC samples
docs/            architecture, methodology, session notes, security notes, ui/ screenshots
infra/           docker-compose profiles, Postgres init, Prometheus, Grafana
```

## Research integrity

Numbers are only ever taken from real command output. Synthetic files are
named `synthetic_*` and never presented as real data. Runs with the scripted
`FakeClient` are plumbing checks, not results. Datasets, secrets and run
logs are git-ignored.
