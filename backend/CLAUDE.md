# backend/CLAUDE.md — local rules (root CLAUDE.md is the index)

- Run everything from `backend/` with `../.venv/Scripts/python.exe`; `pytest` and `mypy` (strict over `app/`) must both be clean before a commit.
- Packages: `app/storage` (db.py: SQLite | PostgreSQL behind `Database`, templated migrations in `migrations/<area>/NNNN_*.sql`; repository.py: `Repository` core area, `AlertReader` for agent tools, `TruthStore` truth area; search.py: FTS5 | OpenSearch; objects.py: local | MinIO), `app/platform` (stream, collectors, enrichment, consumer, bootstrap), `app/api` (auth.py roles/permissions, app.py routes, server.py entry), `app/ops` (metrics), `app/intel` (attack.py: `AttackKB` + `map_alert`; ioc.py: `IocStore` + disabled feed stubs).
- **Truth separation:** labels live only in the truth area (`truth.db` / schema `truth`). Modules on agent tool paths (`TOOL_PATH_MODULES` in tests/test_platform_storage.py) must never mention `TruthStore` or `ground_truth`; the API never returns `time_label`/`event_label` (tests/test_api.py).
- **Migrations are append-only:** never edit an applied file (sha256 check raises `MigrationError`); add `NNNN+1_*.sql`. Placeholders: `{{ID}} {{JSON}} {{TS}} {{S}}`. Queries use `?`.
- **API:** no `from __future__ import annotations` in `app/api/app.py` (FastAPI resolves closure dependencies). Every non-GET endpoint calls `repo.audit(...)`; denied requests are audited as `denied`. New permissions go in `PERMISSIONS` (auth.py) with a row in `test_rbac_matrix`.
- Console v2 (`app/api/console.py`, added in `create_app` before the `{id}` routes): overview, alerts
  query / facets / CSV export, incident summary / analysis / node alerts, entities, search, executive,
  study results, users admin. Aggregates live in `app/outputs/analytics.py` (label-free, in `LABEL_FREE`);
  ATT&CK ids of stored records via `intel.attack.technique_ids` (same rules as `map_alert`). Users:
  migration `0003_user_disabled.sql`; create / reset take the password only from
  `SENTINEL_NEW_USER_PASSWORD` (409 when unset); deactivated users get 401 at login and on every token.
  Reports are `d2`: the API adds `charts` (timeline bins + placed entity graph) and the PDF draws them.
- Console support: `GET /scenarios` (`Repository.list_scenarios`, permission `read`); the copilot answer carries `claims`, `dropped_citations`, `dropped_claims` (real alert ids, never labels) next to the counts.
- Secrets only from the environment: `SENTINEL_JWT_SECRET` (>= 32 chars), `SENTINEL_NEW_USER_PASSWORD` for `create-user`, DB/MinIO credentials. Never as CLI arguments, never in files.
- Consumer writes in transactions of 1000 (`batch_size`); SQLite runs WAL. A per-row transaction makes a dev replay take >10 minutes.
- Infra tests: `tests/test_infra_integration.py`, marker `infra`, skip unless `SENTINEL_TEST_*` URLs are set and the port answers.
- **ATT&CK mapping is deterministic:** Wazuh native `rule.mitre.id` first, then `RULE_TABLE` rows in `intel/attack.py` (each a documented choice); anything else stays unmapped. No LLM, no keyword guessing. Adding a row needs a comment saying why the technique is unambiguous and a test.
- **Feed adapters stay disabled** (OTX, MISP, VirusTotal need API keys; not approved). Their `offline_sample()` is SYNTHETIC (TEST-NET / `.example` values) and must stay labelled so.
- `app/detection` (Wave B): `sigma_engine.py` (label-free; log-type parsers + condition evaluator; skip reasons counted, mapping table in the docstring), `sigma_report.py`, `labels.py`. **Labels reach the detection layer only through `labels.dev_labels`** (truth area, `require_dev` first); `tests/test_detection_labels.py` lists the modules allowed to import it (`LABEL_READERS`) and the ones that must not mention labels at all (`LABEL_FREE`). Keep both lists current when adding modules.
- Triage (`detection/triage.py`) is label-free and must stay so (it is in `LABEL_FREE`); the descriptive phase-overlap check lives in `triage_report.py` and runs only from the CLI after incidents are built. `Repository.iter_alert_models(scenario)` pages stored alerts (5000 per query).
- Sigma alerts: detector `sigma`, id `sigma-` + sha256(rule id, source alert id)[:32], `severity=None` (Sigma levels are words; never mapped), level/tags in `raw_alert["sigma"]`. They are an extra source, never a study variable.
- Python edit scripts on Windows: `Path.write_text` writes CRLF; the repo has `core.autocrlf=true`, so that is harmless, but never embed `\n` escapes in a bash heredoc that feeds Python (they turn into real newlines). Write the script with the Write tool.
- Wave D: `app/outputs/` (reports, playbooks, approvals, feedback_report, jira) and `agent/copilot.py`
  (in `TOOL_PATH_MODULES`). Routes: `POST /reports`, `GET /reports/{id}/download?format=json|pdf|csv`,
  `POST /approvals`, `GET /approvals`, `POST /approvals/{id}/decision`, `POST /approvals/{id}/execute`,
  `POST /copilot/ask` (503 without `services.extras["copilot_client"]`; set from SENTINEL_LLM_* in
  `services_from_env`). PDFs and CSVs go to the object store under `reports/<report_id>.{pdf,csv}`.
  mypy ignores missing reportlab stubs only.
- Wave C: `app/rag/` (no labels anywhere; KB content only), `agent/{rag_tool,verifier,multi_tools,graph,matched}.py`, CLI in `app/cli_wave_c.py` (main.py only registers it). Every agent test uses FakeClient; `pilot-estimate` and `run-matched --dry-run` never call a model. Real matched runs need the user's explicit approval for that run (model download and endpoint).
