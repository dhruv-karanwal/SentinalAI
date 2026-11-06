# backend/CLAUDE.md — local rules (root CLAUDE.md is the index)

- Run everything from `backend/` with `../.venv/Scripts/python.exe`; `pytest` and `mypy` (strict over `app/`) must both be clean before a commit.
- Packages: `app/storage` (db.py: SQLite | PostgreSQL behind `Database`, templated migrations in `migrations/<area>/NNNN_*.sql`; repository.py: `Repository` core area, `AlertReader` for agent tools, `TruthStore` truth area; search.py: FTS5 | OpenSearch; objects.py: local | MinIO), `app/platform` (stream, collectors, enrichment, consumer, bootstrap), `app/api` (auth.py roles/permissions, app.py routes, server.py entry), `app/ops` (metrics).
- **Truth separation:** labels live only in the truth area (`truth.db` / schema `truth`). Modules on agent tool paths (`TOOL_PATH_MODULES` in tests/test_platform_storage.py) must never mention `TruthStore` or `ground_truth`; the API never returns `time_label`/`event_label` (tests/test_api.py).
- **Migrations are append-only:** never edit an applied file (sha256 check raises `MigrationError`); add `NNNN+1_*.sql`. Placeholders: `{{ID}} {{JSON}} {{TS}} {{S}}`. Queries use `?`.
- **API:** no `from __future__ import annotations` in `app/api/app.py` (FastAPI resolves closure dependencies). Every non-GET endpoint calls `repo.audit(...)`; denied requests are audited as `denied`. New permissions go in `PERMISSIONS` (auth.py) with a row in `test_rbac_matrix`.
- Secrets only from the environment: `SENTINEL_JWT_SECRET` (>= 32 chars), `SENTINEL_NEW_USER_PASSWORD` for `create-user`, DB/MinIO credentials. Never as CLI arguments, never in files.
- Consumer writes in transactions of 1000 (`batch_size`); SQLite runs WAL. A per-row transaction makes a dev replay take >10 minutes.
- Infra tests: `tests/test_infra_integration.py`, marker `infra`, skip unless `SENTINEL_TEST_*` URLs are set and the port answers.
