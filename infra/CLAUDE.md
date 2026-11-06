# infra/CLAUDE.md — local rules (root CLAUDE.md is the index)

- `docker-compose.yml` (repo root) has two profiles: `lite` = PostgreSQL 16 + pgvector; `full` = + Kafka (KRaft single node), OpenSearch 2.17 (heap 512 MB, security plugin off, bound to 127.0.0.1), MinIO, Prometheus, Grafana. Validate with `docker compose config` before committing. Report real memory use (`docker stats --no-stream`) in session notes; never estimates as measurements.
- Every port binds to 127.0.0.1. Every secret is `${VAR:?}` from a git-ignored `.env` (template: `.env.example`).
- `infra/postgres/init/01-roles.sh` runs once on an empty volume: pgvector extension, `sentinel_agent` role (SELECT on public tables, nothing on schema `truth`). Changing it needs `docker compose down -v`.
- Memory caps (`mem_limit`) keep `lite` small enough to sit next to the local LLM on a 16 GB laptop.
