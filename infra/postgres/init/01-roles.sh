#!/bin/sh
# Runs once on first start. Creates the pgvector extension and the
# sentinel_agent role: it can read the core tables (public schema) and
# nothing in schema "truth" (ground truth). Agent tool paths connect with
# SET ROLE sentinel_agent. Password from the container environment.
set -e
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" <<SQL
CREATE EXTENSION IF NOT EXISTS vector;
CREATE ROLE sentinel_agent LOGIN PASSWORD '${SENTINEL_AGENT_PASSWORD}';
GRANT sentinel_agent TO ${POSTGRES_USER};
GRANT USAGE ON SCHEMA public TO sentinel_agent;
ALTER DEFAULT PRIVILEGES FOR ROLE ${POSTGRES_USER} IN SCHEMA public GRANT SELECT ON TABLES TO sentinel_agent;
CREATE SCHEMA IF NOT EXISTS truth AUTHORIZATION ${POSTGRES_USER};
REVOKE ALL ON SCHEMA truth FROM PUBLIC;
SQL
