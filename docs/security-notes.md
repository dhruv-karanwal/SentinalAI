# Security notes: SentinelAI (Wave D)

What the platform protects, how, and what it does **not** cover. SentinelAI is a
research demo that runs on one machine (localhost); it is not hardened for production.
The code is the source of truth: `backend/app/api/auth.py` (roles, permissions, JWT, bcrypt),
`backend/app/api/app.py` (routes), `backend/app/outputs/approvals.py` (approval gate).

## Covered

| Area | What is in place | Where |
|---|---|---|
| Authentication | Username + password (bcrypt hash), JWT HS256 bearer tokens that expire after 60 minutes. The signing secret comes only from `SENTINEL_JWT_SECRET` (at least 32 characters); there is no default secret. | `api/auth.py` |
| Authorisation | One permission table (`PERMISSIONS`) for four roles: analyst, manager, admin, executive. Executives can only read: they get no raw records, cannot write reports, request or decide approvals, run actions or use the copilot. Each permission row is tested (`test_rbac_matrix`, `tests/test_wave_d.py`). | `api/auth.py` |
| Audit | Every non-GET route writes `audit_log` (user, role, action, target, detail). Denied requests are audited as `denied`, and refused executions as `action.execute.refused`. Failed logins are audited too. | `api/app.py` |
| Approval gate | Only state-changing playbook actions (block source IP, isolate host, lock account, reset credentials) can be requested. A request is decided once, by someone other than the requester, and the decision needs a reason. **Nothing executes without an approved record**, and an approved record runs at most once. The executor is simulated: no firewall, EDR or directory connectors exist. | `outputs/approvals.py` |
| Secrets | Read only from the environment or a git-ignored `.env` (template: `.env.example`), never passed as CLI arguments or kept in files. LLM API keys are never written to manifests, errors or `repr`. A secret scan runs before every PR. | `agent/config.py`, `infra/CLAUDE.md` |
| Network exposure | The API binds to 127.0.0.1 by default (`serve --host` can change that; don't change it without TLS in front). Every docker-compose port binds to 127.0.0.1. OpenSearch's security plugin is off, which is acceptable only because it is localhost-bound. | `main.py serve`, `docker-compose.yml` |
| Ground-truth separation | Dataset labels live only in the truth area (`truth.db` / schema `truth`). Agent tool paths never import it; the API never returns `event_label` or `time_label`. The PostgreSQL `sentinel_agent` role has no rights on schema `truth`. Leak tests scan tool outputs, prompts, memory writes, reports and copilot answers. | `storage/`, `tests/test_platform_storage.py`, `tests/test_api.py` |
| LLM output handling | Agents see opaque alert ids, time offsets and `<TIME>` masks. Their citations and claims pass the evidence verifier before a report or copilot answer shows them. Agents have read-only tools: no tool can change state. | `agent/tools.py`, `agent/verifier.py` |
| Inputs | Pydantic models validate every request body. Path parameters are not filesystem paths. Object keys are checked (`check_key`). | `api/app.py`, `storage/objects.py` |
| Cost / abuse of the model | Per-case token and tool-call budgets with a hard stop; one repair retry. No paid API is configured. | `agent/agent.py`, `experiments/config/study.json` |

## Not covered

- **TLS**: the API speaks plain HTTP on localhost. Anything beyond one machine needs a reverse proxy with TLS.
- **Token revocation, refresh tokens, MFA, SSO**: none. A stolen token works until it expires (60 minutes).
- **Brute-force protection**: there is no login rate limiting or account lockout. Failed logins are audited, not blocked.
- **Prompt injection through log lines**: alert evidence (raw log lines an attacker can influence) reaches the model as data. The tools are read-only and the verifier drops unsupported claims, but a crafted log line could still steer a verdict or a summary. This is a known open risk, not a solved one.
- **Encryption at rest**: SQLite files, object storage and the PostgreSQL volume are unencrypted. Disk encryption is the host's job.
- **Audit log integrity**: the log is a normal table; an admin with database access can change it. There is no hash chain and no external sink.
- **Supply chain**: dependencies are pinned in `backend/requirements*.txt`, but there is no SBOM, vulnerability scan or signature check in CI. Model weights come from Ollama's registry and are not independently verified.
- **Real response actions**: the executor is simulated. Real connectors would need their own credentials, least-privilege design and a review.
- **Multi-tenancy, backups, high availability**: out of scope.
- **Jira / threat-intel feeds**: Jira, OTX, MISP and VirusTotal adapters are disabled stubs; no external service is contacted.

## Compliance (documentation only)

SentinelAI makes **no compliance claim** and has not been audited or certified. As
orientation only, the controls above map loosely to common framework areas: identity and
access control (roles, permissions, authentication); logging and monitoring (audit log,
Prometheus metrics); change control (approval gate, human in the loop); and data protection
(truth separation, secrets handling). A real deployment would need its own risk assessment
against the framework it must meet (for example ISO/IEC 27001 or NIST CSF) and would have to
close the gaps listed under *Not covered*.

Data: the AIT Alert Data Set (Zenodo 8263181) is CC BY 4.0. It is used for research with
attribution, and raw files are never committed. Analyst feedback is stored with usernames and
is visible to every authenticated role through `GET /feedback`.
