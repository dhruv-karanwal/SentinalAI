"""FastAPI application: platform read API, writes with RBAC and audit.

(No ``from __future__ import annotations`` here: FastAPI must resolve the
``Annotated[..., Depends(closure)]`` hints at definition time.)

``create_app(services)`` takes the storage objects explicitly (tests pass
in-memory ones); ``services_from_env()`` builds them from the environment:

- ``SENTINEL_DB_URL``: PostgreSQL DSN; unset -> SQLite under
  ``SENTINEL_DATA_DIR`` (default ``data/platform``), core + truth files;
- ``SENTINEL_SEARCH_URL``: OpenSearch URL; unset -> SQLite FTS5 file;
- ``SENTINEL_OBJECTS``: ``minio`` (with ``SENTINEL_MINIO_*``) or a local folder.

No endpoint takes a filesystem path. No endpoint returns ground truth.
Every non-GET request writes ``audit_log`` (user, role, action, target).
"""


import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from app.api.auth import (
    AuthError,
    Role,
    allowed,
    decode_token,
    hash_password,
    issue_token,
    jwt_secret,
    verify_password,
)
from app.storage.db import PostgresDatabase, SqliteDatabase
from app.storage.objects import LocalObjectStore, MinioObjectStore, ObjectStore
from app.storage.repository import Repository
from app.storage.search import OpenSearchIndex, SearchIndex, SqliteFtsIndex

REPO_ROOT = Path(__file__).resolve().parents[3]


@dataclass
class Services:
    repo: Repository
    index: SearchIndex
    objects: ObjectStore
    secret: str
    extras: dict[str, Any] = field(default_factory=dict)


def services_from_env() -> Services:
    data_dir = Path(os.environ.get("SENTINEL_DATA_DIR", REPO_ROOT / "data" / "platform"))
    dsn = os.environ.get("SENTINEL_DB_URL")
    db = PostgresDatabase(dsn) if dsn else SqliteDatabase(data_dir / "core.db")
    db.migrate()
    search_url = os.environ.get("SENTINEL_SEARCH_URL")
    index: SearchIndex = OpenSearchIndex(search_url) if search_url else SqliteFtsIndex(data_dir / "search.db")
    objects: ObjectStore
    if os.environ.get("SENTINEL_OBJECTS") == "minio":
        objects = MinioObjectStore(os.environ["SENTINEL_MINIO_ENDPOINT"],
                                   os.environ["SENTINEL_MINIO_ACCESS_KEY"],
                                   os.environ["SENTINEL_MINIO_SECRET_KEY"])
    else:
        objects = LocalObjectStore(data_dir / "objects")
    services = Services(Repository(db), index, objects, jwt_secret())
    if os.environ.get("SENTINEL_LLM_BASE_URL") and os.environ.get("SENTINEL_LLM_MODEL"):
        from app.agent.client import OpenAICompatibleClient
        from app.agent.config import api_key, load_agent_settings

        settings = load_agent_settings()
        services.extras["copilot_client"] = OpenAICompatibleClient(settings.model,
                                                                   api_key=api_key(settings.model))
        base = (settings.model.base_url or "").rstrip("/")

        def _probe() -> bool:
            # GET {base}/models lists models without loading or running one (Ollama, llama.cpp, vLLM).
            import urllib.request

            try:
                with urllib.request.urlopen(base + "/models", timeout=2) as r:
                    return bool(200 <= r.status < 300)
            except OSError:
                return False

        services.extras["model_probe"] = _probe
    return services


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserBody(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.\-]+$")
    password: str = Field(min_length=8, max_length=256)
    role: Role


class FeedbackBody(BaseModel):
    target_type: str = Field(pattern=r"^(alert|incident|finding|report)$")
    target_id: str = Field(min_length=1, max_length=200)
    verdict: str = Field(pattern=r"^(true_positive|false_positive|unsure)$")
    notes: str | None = Field(default=None, max_length=4000)


class BuildBody(BaseModel):
    scenario: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_\-]+$")
    gap_seconds: int = Field(default=300, ge=1, le=86400)
    max_span_seconds: Optional[int] = Field(default=3600, ge=1, le=604800)


class ReportBody(BaseModel):
    incident_id: str = Field(min_length=1, max_length=200)


class ApprovalBody(BaseModel):
    incident_id: str = Field(min_length=1, max_length=200)
    action: dict[str, Any]


class DecisionBody(BaseModel):
    approved: bool
    reason: str = Field(min_length=1, max_length=2000)


class GlossaryEntry(BaseModel):
    term: str = Field(min_length=1, max_length=80)
    definition: str = Field(default="", max_length=600)
    why: str = Field(default="", max_length=600)


class CopilotBody(BaseModel):
    """``mode="investigate"`` (default): the M5 agent on one incident. ``mode="explain"``: one short
    grounded answer for the console's help chat (``app/api/explain.py``)."""
    mode: str = Field(default="investigate", pattern=r"^(investigate|explain)$")
    incident_id: Optional[str] = Field(default=None, min_length=1, max_length=200)
    question: str = Field(min_length=1, max_length=2000)
    screen: Optional[str] = Field(default=None, max_length=80)
    context: Optional[str] = Field(default=None, max_length=6000)
    glossary: list[GlossaryEntry] = Field(default_factory=list, max_length=12)


class StatusBody(BaseModel):
    status: str = Field(pattern=r"^(open|investigating|contained|closed)$")


@dataclass(frozen=True)
class Principal:
    username: str
    role: Role


_bearer = HTTPBearer(auto_error=False)


def create_app(services: Services, *, metrics: Any | None = None) -> FastAPI:
    app = FastAPI(title="SentinelAI API", version="0.1.0")
    app.state.services = services
    repo = services.repo

    def principal(creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)]) -> Principal:
        if creds is None:
            raise HTTPException(401, "missing bearer token")
        try:
            payload = decode_token(creds.credentials, services.secret)
        except AuthError as exc:
            raise HTTPException(401, str(exc)) from exc
        user = repo.get_user(str(payload["sub"]))
        if user is not None and user.get("disabled_utc"):
            raise HTTPException(401, "account deactivated")
        return Principal(str(payload["sub"]), Role(payload["role"]))

    def need(permission: str) -> Callable[..., Principal]:
        def check(p: Annotated[Principal, Depends(principal)]) -> Principal:
            if not allowed(p.role, permission):
                repo.audit(p.username, p.role.value, "denied", permission, {})
                raise HTTPException(403, f"role {p.role.value} may not {permission}")
            return p
        return check

    app.state.need = need
    # console v2 routes first: their fixed paths (/alerts/query, /incidents/summary) must win
    # over the /alerts/{alert_id} and /incidents/{incident_id} routes defined below
    from app.api.console import add_console_routes

    add_console_routes(app, repo, services.index, services.extras, need)

    @app.middleware("http")
    async def _timing(request: Request, call_next: Callable[..., Any]) -> Any:
        start = time.perf_counter()
        response = await call_next(request)
        if metrics is not None:
            metrics.observe_request(request.method, request.url.path, response.status_code,
                                    time.perf_counter() - start)
        return response

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "alerts": sum(repo.count_alerts().values()),
                "database": repo.db.dialect}

    @app.post("/auth/login")
    def login(body: LoginBody) -> dict[str, Any]:
        user = repo.get_user(body.username)
        if user is None or not verify_password(body.password, str(user["password_hash"])):
            repo.audit(body.username, "-", "login.failed", None, {})
            raise HTTPException(401, "invalid credentials")
        if user.get("disabled_utc"):
            repo.audit(body.username, "-", "login.refused", None, {"reason": "deactivated"})
            raise HTTPException(401, "account deactivated")
        role = Role(user["role"])
        repo.audit(body.username, role.value, "login", None, {})
        return {"access_token": issue_token(body.username, role, services.secret),
                "token_type": "bearer", "role": role.value}

    @app.get("/auth/me")
    def me(p: Annotated[Principal, Depends(need("read"))]) -> dict[str, Any]:
        return {"username": p.username, "role": p.role.value}

    @app.post("/users", status_code=201)
    def create_user(body: UserBody, p: Annotated[Principal, Depends(need("user.manage"))]) -> dict[str, str]:
        repo.put_user(body.username, hash_password(body.password), body.role.value)
        repo.audit(p.username, p.role.value, "user.create", body.username, {"role": body.role.value})
        return {"username": body.username, "role": body.role.value}

    @app.get("/scenarios")
    def list_scenarios(p: Annotated[Principal, Depends(need("read"))]) -> dict[str, Any]:
        return {"scenarios": repo.list_scenarios()}

    @app.get("/alerts")
    def list_alerts(p: Annotated[Principal, Depends(need("read"))], scenario: str | None = None,
                    detector: str | None = None, host_ip: str | None = None, since: str | None = None,
                    until: str | None = None, limit: Annotated[int, Query(ge=1, le=500)] = 100,
                    offset: Annotated[int, Query(ge=0)] = 0) -> dict[str, Any]:
        rows = repo.list_alerts(scenario=scenario, detector=detector, host_ip=host_ip, since=since,
                                until=until, limit=limit, offset=offset)
        if not allowed(p.role, "read.raw"):
            rows = [{k: v for k, v in r.items() if k != "record"} for r in rows]
        return {"alerts": rows, "count": len(rows), "offset": offset}

    @app.get("/alerts/search")
    def search_alerts(p: Annotated[Principal, Depends(need("read"))],
                      q: Annotated[str, Query(min_length=1, max_length=200)],
                      scenario: str | None = None,
                      limit: Annotated[int, Query(ge=1, le=200)] = 50) -> dict[str, Any]:
        return {"hits": services.index.search(q, scenario=scenario, limit=limit)}

    @app.get("/alerts/stats")
    def alert_stats(p: Annotated[Principal, Depends(need("read"))],
                    scenario: str | None = None) -> dict[str, Any]:
        return {"by_detector": repo.count_alerts(scenario)}

    @app.get("/alerts/{alert_id}")
    def get_alert(alert_id: str, p: Annotated[Principal, Depends(need("read.raw"))]) -> dict[str, Any]:
        row = repo.get_alert(alert_id)
        if row is None:
            raise HTTPException(404, "no such alert")
        return row

    @app.get("/cases")
    def list_cases(p: Annotated[Principal, Depends(need("read"))],
                   scenario: str | None = None) -> dict[str, Any]:
        return {"cases": repo.list_cases(scenario)}

    @app.get("/runs")
    def list_runs(p: Annotated[Principal, Depends(need("read"))]) -> dict[str, Any]:
        return {"runs": repo.list_runs()}

    @app.get("/runs/{run_id}")
    def get_run(run_id: str, p: Annotated[Principal, Depends(need("read.raw"))]) -> dict[str, Any]:
        run = repo.get_run(run_id)
        if run is None:
            raise HTTPException(404, "no such run")
        return run

    @app.get("/incidents")
    def list_incidents(p: Annotated[Principal, Depends(need("read"))], scenario: str | None = None,
                       severity: str | None = None) -> dict[str, Any]:
        return {"incidents": repo.list_incidents(scenario, severity)}

    @app.post("/incidents/build")
    def build_incidents(body: BuildBody,
                        p: Annotated[Principal, Depends(need("incident.build"))]) -> dict[str, Any]:
        """Triage + correlation (Wave B3) over the scenario's stored alerts; label-free."""
        from app.detection.triage import TriageConfig, build_and_store

        summary = build_and_store(repo, body.scenario, TriageConfig(gap_seconds=body.gap_seconds,
                                                                 max_span_seconds=body.max_span_seconds))
        repo.audit(p.username, p.role.value, "incident.build", body.scenario,
                   {"gap_seconds": body.gap_seconds, "incidents": summary["incidents"]})
        return summary

    @app.get("/incidents/{incident_id}")
    def get_incident(incident_id: str, p: Annotated[Principal, Depends(need("read"))]) -> dict[str, Any]:
        inc = repo.get_incident(incident_id)
        if inc is None:
            raise HTTPException(404, "no such incident")
        return inc

    @app.patch("/incidents/{incident_id}")
    def update_incident(incident_id: str, body: StatusBody,
                        p: Annotated[Principal, Depends(need("incident.update"))]) -> dict[str, Any]:
        if repo.get_incident(incident_id) is None:
            raise HTTPException(404, "no such incident")
        repo.set_incident_status(incident_id, body.status)
        repo.audit(p.username, p.role.value, "incident.update", incident_id, {"status": body.status})
        return {"incident_id": incident_id, "status": body.status}

    @app.get("/reports")
    def list_reports(p: Annotated[Principal, Depends(need("read"))],
                     incident_id: str | None = None) -> dict[str, Any]:
        return {"reports": repo.list_reports(incident_id)}

    @app.get("/reports/{report_id}")
    def get_report(report_id: str, p: Annotated[Principal, Depends(need("read"))]) -> dict[str, Any]:
        rep = repo.get_report(report_id)
        if rep is None:
            raise HTTPException(404, "no such report")
        return rep

    def _incident_alerts(incident: dict[str, Any]) -> list[Any]:
        return [a for a in (repo.alert_model(i) for i in incident["alert_ids"]) if a is not None]

    @app.post("/reports", status_code=201)
    def create_report(body: ReportBody,
                      p: Annotated[Principal, Depends(need("report.create"))]) -> dict[str, Any]:
        from app.outputs.reports import build_report, render_csv, render_pdf

        inc = repo.get_incident(body.incident_id)
        if inc is None:
            raise HTTPException(404, "no such incident")
        report = build_report(inc, _incident_alerts(inc))
        from app.outputs.analytics import fact_from_row, report_charts

        report["charts"] = report_charts(inc, sorted((fact_from_row(r) for r in repo.get_alerts(inc["alert_ids"])),
                                                     key=lambda f: (f.ts, f.alert_id)))
        rid = repo.put_report(body.incident_id, report)
        key = f"reports/{rid}"
        services.objects.put(f"{key}.pdf", render_pdf(report), "application/pdf")
        services.objects.put(f"{key}.csv", render_csv(report).encode("utf-8"), "text/csv")
        repo.db.execute("UPDATE reports SET object_key = ? WHERE report_id = ?", (key, rid))
        repo.audit(p.username, p.role.value, "report.create", rid, {"incident_id": body.incident_id})
        return {"report_id": rid, "incident_id": body.incident_id, "object_key": key,
                "formats": ["json", "pdf", "csv"]}

    @app.get("/reports/{report_id}/download")
    def download_report(report_id: str, p: Annotated[Principal, Depends(need("read"))],
                        format: Annotated[str, Query(pattern="^(json|pdf|csv)$")] = "json") -> Response:
        from app.outputs.reports import render_csv, render_pdf

        rep = repo.get_report(report_id)
        if rep is None:
            raise HTTPException(404, "no such report")
        if format == "json":
            return Response(json.dumps(rep["body"], indent=2), media_type="application/json")
        key = f"{rep['object_key']}.{format}" if rep.get("object_key") else None
        if key and services.objects.exists(key):
            data = services.objects.get(key)
        else:
            data = render_pdf(rep["body"]) if format == "pdf" else render_csv(rep["body"]).encode("utf-8")
        media = "application/pdf" if format == "pdf" else "text/csv"
        return Response(data, media_type=media, headers={
            "Content-Disposition": f'attachment; filename="{report_id}.{format}"'})

    @app.post("/approvals", status_code=201)
    def request_approval(body: ApprovalBody,
                         p: Annotated[Principal, Depends(need("approval.request"))]) -> dict[str, Any]:
        from app.outputs.approvals import ApprovalService

        try:
            aid = ApprovalService(repo).request(body.incident_id, body.action, p.username)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        repo.audit(p.username, p.role.value, "approval.request", f"approval:{aid}",
                   {"incident_id": body.incident_id, "action": body.action})
        return {"id": aid, "status": "pending"}

    @app.get("/approvals")
    def list_approvals(p: Annotated[Principal, Depends(need("read"))],
                       status: Annotated[str | None, Query(pattern="^(pending|approved|rejected)$")] = None
                       ) -> dict[str, Any]:
        return {"approvals": repo.list_approvals(status)}

    @app.post("/approvals/{approval_id}/decision")
    def decide_approval(approval_id: int, body: DecisionBody,
                        p: Annotated[Principal, Depends(need("approval.decide"))]) -> dict[str, Any]:
        from app.outputs.approvals import ApprovalError, ApprovalService

        try:
            ApprovalService(repo).decide(approval_id, body.approved, p.username, body.reason)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except (ApprovalError, ValueError) as exc:
            raise HTTPException(409, str(exc)) from exc
        status = "approved" if body.approved else "rejected"
        repo.audit(p.username, p.role.value, "approval.decide", f"approval:{approval_id}",
                   {"status": status, "reason": body.reason})
        return {"id": approval_id, "status": status}

    @app.post("/approvals/{approval_id}/execute")
    def execute_approval(approval_id: int,
                         p: Annotated[Principal, Depends(need("action.execute"))]) -> dict[str, Any]:
        from app.outputs.approvals import ApprovalError, ApprovalService

        try:
            result = ApprovalService(repo).execute(approval_id, p.username)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ApprovalError as exc:
            repo.audit(p.username, p.role.value, "action.execute.refused", f"approval:{approval_id}",
                       {"reason": str(exc)})
            raise HTTPException(409, str(exc)) from exc
        repo.audit(p.username, p.role.value, "action.execute", f"approval:{approval_id}",
                   {"mode": result["mode"], "action": result["action"]})
        return result

    def _explain(body: CopilotBody, p: Principal, client: Any) -> dict[str, Any]:
        from app.agent.client import ModelRequestError
        from app.api import explain as ex

        incident = None
        if body.incident_id is not None:
            inc = repo.get_incident(body.incident_id)
            if inc is None:
                raise HTTPException(404, "no such incident")
            incident = ex.incident_facts(inc)
        if client is None:
            raise HTTPException(503, "no model endpoint configured for the copilot")
        if not ex.MODEL_LOCK.acquire(blocking=False):
            raise HTTPException(429, "the local model is busy with another question; try again shortly")
        glossary = [g.model_dump() for g in body.glossary]
        try:
            result = client.chat(ex.build_messages(body.question, body.screen, body.context, glossary, incident),
                                 max_tokens=ex.MAX_OUTPUT_TOKENS, temperature=0.0)
        except ModelRequestError as exc:
            raise HTTPException(503, f"local model unreachable: {str(exc)[:200]}") from exc
        finally:
            ex.MODEL_LOCK.release()
        repo.audit(p.username, p.role.value, "copilot.explain", body.incident_id or body.screen,
                   {"output_tokens": result.output_tokens})
        return {"mode": "explain", "status": "ok", "answer": [result.content.strip()],
                "model": client.model_id, "sources": ex.sources(glossary, body.screen, body.context, incident),
                "input_tokens": result.input_tokens, "output_tokens": result.output_tokens,
                "note": "help answer from the glossary and the screen only; not a study result"}

    @app.get("/copilot/status")
    def copilot_status(_: Annotated[Principal, Depends(need("copilot.ask"))]) -> dict[str, Any]:
        """Is the help chat's model reachable? A cheap probe, never a chat request (no GPU load)."""
        from app.api import explain as ex

        client = services.extras.get("copilot_client")
        if client is None:
            return {"state": "offline", "model": None, "reason": "no model endpoint configured"}
        if ex.MODEL_LOCK.locked():
            return {"state": "busy", "model": client.model_id}
        probe = services.extras.get("model_probe")
        ok = bool(probe()) if probe is not None else True
        return {"state": "online" if ok else "offline", "model": client.model_id}

    @app.post("/copilot/ask")
    def copilot_ask(body: CopilotBody,
                    p: Annotated[Principal, Depends(need("copilot.ask"))]) -> dict[str, Any]:
        from app.agent.config import load_agent_settings
        from app.agent.copilot import ask

        client = services.extras.get("copilot_client")
        if body.mode == "explain":
            return _explain(body, p, client)
        if body.incident_id is None:
            raise HTTPException(422, "investigate mode needs an incident_id")
        if client is None:
            raise HTTPException(503, "no model endpoint configured for the copilot")
        inc = repo.get_incident(body.incident_id)
        if inc is None:
            raise HTTPException(404, "no such incident")
        settings = services.extras.get("copilot_settings") or load_agent_settings()
        try:
            answer = ask(client, _incident_alerts(inc), body.question, settings,
                         salt=f"copilot:{body.incident_id}:{body.question}")
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        repo.audit(p.username, p.role.value, "copilot.ask", body.incident_id,
                   {"status": answer["status"], "tool_calls": answer["tool_calls"]})
        return answer

    @app.post("/feedback", status_code=201)
    def add_feedback(body: FeedbackBody,
                     p: Annotated[Principal, Depends(need("feedback.create"))]) -> dict[str, Any]:
        fid = repo.add_feedback(body.target_type, body.target_id, body.verdict, body.notes, p.username)
        repo.audit(p.username, p.role.value, "feedback.create", f"{body.target_type}:{body.target_id}",
                   {"verdict": body.verdict})
        return {"id": fid}

    @app.get("/feedback")
    def list_feedback(p: Annotated[Principal, Depends(need("read"))]) -> dict[str, Any]:
        return {"feedback": repo.list_feedback()}

    @app.get("/audit")
    def audit(p: Annotated[Principal, Depends(need("audit.read"))],
              limit: Annotated[int, Query(ge=1, le=1000)] = 200) -> dict[str, Any]:
        return {"entries": repo.audit_entries(limit)}

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics_endpoint() -> str:
        return metrics.render() if metrics is not None else ""

    return app
