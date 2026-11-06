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


import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
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
    return Services(Repository(db), index, objects, jwt_secret())


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
        return Principal(str(payload["sub"]), Role(payload["role"]))

    def need(permission: str) -> Callable[..., Principal]:
        def check(p: Annotated[Principal, Depends(principal)]) -> Principal:
            if not allowed(p.role, permission):
                repo.audit(p.username, p.role.value, "denied", permission, {})
                raise HTTPException(403, f"role {p.role.value} may not {permission}")
            return p
        return check

    app.state.need = need

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
