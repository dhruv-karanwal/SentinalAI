"""Investigation routes (C2, 2026-11-15): start and read single-agent or graph investigations.

(No ``from __future__ import annotations``: FastAPI resolves the ``Depends`` closures.)

- ``POST /incidents/{incident_id}/investigations`` ``{"workflow": "single" | "graph"}`` -> 202
  ``{"investigation_id", "status": "running"}``. Permission ``investigation.run``. 404 unknown
  incident, 422 no stored alerts, 503 no model endpoint, 409 one already running for the incident,
  429 the local model is busy (the same ``MODEL_LOCK`` as the help chat: one model job at a time).
- ``GET /investigations/{id}`` and ``GET /incidents/{incident_id}/investigations``: permission
  ``read.raw`` (results quote raw log lines, which executives do not see).

The run happens on a worker (``services.extras["investigation_executor"]``, default a daemon
thread; tests pass an inline executor). The row is written ``running`` first, then
``completed`` / ``failed`` with the result; an API restart marks leftover ``running`` rows
``interrupted``. Budgets come from study.json; the model client has its own request timeout, so
a run always ends. Start and finish are audited. Responses never carry system prompts or secrets.
"""

import threading
from collections.abc import Callable
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field


class InvestigationBody(BaseModel):
    workflow: str = Field(default="graph", pattern=r"^(single|graph)$")


def _thread(job: Callable[[], None]) -> None:
    threading.Thread(target=job, name="investigation", daemon=True).start()


def add_investigation_routes(app: FastAPI, services: Any, need: Callable[..., Any]) -> None:
    repo = services.repo
    repo.interrupt_running_investigations()

    @app.post("/incidents/{incident_id}/investigations", status_code=202)
    def start_investigation(incident_id: str, body: InvestigationBody,
                            p: Annotated[Any, Depends(need("investigation.run"))]) -> dict[str, Any]:
        from app.agent.config import load_agent_settings
        from app.agent.investigation import run_investigation
        from app.api import explain as ex

        inc = repo.get_incident(incident_id)
        if inc is None:
            raise HTTPException(404, "no such incident")
        alerts = [a for a in (repo.alert_model(i) for i in inc["alert_ids"]) if a is not None]
        if not alerts:
            raise HTTPException(422, "the incident has no stored alerts")
        client = services.extras.get("copilot_client")
        if client is None:
            raise HTTPException(503, "no model endpoint configured (SENTINEL_LLM_BASE_URL / "
                                     "SENTINEL_LLM_MODEL)")
        if not ex.MODEL_LOCK.acquire(blocking=False):
            raise HTTPException(429, "the local model is busy; try again when it is free")
        try:
            inv_id = repo.start_investigation(incident_id, body.workflow, p.username, client.model_id)
        except ValueError as exc:
            ex.MODEL_LOCK.release()
            raise HTTPException(409, str(exc)) from exc
        repo.audit(p.username, p.role.value, "investigation.start", inv_id,
                   {"incident_id": incident_id, "workflow": body.workflow, "alerts": len(alerts)})
        settings = services.extras.get("copilot_settings") or load_agent_settings()
        retriever = services.extras.get("retriever")

        def job() -> None:
            try:
                result = run_investigation(client, alerts, settings, workflow=body.workflow,
                                           salt=inv_id, retriever=retriever)
                status = "completed" if result["status"] == "ok" else "failed"
                repo.finish_investigation(inv_id, status, result,
                                          None if status == "completed" else result.get("error"))
            except Exception as exc:  # recorded, never silent: the row must leave 'running'
                status = "failed"
                repo.finish_investigation(inv_id, status, None, f"{type(exc).__name__}: {exc}")
            finally:
                ex.MODEL_LOCK.release()
            repo.audit(p.username, p.role.value, "investigation.finish", inv_id,
                       {"incident_id": incident_id, "status": status})

        executor = services.extras.get("investigation_executor") or _thread
        try:
            executor(job)
        except Exception as exc:
            ex.MODEL_LOCK.release()
            repo.finish_investigation(inv_id, "failed", None, f"could not start: {exc}")
            raise HTTPException(500, "could not start the investigation") from exc
        return {"investigation_id": inv_id, "status": "running", "workflow": body.workflow}

    @app.get("/incidents/{incident_id}/investigations")
    def list_investigations(incident_id: str,
                            _: Annotated[Any, Depends(need("read.raw"))]) -> dict[str, Any]:
        return {"investigations": repo.list_investigations(incident_id)}

    @app.get("/investigations/{investigation_id}")
    def get_investigation(investigation_id: str,
                          _: Annotated[Any, Depends(need("read.raw"))]) -> dict[str, Any]:
        inv = repo.get_investigation(investigation_id)
        if inv is None:
            raise HTTPException(404, "no such investigation")
        return dict(inv)
