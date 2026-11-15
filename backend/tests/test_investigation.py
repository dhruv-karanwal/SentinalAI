"""C2 (2026-11-15): product investigations of an incident, single agent and LangGraph graph.

FakeClient only (no network, no model). The executor runs the job inline so each request is
complete when the POST returns; production uses a daemon thread.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.agent.client import FakeClient, ModelRequestError
from app.api.app import Services, create_app
from app.api.auth import Role
from app.api import explain as ex
from tests.test_api import PASSWORD, services, token  # noqa: F401  (fixtures)
from tests.test_variants import processed  # noqa: F401  (fixture)
from tests.test_wave_c_graph import note, route, tool
from tests.test_wave_d import LABEL_WORDS, stored_incident


def inline(job: Callable[[], None]) -> None:
    job()


def app_with(services: Services, replies: list[Any] | None,  # noqa: F811
             executor: Callable[[Callable[[], None]], None] = inline) -> TestClient:
    if replies is not None:
        services.extras["copilot_client"] = FakeClient(replies)
    services.extras["investigation_executor"] = executor
    return TestClient(create_app(services))


def first_listed(messages: list[dict[str, str]]) -> str:
    return str(json.loads(messages[-1]["content"].split("\n", 1)[1])["alerts"][0]["alert_id"])


def final_citing_first(messages: list[dict[str, str]]) -> str:
    aid = first_listed(messages)
    return json.dumps({"action": "final", "verdict": "attack", "findings": [
        {"summary": "the first alert shows the activity", "alert_ids": [aid, "al-not-real"],
         "claims": [{"alert_id": aid, "kind": "field_value", "field": "detector",
                     "value": "no-such-detector"}]}]})


def start(c: TestClient, workflow: str, role: Role = Role.ANALYST, incident: str = "inc-rep") -> Any:
    return c.post(f"/incidents/{incident}/investigations", headers=token(c, role),
                  json={"workflow": workflow})


def test_single_investigation_is_persisted_and_verified(services: Services) -> None:  # noqa: F811
    inc = stored_incident(services.repo)
    c = app_with(services, [tool("list_alerts"), final_citing_first])
    r = start(c, "single")
    assert r.status_code == 202, r.text
    inv_id = r.json()["investigation_id"]
    got = c.get(f"/investigations/{inv_id}", headers=token(c, Role.ANALYST)).json()
    assert got["status"] == "completed" and got["workflow"] == "single" and got["completed_utc"]
    res = got["result"]
    assert res["prompt_version"] == "m5-v5"
    assert res["conclusion"]["verified"] and res["conclusion"]["verdict"] == "attack"
    assert res["conclusion"]["cited_alert_ids"] and set(res["conclusion"]["cited_alert_ids"]) <= set(inc["alert_ids"])
    assert res["verification"]["citations_dropped"] == 1 and res["verification"]["claims_dropped"] == 1
    assert res["observed"] == []  # the planted claim was false
    assert res["hypotheses"][0]["status"] == "unverified model text"
    assert res["detections"][0]["alert_id"] == res["conclusion"]["cited_alert_ids"][0]
    assert res["recommendations"]  # playbook rows (fallback manual review when no technique)
    events = res["steps"][0]["events"]
    assert [e.get("tool") for e in events if e["type"] == "tool_result"] == ["list_alerts"]
    assert all(set(res["id_map"].values()) >= {i} for i in res["conclusion"]["cited_alert_ids"])
    text = json.dumps(got)
    assert "You are a security analyst" not in text  # no system prompt in the response
    for word in LABEL_WORDS:
        assert word not in text
    actions = [e["action"] for e in services.repo.audit_entries()]
    assert "investigation.start" in actions and "investigation.finish" in actions
    listed = c.get("/incidents/inc-rep/investigations", headers=token(c, Role.MANAGER)).json()
    assert [i["investigation_id"] for i in listed["investigations"]] == [inv_id]
    assert not ex.MODEL_LOCK.locked()


def test_graph_investigation_records_supervisor_agents_and_notes(services: Services) -> None:  # noqa: F811
    stored_incident(services.repo)

    def note_first(messages: list[dict[str, str]]) -> str:
        return note("first alert looks like a scan", [first_listed(messages)])

    def report(messages: list[dict[str, str]]) -> str:
        notes = json.loads(messages[-1]["content"].split("\n", 1)[1])["notes"]
        aid = notes[0]["alert_ids"][0]
        return json.dumps({"action": "final", "verdict": "attack",
                           "findings": [{"summary": "scan", "alert_ids": [aid], "claims": []}]})

    c = app_with(services, [route("log_analysis"), tool("list_alerts"), note_first,
                            route("report_generation"), tool("recall_notes"), report])
    inv_id = start(c, "graph").json()["investigation_id"]
    res = c.get(f"/investigations/{inv_id}", headers=token(c, Role.ANALYST)).json()["result"]
    assert res["prompt_version"] == "wave-c-v2" and res["status"] == "ok"
    assert res["trace"][:3] == ["supervisor", "log_analysis", "supervisor"]
    nodes = [s["node"] for s in res["steps"]]
    assert "log_analysis" in nodes and "report_generation" in nodes and "supervisor" in nodes
    routes = [e.get("agent") for s in res["steps"] for e in s["events"] if e.get("action") == "route"]
    assert routes == ["log_analysis", "report_generation"]
    assert res["notes"][0]["agent"] == "log_analysis"
    assert res["conclusion"]["verified"] and len(res["conclusion"]["cited_alert_ids"]) == 1
    assert res["knowledge"] == [] and res["retrieval"] is False


def test_retrieved_attack_knowledge_is_listed_with_its_source(services: Services) -> None:  # noqa: F811
    stored_incident(services.repo)

    class Retr:
        def search(self, text: str, k: int = 5) -> list[dict[str, Any]]:
            return [{"technique_id": "T1046", "name": "Network Service Discovery",
                     "tactics": ["discovery"], "score": 0.8, "text": "T1046 Network Service Discovery."}]

    services.extras["retriever"] = Retr()
    c = app_with(services, [tool("search_attack", text="port scan"), tool("list_alerts"),
                            final_citing_first])
    inv_id = start(c, "single").json()["investigation_id"]
    res = c.get(f"/investigations/{inv_id}", headers=token(c, Role.ANALYST)).json()["result"]
    assert res["retrieval"] is True
    assert res["knowledge"] == [{"technique_id": "T1046", "name": "Network Service Discovery",
                                 "tactics": ["discovery"], "excerpt": "T1046 Network Service Discovery.",
                                 "retrieved_by": ["single_agent"]}]


def test_malformed_output_fails_visibly(services: Services) -> None:  # noqa: F811
    stored_incident(services.repo)
    c = app_with(services, ["not json", "still not json"])
    got = c.get(f"/investigations/{start(c, 'single').json()['investigation_id']}",
                headers=token(c, Role.ANALYST)).json()
    assert got["status"] == "failed" and "unparseable" in got["error"]
    res = got["result"]
    assert res["conclusion"] == {"verdict": None, "verified": False, "cited_alert_ids": [],
                                 "note": res["conclusion"]["note"]}
    assert res["recommendations"] == [] and res["hypotheses"] == []


def test_unavailable_model_and_crash_are_recorded(services: Services) -> None:  # noqa: F811
    stored_incident(services.repo)
    c = app_with(services, [ModelRequestError("timed out after 120 s")])
    got = c.get(f"/investigations/{start(c, 'single').json()['investigation_id']}",
                headers=token(c, Role.ANALYST)).json()
    assert got["status"] == "failed" and "timed out" in got["error"]

    def boom(messages: list[dict[str, str]]) -> str:
        raise RuntimeError("worker crashed")

    c = app_with(services, [boom])
    got = c.get(f"/investigations/{start(c, 'graph').json()['investigation_id']}",
                headers=token(c, Role.ANALYST)).json()
    assert got["status"] == "failed" and got["result"] is None and "worker crashed" in got["error"]
    assert not ex.MODEL_LOCK.locked()


def test_errors_and_rbac(services: Services) -> None:  # noqa: F811
    stored_incident(services.repo)
    c = app_with(services, None)
    assert start(c, "graph").status_code == 503  # no model endpoint
    c = app_with(services, [final_citing_first])
    assert start(c, "graph", incident="inc-missing").status_code == 404
    assert start(c, "graph", incident="inc-1").status_code == 422  # incident without alerts
    assert c.post("/incidents/inc-rep/investigations", headers=token(c, Role.ANALYST),
                  json={"workflow": "shell"}).status_code == 422
    assert start(c, "graph", role=Role.EXECUTIVE).status_code == 403
    assert c.get("/incidents/inc-rep/investigations", headers=token(c, Role.EXECUTIVE)).status_code == 403
    assert c.get("/investigations/inv-nope", headers=token(c, Role.ANALYST)).status_code == 404


def test_one_running_investigation_per_incident_and_one_model_job(services: Services) -> None:  # noqa: F811
    stored_incident(services.repo)
    c = app_with(services, [tool("list_alerts"), final_citing_first])
    assert ex.MODEL_LOCK.acquire(blocking=False)  # e.g. a help-chat answer in progress
    try:
        assert start(c, "single").status_code == 429
    finally:
        ex.MODEL_LOCK.release()
    services.repo.start_investigation("inc-rep", "graph", "manager", "m")  # one already running
    assert start(c, "single").status_code == 409
    assert not ex.MODEL_LOCK.locked()  # the refused request gave the lock back


def test_restart_marks_running_rows_interrupted(services: Services) -> None:  # noqa: F811
    stored_incident(services.repo)
    inv = services.repo.start_investigation("inc-rep", "graph", "analyst", "m")
    TestClient(create_app(services))  # a new API process
    got = services.repo.get_investigation(inv)
    assert got is not None and got["status"] == "interrupted" and got["error"]


def test_injected_log_text_cannot_act(services: Services) -> None:  # noqa: F811
    """A log line that orders the model to approve an action changes nothing: the agent has only
    read-only tools, an unknown tool is an error, and approvals need a human decision."""
    inc = stored_incident(services.repo)

    def obey_injection(messages: list[dict[str, str]]) -> str:
        return tool("approve_action", approval_id=1)

    c = app_with(services, [obey_injection, tool("request_approval", action="isolate_host"),
                            tool("list_alerts"), final_citing_first])
    before = services.repo.list_approvals()
    res = c.get(f"/investigations/{start(c, 'single').json()['investigation_id']}",
                headers=token(c, Role.ANALYST)).json()["result"]
    errors = [e["text"] for e in res["steps"][0]["events"] if e["type"] == "tool_result"]
    assert len(errors) == 3 and all("unknown tool" in e for e in errors[:2])
    assert services.repo.list_approvals() == before
    assert inc["incident_id"] == "inc-rep"
