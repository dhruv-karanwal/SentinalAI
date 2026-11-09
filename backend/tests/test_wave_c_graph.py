"""Wave C (C2): evidence verifier, LangGraph supervisor graph, matched-budget runner.

No network and no model: every agent test uses FakeClient. The RAG pieces
(``HashEmbedder`` test double, ``kb`` / ``retriever`` fixtures) come from
tests/test_rag.py.
"""

from __future__ import annotations

import dataclasses
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from app.agent.client import FakeClient
from app.agent.config import AgentConfig, load_agent_settings
from app.agent.graph import (
    AGENT_TOOLS,
    AGENTS,
    GRAPH_EDGES,
    PROMPTS,
    GraphSettings,
    parse_graph_reply,
    run_graph,
)
from app.agent.multi_tools import CaseMemory, MultiAgentToolkit, session_id_for
from app.agent.protocol import ProtocolError
from app.agent.rag_tool import AttackSearchTool
from app.agent.tools import CaseToolkit
from app.agent.verifier import verify_answer
from app.evaluation.metrics import Claim
from app.intel.attack import AttackKB
from app.rag.chunks import attack_chunks
from app.rag.retriever import AttackRetriever
from app.rag.vector_store import SqliteVectorStore
from app.storage.db import SqliteDatabase
from app.storage.repository import Repository
from app.study.variants import AlertPool
from tests.test_agent_tools import WINDOW_START, alerts, forbidden_tokens
from tests.test_rag import HashEmbedder, kb, retriever  # noqa: F401  (fixtures)
from tests.test_variants import pool, processed  # noqa: F401  (fixtures)

REPO = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------- verifier

def test_verifier_drops_and_counts_planted_unsupported_claim(pool: AlertPool) -> None:  # noqa: F811
    case = alerts(pool)
    a = case[0]
    claims = [Claim.about_alert(a.alert_id, "detector", a.detector.value),
              Claim.about_alert(a.alert_id, "detector", "planted-wrong-value"),
              Claim.about_alert(a.alert_id, "no.such.field", "x"),
              Claim.quote(a.alert_id, "this text is not in any log line"),
              Claim.about_alert("not-in-case", "detector", "wazuh")]
    out = verify_answer([a.alert_id, "unknown:al-x", a.alert_id], claims, case)
    assert out.cited == [a.alert_id] and out.dropped_citations == ["unknown:al-x"]
    assert out.claims == claims[:1] and out.checked_claims == 5
    assert [d["reason"] for d in out.dropped_claims] == [
        "value differs from record", "field not in record", "quote not in the alert's log lines",
        "alert not in case"]
    assert out.summary() == {"citations_kept": 1, "citations_dropped": 1, "claims_checked": 5,
                             "claims_kept": 1, "claims_dropped": 4}


# ---------------------------------------------------------------- graph

def kit_for(pool: AlertPool, retr: Any = None, repo: Repository | None = None,  # noqa: F811
            vectors: Any = None, embedder: Any = None) -> MultiAgentToolkit:
    case = CaseToolkit(alerts(pool), window_start=WINDOW_START, window_seconds=100.0, id_salt="s")
    memory = CaseMemory(session_id_for("s"), repo, vectors, embedder)
    return MultiAgentToolkit(case, memory, AttackSearchTool(retr) if retr else None)


def route(agent: str) -> str:
    return json.dumps({"action": "route", "agent": agent})


def tool(name: str, **arguments: Any) -> str:
    return json.dumps({"action": "call_tool", "tool": name, "arguments": arguments})


def note(text: str, ids: list[str] | None = None) -> str:
    return json.dumps({"action": "note", "text": text, "alert_ids": ids or []})


def ids_in(messages: list[dict[str, str]]) -> list[str]:
    return list(dict.fromkeys(re.findall(r"al-[0-9a-f]{8,}", " ".join(m["content"] for m in messages))))


def note_listed(messages: list[dict[str, str]]) -> str:
    return note("listed the alerts", ids_in(messages[-1:])[:3])


def get_first_noted(messages: list[dict[str, str]]) -> str:
    return tool("get_alert", alert_id=ids_in(messages)[0])


def final_with_planted_claim(messages: list[dict[str, str]]) -> str:
    record = json.loads(messages[-1]["content"].split("\n", 1)[1])
    aid = record["alert_id"]
    return json.dumps({"action": "final", "verdict": "attack", "findings": [
        {"summary": "s", "alert_ids": [aid, "al-doesnotexist"], "claims": [
            {"alert_id": aid, "kind": "field_value", "field": "detector", "value": record["detector"]},
            {"alert_id": aid, "kind": "field_value", "field": "detector", "value": "planted"}]}]})


FULL_WALK = [
    route("log_analysis"), tool("list_alerts"), note_listed,
    route("correlation"), tool("recall_notes"), note("grouped by host"),
    route("knowledge_retrieval"), tool("search_attack", text="brute force"), note("T1110 fits"),
    route("anomaly_analysis"), note("nothing unusual"),
    route("investigation"), tool("search_notes", text="host"), note("attack shown"),
    route("report_generation"), get_first_noted, final_with_planted_claim,
]
SETTINGS = load_agent_settings()


def test_every_graph_edge_and_the_verifier(pool: AlertPool, retriever: AttackRetriever) -> None:  # noqa: F811
    repo_db = SqliteDatabase(":memory:")
    repo_db.migrate()
    repo = Repository(repo_db)
    kit = kit_for(pool, retriever, repo, SqliteVectorStore(), HashEmbedder())
    client = FakeClient(list(FULL_WALK))
    run = run_graph(client, kit, alerts(pool), SETTINGS.agent, SETTINGS.model)
    assert run.status == "ok" and run.parse_status == "ok", run.error
    assert run.trace == ["supervisor", "log_analysis", "supervisor", "correlation", "supervisor",
                         "knowledge_retrieval", "supervisor", "anomaly_analysis", "supervisor",
                         "investigation", "supervisor", "report_generation", "verifier"]
    walked = {("__start__", "supervisor"), *zip(run.trace, run.trace[1:]), ("verifier", "__end__")}
    normal = {e for e in GRAPH_EDGES if e[1] != "__end__" or e[0] == "verifier"}
    assert normal <= walked
    assert run.notes == 5 and run.tool_calls == 5
    assert run.verification["claims_dropped"] == 1 and run.verification["citations_dropped"] == 1
    assert len(run.claims) == 1 and len(run.raw_claims) == 2
    assert [r["value"]["agent"] for r in repo.recall(kit.memory.session_id)] == list(AGENTS[:-1])
    assert kit.memory.search("host")  # vector memory answers


def test_stop_edges_supervisor_worker_report(pool: AlertPool) -> None:  # noqa: F811
    # supervisor -> END: two bad replies (one repair per case)
    run = run_graph(FakeClient(["nope", "still nope"]), kit_for(pool), alerts(pool), SETTINGS.agent,
                    SETTINGS.model)
    assert (run.status, run.parse_status, run.trace) == ("failed", "unparseable", ["supervisor"])
    assert run.verdict is None and run.cited_alert_ids == []
    # worker -> END: tool budget
    small = dataclasses.replace(SETTINGS.agent, max_tool_calls=1)
    run = run_graph(FakeClient([route("log_analysis"), tool("list_alerts"), tool("list_alerts"),
                                tool("list_alerts")]), kit_for(pool), alerts(pool), small, SETTINGS.model)
    assert run.status == "tool_budget_exceeded" and run.budget_hit == "tool_budget_exceeded"
    assert run.tool_calls == 1 and run.trace == ["supervisor", "log_analysis"]
    # report_generation -> END: unparseable final
    run = run_graph(FakeClient([route("report_generation"), "{bad", "{bad"]), kit_for(pool),
                    alerts(pool), SETTINGS.agent, SETTINGS.model)
    assert run.status == "failed" and run.trace == ["supervisor", "report_generation"]


def test_token_budget_hard_stop(pool: AlertPool) -> None:  # noqa: F811
    model = dataclasses.replace(SETTINGS.model, max_tokens=200)
    agent = dataclasses.replace(SETTINGS.agent, max_tokens_per_case=2_000)
    script = [route("log_analysis")] + [tool("list_alerts")] * 20
    run = run_graph(FakeClient(script), kit_for(pool), alerts(pool), agent, model)
    assert run.status == "token_budget_exceeded" and run.budget_hit == "token_budget_exceeded"
    assert run.total_tokens <= agent.max_tokens_per_case
    assert run.verdict is None


def test_turn_limit_ends_turn_without_note_and_forced_report(pool: AlertPool) -> None:  # noqa: F811
    gs = GraphSettings(max_turn_tool_calls=1, max_supervisor_steps=1)
    final = json.dumps({"action": "final", "verdict": "benign", "findings": []})
    script = [route("log_analysis"), tool("list_alerts"), tool("list_alerts"), tool("list_alerts"),
              final]
    run = run_graph(FakeClient(script), kit_for(pool), alerts(pool), SETTINGS.agent, SETTINGS.model, gs)
    assert run.turns_without_note == 1 and run.notes == 0
    assert run.forced_report and run.trace[-2:] == ["report_generation", "verifier"]
    assert run.status == "ok" and run.verdict == "benign"


def test_empty_retrieval_and_unavailable_retrieval(pool: AlertPool) -> None:  # noqa: F811
    kit = kit_for(pool)  # no retriever
    out = kit.call("search_attack", {"text": "x"}, AGENT_TOOLS["knowledge_retrieval"])
    assert json.loads(out)["techniques"] == []
    denied = kit.call("list_alerts", {}, AGENT_TOOLS["knowledge_retrieval"])
    assert "not available to this agent" in denied


def test_parse_graph_reply_is_strict() -> None:
    with pytest.raises(ProtocolError):
        parse_graph_reply('{"action": "route", "agent": "boss"}', ("route",))
    with pytest.raises(ProtocolError):
        parse_graph_reply('{"action": "note", "text": "x", "extra": 1}', ("note",))
    with pytest.raises(ProtocolError):
        parse_graph_reply('{"action": "final", "verdict": "attack", "findings": []}', ("route",))


def test_no_prompt_tool_output_or_memory_write_leaks(pool: AlertPool, retriever: AttackRetriever) -> None:  # noqa: F811
    repo_db = SqliteDatabase(":memory:")
    repo_db.migrate()
    repo = Repository(repo_db)
    kit = kit_for(pool, retriever, repo, SqliteVectorStore(), HashEmbedder())
    client = FakeClient(list(FULL_WALK))
    run_graph(client, kit, alerts(pool), SETTINGS.agent, SETTINGS.model)
    real_ids = {a.alert_id for a in alerts(pool)}
    texts = [m["content"] for call in client.calls for m in call]
    texts += [json.dumps(w) for w in kit.memory.writes]
    texts += [json.dumps(r) for r in repo.recall(kit.memory.session_id)]
    texts += list(PROMPTS.values())
    assert kit.memory.session_id.startswith("mem-") and "synthetic" not in kit.memory.session_id
    # KB excerpts are ATT&CK text; label words may appear there only if the KB has them
    kb_text = " ".join(c.text for c in attack_chunks(AttackKB.from_stix(
        REPO / "data" / "samples" / "synthetic_attack_stix.json"))).lower()
    for text in texts:
        lower = text.lower()
        for token in forbidden_tokens(pool):
            if token.lower() in lower:
                assert token.lower() in kb_text, f"leaked {token!r} in {text[:160]}"
        for value in re.findall(r'"([^"]*)"', text):
            assert value not in real_ids, f"real alert id leaked: {value}"
        assert not re.search(r"\b1[0-9]{9}\b", text), text[:160]
        assert not re.search(r"20[0-9]{2}-[01][0-9]-[0-3][0-9]", text), text[:160]


def test_budgets_are_the_m5_budgets() -> None:
    import inspect

    from app.agent import graph
    src = inspect.getsource(graph)
    assert "agent.max_tokens_per_case" in src and "agent.max_tool_calls" in src
    assert "agent.repair_retries" in src
    assert isinstance(SETTINGS.agent, AgentConfig)
