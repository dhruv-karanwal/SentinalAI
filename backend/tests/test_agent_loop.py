"""Single tool-using agent loop with the scripted FakeClient (no network)."""

import json
from datetime import datetime, timezone

import pytest

from app.agent.agent import investigate
from app.agent.client import FakeClient, ModelRequestError
from app.agent.config import AgentConfig, ModelConfig
from app.agent.protocol import SYSTEM_PROMPT, ProtocolError, parse_reply
from app.agent.tools import CaseToolkit
from app.study.variants import AlertPool, build_variants
from tests.test_variants import S2, aminer_id, pool, processed  # noqa: F401  (fixtures)

MODEL = ModelConfig(base_url=None, model=None, max_tokens=200)
AGENT = AgentConfig(max_tool_calls=3, max_tokens_per_case=50_000, repair_retries=1)


def kit(pool: AlertPool) -> CaseToolkit:  # noqa: F811
    alerts = list(pool.alerts(build_variants(pool, seed=7, shuffled_references=())["fused"]))
    return CaseToolkit(alerts, window_start=datetime.fromtimestamp(1700000100, tz=timezone.utc),
                       window_seconds=100.0, id_salt="t")


def tool(name: str, **arguments: object) -> str:
    return json.dumps({"action": "call_tool", "tool": name, "arguments": arguments})


def final(verdict: str, findings: list[dict[str, object]]) -> str:
    return json.dumps({"action": "final", "verdict": verdict, "findings": findings})


def opaque(k: CaseToolkit, real: str) -> str:
    return next(i for i in k.alert_ids if k.resolve(i) == real)


def test_parse_reply_is_strict() -> None:
    assert parse_reply(tool("list_alerts")).tool == "list_alerts"  # type: ignore[union-attr]
    for bad in ("", "not json", "```json\n{}\n```", "[1]", '{"action": "dance"}',
                final("maybe", []), '{"action": "final", "verdict": "attack"}',
                final("attack", [{"summary": "x", "alert_ids": ["a"],
                                  "claims": [{"alert_id": "a", "kind": "quote", "text": "short"}]}]),
                final("attack", [{"summary": "x", "alert_ids": ["a"], "extra": 1}])):
        with pytest.raises(ProtocolError):
            parse_reply(bad)
    assert "call_tool" in SYSTEM_PROMPT and "<TIME>" in SYSTEM_PROMPT


def test_tool_then_final_maps_opaque_ids_back(pool: AlertPool) -> None:  # noqa: F811
    k = kit(pool)
    a2, s2 = opaque(k, aminer_id(pool)), opaque(k, S2)

    def answer(messages: list[dict[str, str]]) -> str:
        assert a2 in messages[-1]["content"]  # the tool result reached the model
        return final("attack", [{"summary": "sudo after scan", "alert_ids": [a2, s2, "al-unknown"],
                                 "claims": [{"alert_id": a2, "kind": "field_value",
                                             "field": "detector", "value": "aminer"},
                                            {"alert_id": a2, "kind": "quote", "text": 'a0="sudo"'},
                                            {"alert_id": s2, "kind": "field_value",
                                             "field": "severity", "value": 2}]}])

    client = FakeClient([tool("search_alerts", text="sudo"), answer])
    run = investigate(client, k, AGENT, MODEL)
    assert (run.status, run.parse_status, run.verdict, run.tool_calls, run.requests) == (
        "ok", "ok", "attack", 1, 2)
    assert run.cited_alert_ids == [aminer_id(pool), S2, "unknown:al-unknown"]
    assert [(c.record_id, c.kind, c.field, c.value) for c in run.claims] == [
        (aminer_id(pool), "field_value", "detector", "aminer"),
        (aminer_id(pool), "quote", "raw_log_line", 'a0="sudo"'),
        (S2, "field_value", "severity", "2")]
    assert run.input_tokens > 0 and run.output_tokens > 0 and not run.usage_reported
    roles = [m["role"] for m in run.transcript]
    assert roles == ["system", "user", "assistant", "user", "assistant"]
    assert run.transcript[0]["content"] == SYSTEM_PROMPT
    assert [r["parse"] for r in run.request_log] == ["call_tool", "final"]


def test_one_repair_retry_then_success(pool: AlertPool) -> None:  # noqa: F811
    client = FakeClient(["Sure! Here is my answer", final("benign", [])])
    run = investigate(client, kit(pool), AGENT, MODEL)
    assert (run.status, run.parse_status, run.verdict, run.repairs) == ("ok", "repaired", "benign", 1)
    assert "not valid" in client.calls[1][-1]["content"]


def test_unparseable_after_repair_is_a_logged_failure(pool: AlertPool) -> None:  # noqa: F811
    client = FakeClient(["nope", final("unsure", [])])
    run = investigate(client, kit(pool), AGENT, MODEL)
    assert (run.status, run.parse_status, run.verdict) == ("failed", "unparseable", None)
    assert run.cited_alert_ids == [] and run.claims == [] and "verdict" in (run.error or "")
    assert len(client.calls) == 2  # exactly one repair, never more


def test_tool_budget_is_enforced(pool: AlertPool) -> None:  # noqa: F811
    budget = AgentConfig(max_tool_calls=2, max_tokens_per_case=50_000)
    client = FakeClient([tool("list_alerts")] * 4)
    run = investigate(client, kit(pool), budget, MODEL)
    assert (run.status, run.tool_calls) == ("tool_budget_exceeded", 2)
    assert "budget" in client.calls[3][-1]["content"]  # the model was told to answer now
    assert run.verdict is None


def test_token_budget_is_enforced_before_a_request(pool: AlertPool) -> None:  # noqa: F811
    client = FakeClient([final("benign", [])])
    run = investigate(client, kit(pool), AgentConfig(max_tokens_per_case=100), MODEL)
    assert (run.status, run.requests) == ("token_budget_exceeded", 0)
    assert client.calls == []


def test_request_failure_is_logged(pool: AlertPool) -> None:  # noqa: F811
    run = investigate(FakeClient([ModelRequestError("HTTP 503")]), kit(pool), AGENT, MODEL)
    assert (run.status, run.verdict) == ("request_failed", None) and "503" in (run.error or "")


def test_tool_errors_count_as_calls_and_go_back_to_the_model(pool: AlertPool) -> None:  # noqa: F811
    client = FakeClient([tool("get_alert", alert_id="al-0"), final("benign", [])])
    run = investigate(client, kit(pool), AGENT, MODEL)
    assert run.tool_calls == 1 and "unknown alert id" in client.calls[1][-1]["content"]
