"""Multi-agent investigation graph (Wave C): a LangGraph supervisor and six agents.

Nodes: ``supervisor``, six agents (:data:`AGENTS`) and ``verifier``.
Edges (:data:`GRAPH_EDGES`): START -> supervisor; supervisor -> any agent
(its JSON reply picks one) or END on a stop; each of the five working
agents -> supervisor (or END on a stop); report_generation -> verifier (or
END on a stop); verifier -> END.

Every agent is one model with a role prompt; it may call the tools of its
role (:data:`AGENT_TOOLS`) and ends its turn with a note
(``{"action": "note", ...}``) written to the shared memory
(:class:`~app.agent.multi_tools.CaseMemory`: repository memory table +
vector memory). ``report_generation`` ends with the M5 final-answer object
(:class:`~app.agent.protocol.FinalAnswer`), which the ``verifier`` node checks
against the case's alert records (:mod:`app.agent.verifier`).

**Budgets: the same per-case numbers as the M5 single agent**, read from
the one ``agent`` section of study.json (:class:`AgentConfig`) and enforced
here over the whole graph, with a hard stop:

- ``max_tokens_per_case``: before every request (supervisor or agent) the
  tokens used so far + the prompt estimate (3 chars/token, as in M5) +
  ``max_tokens`` must fit, else the case stops as ``token_budget_exceeded``;
- ``max_tool_calls``: tool calls over all agents; when used up the calling
  agent is told once to finish; another tool call stops the case as
  ``tool_budget_exceeded``;
- ``repair_retries``: one repair over the whole case; a second bad reply
  stops it as ``failed`` / ``unparseable``.

Pacing inside the budget (not a budget): ``GraphSettings.max_turn_tool_calls``
per agent turn and ``max_supervisor_steps`` (then report_generation is
forced). A stopped case has no verdict and no citations, as in M5.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, TypedDict

from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.agent.agent import CaseRun, conservative_tokens
from app.agent.client import ChatClient, ModelRequestError
from app.agent.config import AgentConfig, ModelConfig
from app.agent.multi_tools import MultiAgentToolkit
from app.agent.protocol import OUTPUT_CAP, FinalAnswer, ProtocolError, ToolCall
from app.agent.tools import TIME_MASK
from app.agent.verifier import verify_answer
from app.evaluation.metrics import QUOTE_MIN_CHARS, Claim
from app.schemas.alert import Alert

# wave-c-v2 (2026-11-13, pilot gate): repair message per node, brief asks only report_generation
# for a final answer, output cap in the report form
GRAPH_PROMPT_VERSION = "wave-c-v2"

AGENTS = ("log_analysis", "correlation", "knowledge_retrieval", "anomaly_analysis",
          "investigation", "report_generation")
WORKERS = AGENTS[:-1]
AGENT_ROLES = {
    "log_analysis": "Read the alerts and their raw log lines; describe what each group of alerts shows.",
    "correlation": "Find alerts that belong together (same host, IP, rule or close in time) and say how.",
    "knowledge_retrieval": "Map the observed behaviour to MITRE ATT&CK techniques with search_attack.",
    "anomaly_analysis": "Look at anomaly-detector alerts (aminer) and unusual values; say what stands out.",
    "investigation": "Weigh the notes so far and the evidence; state whether attacker activity is shown.",
    "report_generation": "Write the final answer for the case from the notes, citing alert evidence.",
}
AGENT_TOOLS: dict[str, tuple[str, ...]] = {
    "log_analysis": ("list_alerts", "get_alert", "get_raw_log", "search_alerts"),
    "correlation": ("list_alerts", "search_alerts", "get_alert", "recall_notes"),
    "knowledge_retrieval": ("search_attack", "get_alert", "recall_notes"),
    "anomaly_analysis": ("list_alerts", "get_alert", "get_raw_log"),
    "investigation": ("list_alerts", "get_alert", "get_raw_log", "search_alerts", "recall_notes",
                      "search_notes", "search_attack"),
    "report_generation": ("recall_notes", "get_alert", "get_raw_log"),
}
GRAPH_EDGES: tuple[tuple[str, str], ...] = (
    ("__start__", "supervisor"),
    *(("supervisor", a) for a in AGENTS), ("supervisor", "__end__"),
    *((w, "supervisor") for w in WORKERS), *((w, "__end__") for w in WORKERS),
    ("report_generation", "verifier"), ("report_generation", "__end__"),
    ("verifier", "__end__"),
)

_JSON_RULE = "Reply with exactly ONE JSON object and nothing else (no markdown, no prose)."
_CONTEXT = (f"Times are offsets in seconds from the window start; absolute dates and times are "
            f"masked as {TIME_MASK}. Cite only alert_id values returned by the tools.")

SUPERVISOR_PROMPT = f"""You coordinate a team of security analysts investigating one case: a time \
window of a monitored network and the alerts intrusion detectors raised in it. Agents:
{chr(10).join(f"- {a}: {AGENT_ROLES[a]}" for a in AGENTS)}
{_JSON_RULE} Form: {{"action": "route", "agent": "<agent name>"}}
Pick the agent whose work is most useful next. Route to report_generation when the notes are \
enough; it writes the final answer and ends the case. The tool and token budget is shared."""


def _agent_prompt(name: str) -> str:
    tools = ", ".join(AGENT_TOOLS[name])
    if name == "report_generation":
        form = (f"""Final answer form (ends the case):
{{"action": "final", "verdict": "attack" or "benign", "findings": [
  {{"summary": "<one sentence>", "alert_ids": ["<alert_id>", ...], "claims": [
    {{"alert_id": "<alert_id>", "kind": "field_value", "field": "<dotted field path>", "value": "<exact value>"}},
    {{"alert_id": "<alert_id>", "kind": "quote", "text": "<exact text copied from one log line>"}}]}}]}}
field_value: a dotted path into the record from get_alert and its exact value; not alert_id, \
offset or time fields. quote: copied exactly from one log line, at least {QUOTE_MIN_CHARS} \
characters, without {TIME_MASK}. Unsupported claims are removed by a verifier.
{OUTPUT_CAP}""")
    else:
        form = ('End your turn with a note: {"action": "note", "text": "<your findings>", '
                '"alert_ids": ["<alert_id>", ...]}')
    return f"""You are the {name} agent of a security investigation team. {AGENT_ROLES[name]}
Tools: {tools}. Tool call form: {{"action": "call_tool", "tool": "<tool name>", "arguments": {{...}}}}
Tool arguments: list_alerts (all optional) detector, rule_id, min_severity, offset_min, offset_max, \
page; get_alert / get_raw_log: alert_id; search_alerts: text, optional field, page; \
search_attack: text, optional k (1-5); recall_notes: none; search_notes: text.
{form}
{_JSON_RULE} {_CONTEXT}"""


PROMPTS = {"supervisor": SUPERVISOR_PROMPT, **{a: _agent_prompt(a) for a in AGENTS}}
PROMPTS_SHA256 = hashlib.sha256(json.dumps(PROMPTS, sort_keys=True).encode()).hexdigest()
TURN_LIMIT_MESSAGE = "This turn's tool calls are used up. Reply now with your {form} object."
REPLY_FORMS = {
    "route": '{"action": "route", "agent": "<agent name>"}',
    "call_tool": '{"action": "call_tool", "tool": "<tool name>", "arguments": {...}}',
    "note": '{"action": "note", "text": "<your findings>", "alert_ids": ["<alert_id>", ...]}',
    "final": '{"action": "final", "verdict": "attack" or "benign", "findings": [...]}',
}


def repair_message(error: object, actions: Sequence[str]) -> str:
    """The repair names only the node's own forms (the pilot's shared single-agent message
    offered `final` to note agents, which the parser then rejected)."""
    forms = " or ".join(REPLY_FORMS[a] for a in actions)
    which = "this form" if len(actions) == 1 else "one of these forms"
    return (f"Your last reply was not valid: {error}. Reply again with exactly one JSON object "
            f"in {which}, and nothing else: {forms}.")


BUDGET_MESSAGE = ("The case's tool budget is used up ({calls} calls). Reply now with your {form} "
                  "object and no further tool calls.")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Route(_Strict):
    action: Literal["route"]
    agent: Literal["log_analysis", "correlation", "knowledge_retrieval", "anomaly_analysis",
                   "investigation", "report_generation"]


class Note(_Strict):
    action: Literal["note"]
    text: str = Field(min_length=1)
    alert_ids: list[str] = Field(default_factory=list)


_MODELS: dict[str, type[BaseModel]] = {"route": Route, "note": Note, "call_tool": ToolCall,
                                       "final": FinalAnswer}


def parse_graph_reply(text: str, actions: Sequence[str]) -> BaseModel:
    try:
        data = json.loads(text.strip())
    except json.JSONDecodeError as exc:
        raise ProtocolError(f"not valid JSON ({exc.msg})") from None
    if not isinstance(data, dict):
        raise ProtocolError("the reply must be one JSON object")
    action = data.get("action")
    if action not in actions:
        raise ProtocolError(f'"action" must be one of {", ".join(actions)}')
    try:
        return _MODELS[str(action)].model_validate(data)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(p) for p in first["loc"]) or "object"
        raise ProtocolError(f"{where}: {first['msg']}") from None


@dataclass(frozen=True)
class GraphSettings:
    max_turn_tool_calls: int = 4
    max_supervisor_steps: int = 8
    recursion_limit: int = 64


@dataclass
class GraphRun(CaseRun):
    trace: list[str] = field(default_factory=list)
    notes: int = 0
    budget_hit: str | None = None
    verification: dict[str, Any] = field(default_factory=dict)
    forced_report: bool = False
    turns_without_note: int = 0
    raw_cited_alert_ids: list[str] = field(default_factory=list)  # before the verifier
    raw_claims: list[Claim] = field(default_factory=list)

    def trace_agents(self) -> list[str]:
        return [t for t in self.trace if t in AGENTS]


class GraphState(TypedDict, total=False):
    next: str
    status: str


class _Stop(Exception):
    def __init__(self, status: str, error: str, parse_status: str | None = None) -> None:
        super().__init__(error)
        self.status, self.error, self.parse_status = status, error, parse_status


class _CaseContext:
    def __init__(self, client: ChatClient, kit: MultiAgentToolkit, alerts: Sequence[Alert],
                 agent: AgentConfig, model: ModelConfig, settings: GraphSettings) -> None:
        self.client, self.kit, self.alerts = client, kit, list(alerts)
        self.agent, self.model, self.settings = agent, model, settings
        self.run = GraphRun()
        self.told_budget = False
        self.supervisor_steps = 0
        self.final: FinalAnswer | None = None

    # -- model requests under the shared budget --------------------------------------------
    def request(self, node: str, messages: list[dict[str, str]]) -> str:
        run = self.run
        needed = run.total_tokens + conservative_tokens(messages) + self.model.max_tokens
        if needed > self.agent.max_tokens_per_case:
            raise _Stop("token_budget_exceeded", f"{node}: next request could need {needed} tokens; "
                        f"budget {self.agent.max_tokens_per_case} per case")
        try:
            result = self.client.chat(messages, max_tokens=self.model.max_tokens,
                                      temperature=self.model.temperature)
        except ModelRequestError as exc:
            raise _Stop("request_failed", f"{node}: {exc}") from exc
        run.requests += 1
        run.input_tokens += result.input_tokens
        run.output_tokens += result.output_tokens
        run.usage_reported = run.usage_reported and result.usage_reported
        run.latency_seconds += result.latency_seconds
        run.request_log.append({"request": run.requests, "node": node,
                                "input_tokens": result.input_tokens,
                                "output_tokens": result.output_tokens,
                                "usage_reported": result.usage_reported,
                                "latency_seconds": result.latency_seconds,
                                "finish_reason": result.finish_reason, "attempts": result.attempts})
        messages.append({"role": "assistant", "content": result.content})
        return result.content

    def ask(self, node: str, messages: list[dict[str, str]], actions: Sequence[str]) -> BaseModel:
        """One reply, with the case's single repair retry shared across all nodes."""
        while True:
            text = self.request(node, messages)
            try:
                reply = parse_graph_reply(text, actions)
            except ProtocolError as exc:
                self.run.request_log[-1]["parse"] = f"error: {exc}"
                if self.run.repairs < self.agent.repair_retries:
                    self.run.repairs += 1
                    messages.append({"role": "user", "content": repair_message(exc, actions)})
                    continue
                raise _Stop("failed", f"{node}: unparseable reply: {exc}", "unparseable") from None
            self.run.request_log[-1]["parse"] = str(getattr(reply, "action"))
            return reply

    def notes_text(self) -> str:
        notes = self.kit.memory.recall()
        if not notes:
            return "Notes so far: none."
        return "Notes so far:\n" + "\n".join(
            f"[{n['n']}] {n['agent']}: {n['text']} (alerts: {', '.join(n['alert_ids']) or 'none'})"
            for n in notes)

    # -- nodes ----------------------------------------------------------------------------
    def supervisor(self, state: GraphState) -> GraphState:
        self.run.trace.append("supervisor")
        if self.supervisor_steps >= self.settings.max_supervisor_steps:
            self.run.forced_report = True
            return {"next": "report_generation"}
        self.supervisor_steps += 1
        messages = [{"role": "system", "content": SUPERVISOR_PROMPT},
                    {"role": "user", "content": f"{self.kit.brief(final=False)}\n\n{self.notes_text()}\n\n"
                     f"Agents visited so far: {', '.join(self.run.trace_agents()) or 'none'}."}]
        self.run.transcript.append({"role": "node", "content": "supervisor"})
        try:
            reply = self.ask("supervisor", messages, ("route",))
        finally:
            self.run.transcript.extend(messages)
        assert isinstance(reply, Route)
        return {"next": reply.agent}

    def agent_turn(self, name: str) -> GraphState:
        self.run.trace.append(name)
        report = name == "report_generation"
        form = "final answer" if report else "note"
        end_action = "final" if report else "note"
        messages = [{"role": "system", "content": PROMPTS[name]},
                    {"role": "user", "content": f"{self.kit.brief(final=report)}\n\n{self.notes_text()}"}]
        self.run.transcript.append({"role": "node", "content": name})
        turn_calls, told_turn = 0, False
        try:
            while True:
                reply = self.ask(name, messages, ("call_tool", end_action))
                if isinstance(reply, Note):
                    note = self.kit.memory.write(name, reply.text, reply.alert_ids)
                    self.run.notes += 1
                    self.run.request_log[-1]["note"] = note["n"]
                    return {"next": "supervisor"}
                if isinstance(reply, FinalAnswer):
                    self.final = reply
                    return {"next": "verifier"}
                assert isinstance(reply, ToolCall)
                if self.run.tool_calls >= self.agent.max_tool_calls:
                    if self.told_budget:
                        raise _Stop("tool_budget_exceeded", f"{name}: tool call after the budget of "
                                    f"{self.agent.max_tool_calls} was used up")
                    self.told_budget = True
                    messages.append({"role": "user", "content": BUDGET_MESSAGE.format(
                        calls=self.agent.max_tool_calls, form=form)})
                    continue
                if turn_calls >= self.settings.max_turn_tool_calls:
                    if told_turn:  # the turn ends without a note; nothing is written for it
                        self.run.turns_without_note += 1
                        self.run.request_log[-1]["turn"] = "ended at the turn limit, no note"
                        if report:
                            raise _Stop("failed", "report_generation reached its turn limit "
                                        "without a final answer")
                        return {"next": "supervisor"}
                    told_turn = True
                    messages.append({"role": "user", "content": TURN_LIMIT_MESSAGE.format(form=form)})
                    continue
                self.run.tool_calls += 1
                turn_calls += 1
                self.run.request_log[-1]["tool"] = reply.tool
                out = self.kit.call(reply.tool, reply.arguments, AGENT_TOOLS[name])
                messages.append({"role": "user", "content": f"TOOL RESULT ({reply.tool}):\n{out}"})
        finally:
            self.run.transcript.extend(messages)

    def verifier(self, state: GraphState) -> GraphState:
        self.run.trace.append("verifier")
        assert self.final is not None
        answer = self.final
        cited: list[str] = []
        claims: list[Claim] = []
        for finding in answer.findings:
            cited.extend(self._resolve(i) for i in finding.alert_ids)
            for c in finding.claims:
                alert_id = self._resolve(c.alert_id)
                if c.kind == "quote":
                    assert c.text is not None
                    claims.append(Claim.quote(alert_id, c.text))
                else:
                    assert c.field is not None
                    claims.append(Claim.about_alert(alert_id, c.field, c.value_text()))
        checked = verify_answer(cited, claims, self.alerts)
        run = self.run
        run.raw_cited_alert_ids = list(dict.fromkeys(cited))
        run.raw_claims = claims
        run.verdict = answer.verdict
        run.final = answer.model_dump(mode="json")
        run.cited_alert_ids = checked.cited
        run.claims = checked.claims
        run.verification = {**checked.summary(), "dropped_citations": checked.dropped_citations,
                            "dropped_claims": checked.dropped_claims}
        run.status = "ok"
        run.parse_status = "repaired" if run.repairs else "ok"
        return {"next": "end"}

    def _resolve(self, opaque: str) -> str:
        real = self.kit.case.resolve(opaque)
        return real if real is not None else f"unknown:{opaque}"


def _guard(ctx: _CaseContext, fn: Callable[[GraphState], GraphState]) -> Callable[[GraphState], GraphState]:
    def node(state: GraphState) -> GraphState:
        try:
            return fn(state)
        except _Stop as stop:
            ctx.run.status, ctx.run.error = stop.status, stop.error
            ctx.run.parse_status = stop.parse_status or ctx.run.parse_status
            if stop.status in ("token_budget_exceeded", "tool_budget_exceeded"):
                ctx.run.budget_hit = stop.status
            return {"next": "stop", "status": stop.status}
    return node


def _agent_node(ctx: _CaseContext, name: str) -> Callable[[GraphState], GraphState]:
    def node(state: GraphState) -> GraphState:
        return ctx.agent_turn(name)
    return node


def build_graph(ctx: _CaseContext) -> Any:
    # LangGraph's add_node overloads do not type plain callables under mypy --strict; the graph
    # object is Any at this one boundary, the node functions themselves are typed.
    g: Any = StateGraph(GraphState)
    g.add_node("supervisor", _guard(ctx, ctx.supervisor))
    for a in AGENTS:
        g.add_node(a, _guard(ctx, _agent_node(ctx, a)))
    g.add_node("verifier", _guard(ctx, ctx.verifier))
    g.add_edge(START, "supervisor")
    g.add_conditional_edges("supervisor", nxt, {**{a: a for a in AGENTS}, "stop": END})
    for w in WORKERS:
        g.add_conditional_edges(w, nxt, {"supervisor": "supervisor", "stop": END})
    g.add_conditional_edges("report_generation", nxt, {"verifier": "verifier", "stop": END})
    g.add_edge("verifier", END)
    return g.compile()


def nxt(state: GraphState) -> str:
    return str(state.get("next", "stop"))


def run_graph(client: ChatClient, kit: MultiAgentToolkit, alerts: Sequence[Alert], agent: AgentConfig,
              model: ModelConfig, settings: GraphSettings = GraphSettings()) -> GraphRun:
    ctx = _CaseContext(client, kit, alerts, agent, model, settings)
    started = time.perf_counter()
    build_graph(ctx).invoke({"next": "supervisor"}, {"recursion_limit": settings.recursion_limit})
    run = ctx.run
    if run.total_tokens > agent.max_tokens_per_case and run.status == "ok":
        run.error = f"used {run.total_tokens} tokens, above the per-case budget"
    run.wall_seconds = time.perf_counter() - started
    return run
