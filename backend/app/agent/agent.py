"""The single tool-using investigation agent: a bounded loop over one case.

Loop: send the conversation, parse the reply strictly
(app.agent.protocol), run a tool call or stop on a final answer. Bounds,
all from :class:`AgentConfig`:

- ``max_tool_calls`` per case. When it is used up the model is told once to
  answer; another tool call then ends the case as ``tool_budget_exceeded``.
- ``max_tokens_per_case`` (input + output over all requests). Before each
  request the loop checks that the tokens used so far, plus a conservative
  estimate of the prompt (3 characters per token) plus the request's
  ``max_tokens``, fit the budget; otherwise the case ends as
  ``token_budget_exceeded`` without sending it.
- ``repair_retries`` (at most 1): an unparseable or invalid reply gets one
  repair message; a second bad reply ends the case as ``failed`` with
  ``parse_status = "unparseable"``. A failed case has no verdict and no
  citations: it is a logged failure, never a silent success.

The final answer's opaque alert ids are mapped back to real ids; an id the
toolkit does not know becomes ``unknown:<id>`` so the scorer counts it as a
wrong citation. Claims become :class:`Claim` objects about the real ids.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any

from app.agent.client import ChatClient, ModelRequestError
from app.agent.config import AgentConfig, ModelConfig
from app.agent.protocol import (
    REPAIR_MESSAGE,
    SYSTEM_PROMPT,
    TOOL_BUDGET_MESSAGE,
    FinalAnswer,
    ProtocolError,
    parse_reply,
)
from app.agent.tools import CaseToolkit
from app.evaluation.metrics import Claim

STATUSES = ("ok", "failed", "tool_budget_exceeded", "token_budget_exceeded", "request_failed")


def conservative_tokens(messages: list[dict[str, str]]) -> int:
    """Prompt-size estimate for the budget check: 3 characters per token (deliberately high)."""
    return sum(math.ceil(len(m["content"]) / 3) for m in messages)


@dataclass
class CaseRun:
    status: str = "failed"
    parse_status: str | None = None  # ok | repaired | unparseable (None: no reply parsed)
    verdict: str | None = None
    final: dict[str, Any] | None = None
    cited_alert_ids: list[str] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    usage_reported: bool = True
    requests: int = 0
    tool_calls: int = 0
    repairs: int = 0
    latency_seconds: float = 0.0  # sum of request latencies
    wall_seconds: float = 0.0
    error: str | None = None
    transcript: list[dict[str, str]] = field(default_factory=list)
    request_log: list[dict[str, Any]] = field(default_factory=list)

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


def _resolve(toolkit: CaseToolkit, opaque: str) -> str:
    real = toolkit.resolve(opaque)
    return real if real is not None else f"unknown:{opaque}"


def _apply_final(run: CaseRun, answer: FinalAnswer, toolkit: CaseToolkit) -> None:
    run.verdict = answer.verdict
    run.final = answer.model_dump(mode="json")
    cited: list[str] = []
    for finding in answer.findings:
        cited.extend(_resolve(toolkit, i) for i in finding.alert_ids)
        for claim in finding.claims:
            alert_id = _resolve(toolkit, claim.alert_id)
            if claim.kind == "quote":
                assert claim.text is not None  # checked by ClaimOut
                run.claims.append(Claim.quote(alert_id, claim.text))
            else:
                assert claim.field is not None
                run.claims.append(Claim.about_alert(alert_id, claim.field, claim.value_text()))
    run.cited_alert_ids = list(dict.fromkeys(cited))


def investigate(client: ChatClient, toolkit: CaseToolkit, agent: AgentConfig,
                model: ModelConfig) -> CaseRun:
    run = CaseRun()
    messages: list[dict[str, str]] = [{"role": "system", "content": SYSTEM_PROMPT},
                                      {"role": "user", "content": toolkit.brief()}]
    run.transcript = messages
    told_budget = False
    started = time.perf_counter()
    while True:
        needed = run.total_tokens + conservative_tokens(messages) + model.max_tokens
        if needed > agent.max_tokens_per_case:
            run.status = "token_budget_exceeded"
            run.error = (f"next request could need {needed} tokens; budget "
                         f"{agent.max_tokens_per_case} per case")
            break
        try:
            result = client.chat(messages, max_tokens=model.max_tokens, temperature=model.temperature)
        except ModelRequestError as exc:
            run.status, run.error = "request_failed", str(exc)
            break
        run.requests += 1
        run.input_tokens += result.input_tokens
        run.output_tokens += result.output_tokens
        run.usage_reported = run.usage_reported and result.usage_reported
        run.latency_seconds += result.latency_seconds
        messages.append({"role": "assistant", "content": result.content})
        entry: dict[str, Any] = {"request": run.requests, "input_tokens": result.input_tokens,
                                 "output_tokens": result.output_tokens,
                                 "usage_reported": result.usage_reported,
                                 "latency_seconds": result.latency_seconds,
                                 "finish_reason": result.finish_reason, "attempts": result.attempts}
        run.request_log.append(entry)
        try:
            reply = parse_reply(result.content)
        except ProtocolError as exc:
            entry["parse"] = f"error: {exc}"
            if run.repairs < agent.repair_retries:
                run.repairs += 1
                messages.append({"role": "user", "content": REPAIR_MESSAGE.format(error=exc)})
                continue
            run.status, run.parse_status, run.error = "failed", "unparseable", f"unparseable reply: {exc}"
            break
        entry["parse"] = reply.action
        if isinstance(reply, FinalAnswer):
            _apply_final(run, reply, toolkit)
            run.status = "ok"
            run.parse_status = "repaired" if run.repairs else "ok"
            break
        if run.tool_calls >= agent.max_tool_calls:
            if told_budget:
                run.status = "tool_budget_exceeded"
                run.error = f"tool call after the budget of {agent.max_tool_calls} was used up"
                break
            told_budget = True
            messages.append({"role": "user",
                             "content": TOOL_BUDGET_MESSAGE.format(calls=agent.max_tool_calls)})
            continue
        run.tool_calls += 1
        entry["tool"] = reply.tool
        output = toolkit.call(reply.tool, reply.arguments)
        messages.append({"role": "user", "content": f"TOOL RESULT ({reply.tool}):\n{output}"})
    if run.total_tokens > agent.max_tokens_per_case and run.status == "ok":
        # The estimate was too low for this model's tokenizer: record it, keep the answer.
        run.error = f"used {run.total_tokens} tokens, above the per-case budget"
    run.wall_seconds = time.perf_counter() - started
    return run
