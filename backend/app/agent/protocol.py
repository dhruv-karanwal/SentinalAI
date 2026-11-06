"""The agent's reply protocol: one JSON object per reply, parsed strictly.

The protocol is plain JSON in the message text rather than a provider's
native function-calling API, so the same agent runs on any
OpenAI-compatible endpoint (small local models often lack reliable native
tool calling). Every reply must be exactly one JSON object, nothing else:

    {"action": "call_tool", "tool": "<name>", "arguments": {...}}
    {"action": "final", "verdict": "attack" | "benign",
     "findings": [{"summary": "...", "alert_ids": ["al-..."],
                   "claims": [{"alert_id": "al-...", "kind": "field_value",
                               "field": "<dotted path>", "value": "..."},
                              {"alert_id": "al-...", "kind": "quote",
                               "text": "<exact text from a log line>"}]}]}

Parsing is strict: no markdown fences, no prose around the object, no
unknown keys. The agent loop allows at most one repair retry per case.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.agent.tools import TIME_MASK, TOOL_NAMES
from app.evaluation.metrics import QUOTE_MIN_CHARS

PROMPT_VERSION = "m5-v1"

SYSTEM_PROMPT = f"""You are a security analyst investigating one case: a time window of a \
monitored network and the alerts that intrusion detectors raised in it. Decide whether the \
window contains attacker activity, and support every finding with alert evidence.

Reply with exactly ONE JSON object and nothing else (no markdown, no prose). Two forms:

1. Call a tool:
{{"action": "call_tool", "tool": "<tool name>", "arguments": {{...}}}}

2. Final answer (ends the case):
{{"action": "final", "verdict": "attack" or "benign", "findings": [
  {{"summary": "<one sentence>", "alert_ids": ["<alert_id>", ...],
    "claims": [
      {{"alert_id": "<alert_id>", "kind": "field_value", "field": "<dotted field path>", "value": "<exact value>"}},
      {{"alert_id": "<alert_id>", "kind": "quote", "text": "<exact text copied from one log line>"}}
    ]}}
]}}

Tools ({", ".join(TOOL_NAMES)}):
- list_alerts: arguments (all optional) detector, rule_id, min_severity, offset_min, offset_max, page. \
Returns alert summaries in time order, one page at a time.
- get_alert: arguments alert_id. Returns the full alert record.
- search_alerts: arguments text (required), field (optional dotted path), page. Case-insensitive \
substring search over alert fields.
- get_raw_log: arguments alert_id. Returns the raw log lines the alert carries.

Rules:
- Cite only alert_id values returned by the tools. Cite the alerts that show attacker activity; \
for a benign verdict, findings may be empty.
- field_value claims: "field" is a dotted path into the record returned by get_alert (for example \
rule_id, severity, raw_alert.rule.level, evidence.log_lines.0) and "value" its exact value. Do not \
make claims about alert_id, offset or time fields.
- quote claims: "text" must be copied exactly from one of the alert's log lines, at least \
{QUOTE_MIN_CHARS} characters, and must not include {TIME_MASK}.
- Times are offsets in seconds from the window start; absolute dates and times are masked as {TIME_MASK}.
- You have a limited number of tool calls. When told the budget is used up, give your final answer.
"""

REPAIR_MESSAGE = ("Your last reply was not valid: {error}. Reply again with exactly one JSON object "
                  "in one of the two forms, and nothing else.")
TOOL_BUDGET_MESSAGE = ("The tool budget is used up ({calls} calls). Reply now with your final "
                       "answer as one JSON object with action \"final\".")


class ProtocolError(Exception):
    """A reply that is not a valid protocol object."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ClaimOut(_Strict):
    alert_id: str = Field(min_length=1)
    kind: Literal["field_value", "quote"]
    field: str | None = Field(default=None, min_length=1)
    value: str | int | float | bool | None = None
    text: str | None = None

    @model_validator(mode="after")
    def _check(self) -> ClaimOut:
        if self.kind == "field_value" and (self.field is None or self.value is None):
            raise ValueError("a field_value claim needs field and value")
        if self.kind == "quote" and (self.text is None or len(self.text) < QUOTE_MIN_CHARS):
            raise ValueError(f"a quote claim needs text of at least {QUOTE_MIN_CHARS} characters")
        return self

    def value_text(self) -> str:
        """The claimed value in the flattened-record spelling (strings as-is, others as JSON)."""
        return self.value if isinstance(self.value, str) else json.dumps(self.value)


class FindingOut(_Strict):
    summary: str
    alert_ids: list[str]
    claims: list[ClaimOut] = Field(default_factory=list)


class FinalAnswer(_Strict):
    action: Literal["final"]
    verdict: Literal["attack", "benign"]
    findings: list[FindingOut]


class ToolCall(_Strict):
    action: Literal["call_tool"]
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)


def parse_reply(text: str) -> ToolCall | FinalAnswer:
    try:
        data = json.loads(text.strip())
    except json.JSONDecodeError as exc:
        raise ProtocolError(f"not valid JSON ({exc.msg})") from None
    if not isinstance(data, dict):
        raise ProtocolError("the reply must be one JSON object")
    action = data.get("action")
    model: type[ToolCall] | type[FinalAnswer]
    if action == "call_tool":
        model = ToolCall
    elif action == "final":
        model = FinalAnswer
    else:
        raise ProtocolError('"action" must be "call_tool" or "final"')
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(p) for p in first["loc"]) or "object"
        raise ProtocolError(f"{where}: {first['msg']}") from None
