"""Pilot preflight: cheap checks before an expensive matched pilot (2026-11-15).

A dev pilot takes ~1.6 h of model time. These checks catch the mistakes that waste it: a held-out
scenario in the plan, missing processed inputs, an empty ATT&CK index (the single arm now uses it
too, m5-v5), an endpoint that does not serve the configured model, and a model that cannot produce
a parseable protocol reply. Every check returns a :class:`Check`; nothing raises.

Held-out guard: input files are only looked at for dev scenarios; a held-out name fails the plan
check and its files are never opened or even stat-ed.

``schema_smoke`` sends **one** request (the m5-v5 system prompt and a fixed, case-free user
message) and parses the reply with the study's strict parser. It is opt-in (``--smoke``).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from app.agent.client import ChatClient, ModelRequestError
from app.agent.graph import GRAPH_PROMPT_VERSION
from app.agent.protocol import PROMPT_VERSION, SYSTEM_PROMPT, ProtocolError, parse_reply

SMOKE_MESSAGE = ("Preflight check, no case: there are no alerts. Reply now with your final answer "
                 "as one JSON object: verdict benign, no findings.")


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


class _Retriever(Protocol):
    def search(self, text: str, k: int = 5) -> list[dict[str, Any]]: ...


def preflight(*, scenarios: Sequence[str], dev: Sequence[str], processed_dir: Path, labels: Path,
              retriever: _Retriever | None, model_id: str | None,
              list_models: Callable[[], list[str]]) -> list[Check]:
    from app.agent.matched import TOOL_ACCESS

    checks = [Check("prompt versions", True, f"single {PROMPT_VERSION}, graph {GRAPH_PROMPT_VERSION}"),
              Check("tool access", True, "; ".join(f"{arm}: {', '.join(t)}"
                                                    for arm, t in TOOL_ACCESS.items()))]
    held = [s for s in scenarios if s not in dev]
    checks.append(Check("dev scenarios only", not held,
                        "ok" if not held else f"not dev scenarios: {', '.join(held)}"))
    dev_in_plan = [s for s in scenarios if s in dev]
    missing = [str(p) for s in dev_in_plan
               for p in (processed_dir / f"{s}.alerts.jsonl", processed_dir / f"{s}.ground_truth.jsonl")
               if not p.exists()]
    if not labels.exists():
        missing.append(str(labels))
    detail = "ok" if not missing else "missing: " + ", ".join(missing)
    if held:
        detail += f" (not checked: {', '.join(held)})"
    checks.append(Check("inputs present", not missing and not held, detail))
    if retriever is None:
        checks.append(Check("ATT&CK retrieval", False, "retrieval is off: both arms would run "
                                                       "without search_attack"))
    else:
        try:
            hits = retriever.search("failed password for root from remote host", 3)
            checks.append(Check("ATT&CK retrieval", bool(hits),
                                f"{len(hits)} technique(s) for a probe query" if hits
                                else "the index returned nothing (run rag-index)"))
        except Exception as exc:  # report, never raise: the point is to list every problem
            checks.append(Check("ATT&CK retrieval", False, f"{type(exc).__name__}: {exc}"))
    if not model_id:
        checks.append(Check("model endpoint", False, "no model configured (SENTINEL_LLM_BASE_URL / "
                                                     "SENTINEL_LLM_MODEL)"))
    else:
        try:
            listed = list_models()
            ok = model_id in listed or f"{model_id}:latest" in listed
            checks.append(Check("model endpoint", ok, f"{model_id} listed" if ok else
                                f"{model_id} not listed by the endpoint ({len(listed)} models)"))
        except Exception as exc:
            checks.append(Check("model endpoint", False, f"{type(exc).__name__}: {exc}"))
    return checks


def schema_smoke(client: ChatClient, *, max_tokens: int, temperature: float = 0.0) -> Check:
    messages = [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": SMOKE_MESSAGE}]
    try:
        result = client.chat(messages, max_tokens=max_tokens, temperature=temperature)
    except ModelRequestError as exc:
        return Check("schema smoke", False, f"request failed: {exc}")
    try:
        reply = parse_reply(result.content)
    except ProtocolError as exc:
        return Check("schema smoke", False, f"unparseable reply: {exc}")
    return Check("schema smoke", True, f"parsed a {reply.action} reply in "
                                       f"{result.latency_seconds:.1f} s")
