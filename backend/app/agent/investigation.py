"""Product investigations (C2, 2026-11-15): run the study's agents on a stored incident.

Reuses the study code unchanged: the single agent (:func:`~app.agent.agent.investigate`, prompt
m5-v5) or the LangGraph supervisor graph (:func:`~app.agent.graph.run_graph`, wave-c-v2), the
same :class:`CaseToolkit` view (opaque ids, time offsets, ``<TIME>`` masks, no labels), the same
budgets from study.json and the same evidence verifier. Investigations are platform outputs,
never study results.

The result separates what the analyst may trust from what the model said:

- ``observed``: claims that survived the verifier (exact field values / log quotes of cited alerts);
- ``detections``: detector, rule and ATT&CK ids of the verified cited alerts (deterministic mapping);
- ``knowledge``: techniques the agents retrieved with ``search_attack`` (ATT&CK KB content);
- ``hypotheses``: the model's finding summaries (free text, **not verified**);
- ``conclusion``: verdict plus the verified citations; ``verified`` is False when the run failed or
  nothing the model cited survived the verifier;
- ``recommendations``: playbook rows for the ATT&CK ids of the verified evidence
  (:func:`app.outputs.playbooks.recommend`); state-changing ones need a human approval.

Log lines and alert text are untrusted: they reach the model only as tool output, the agents have
only read-only tools (no approval, report or action tool exists on this path), and nothing in a
reply can change approval state. ``tests/test_investigation.py`` checks this with injected text.

``steps`` is built from the transcript without system prompts: per node, the model's replies and the
tool results it received. Opaque ids are mapped back to real alert ids with ``id_map``.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Sequence
from typing import Any

from app.agent.agent import CaseRun, investigate
from app.agent.client import ChatClient
from app.agent.config import AgentSettings
from app.agent.graph import GRAPH_PROMPT_VERSION, GraphRun, GraphSettings, run_graph
from app.agent.multi_tools import CaseMemory, MultiAgentToolkit, session_id_for
from app.agent.protocol import PROMPT_VERSION
from app.agent.rag_tool import AttackSearchTool, Retriever
from app.agent.tools import CaseToolkit
from app.agent.verifier import verify_answer
from app.intel.attack import technique_ids
from app.outputs.playbooks import recommend
from app.schemas.alert import Alert

WORKFLOWS = ("single", "graph")
MAX_STEP_CHARS = 4_000


def _kit(alerts: Sequence[Alert], settings: AgentSettings, salt: str,
         attack: AttackSearchTool | None) -> CaseToolkit:
    span = (alerts[-1].timestamp - alerts[0].timestamp).total_seconds()
    return CaseToolkit(alerts, window_start=alerts[0].timestamp, window_seconds=max(1.0, span),
                       id_salt=hashlib.sha256(salt.encode()).hexdigest()[:16],
                       page_size=settings.agent.list_page_size,
                       max_output_chars=settings.agent.max_tool_output_chars, attack=attack)


def _steps(transcript: Sequence[dict[str, str]], workflow: str) -> list[dict[str, Any]]:
    """Per node: replies and tool results, no system prompts. Single agent = one node."""
    steps: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None if workflow == "graph" else {"node": "single_agent",
                                                                     "events": []}
    if current is not None:
        steps.append(current)
    for m in transcript:
        role, content = m.get("role"), str(m.get("content", ""))
        if role == "node":
            current = {"node": content, "events": []}
            steps.append(current)
            continue
        if role == "system" or current is None:
            continue
        if role == "assistant":
            event: dict[str, Any] = {"type": "reply", "text": content[:MAX_STEP_CHARS]}
            try:
                parsed = json.loads(content)
                if isinstance(parsed, dict):
                    event["action"] = parsed.get("action")
                    if parsed.get("action") == "call_tool":
                        event["tool"] = parsed.get("tool")
                        event["arguments"] = parsed.get("arguments")
                    if parsed.get("action") == "route":
                        event["agent"] = parsed.get("agent")
            except json.JSONDecodeError:
                event["action"] = "unparseable"
            current["events"].append(event)
        elif content.startswith("TOOL RESULT ("):
            tool = content[len("TOOL RESULT ("):content.index(")")]
            current["events"].append({"type": "tool_result", "tool": tool,
                                      "text": content.split("\n", 1)[-1][:MAX_STEP_CHARS]})
        else:
            current["events"].append({"type": "message", "text": content[:MAX_STEP_CHARS]})
    # A node seen twice (the graph revisits agents) keeps its own entry, in order.
    return steps


def _retrieved(steps: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for s in steps:
        for e in s["events"]:
            if e["type"] != "tool_result" or e["tool"] != "search_attack":
                continue
            try:
                body = json.loads(e["text"])
            except json.JSONDecodeError:
                continue
            for t in body.get("techniques", []) if isinstance(body, dict) else []:
                tid = str(t.get("technique_id"))
                row = seen.setdefault(tid, {"technique_id": tid, "name": t.get("name"),
                                            "tactics": t.get("tactics", []), "excerpt": t.get("excerpt"),
                                            "retrieved_by": []})
                if s["node"] not in row["retrieved_by"]:
                    row["retrieved_by"].append(s["node"])
    return list(seen.values())


def run_investigation(client: ChatClient, alerts: Sequence[Alert], settings: AgentSettings, *,
                      workflow: str, salt: str, retriever: Retriever | None = None,
                      graph: GraphSettings = GraphSettings()) -> dict[str, Any]:
    if workflow not in WORKFLOWS:
        raise ValueError(f"workflow must be one of {', '.join(WORKFLOWS)}")
    if not alerts:
        raise ValueError("the incident has no stored alerts")
    ordered = sorted(alerts, key=lambda a: (a.timestamp, a.source_file, a.source_line))
    attack = AttackSearchTool(retriever) if retriever is not None else None
    kit = _kit(ordered, settings, f"investigation:{workflow}:{salt}", attack)
    started = time.perf_counter()
    run: CaseRun
    notes: list[dict[str, Any]] = []
    trace: list[str] = []
    if workflow == "single":
        run = investigate(client, kit, settings.agent, settings.model)
        raw_cited, raw_claims = run.cited_alert_ids, run.claims
        prompt_version = PROMPT_VERSION
    else:
        memory = CaseMemory(session_id_for(f"investigation:{salt}"))
        g: GraphRun = run_graph(client, MultiAgentToolkit(kit, memory, attack), ordered,
                                settings.agent, settings.model, graph)
        run, raw_cited, raw_claims = g, g.raw_cited_alert_ids, g.raw_claims
        notes, trace = memory.recall(), list(g.trace)
        prompt_version = GRAPH_PROMPT_VERSION
    checked = verify_answer(raw_cited, raw_claims, ordered)
    by_id = {a.alert_id: a for a in ordered}
    verified_alerts = [by_id[i] for i in checked.cited if i in by_id]
    techniques = sorted({t for a in verified_alerts for t in technique_ids(a.detector.value, a.raw_alert)})
    steps = _steps(run.transcript, workflow)
    findings = (run.final or {}).get("findings", []) if run.status == "ok" else []
    verified = run.status == "ok" and bool(checked.cited or run.verdict == "benign")
    return {
        "workflow": workflow, "status": run.status, "parse_status": run.parse_status,
        "prompt_version": prompt_version, "error": run.error,
        "conclusion": {"verdict": run.verdict if run.status == "ok" else None, "verified": verified,
                       "cited_alert_ids": checked.cited,
                       "note": ("verdict and citations after the evidence verifier" if verified else
                                "not verified: the run did not finish, or no cited alert survived "
                                "the verifier")},
        "observed": [{"record_id": c.record_id, "kind": c.kind, "field": c.field, "value": c.value}
                     for c in checked.claims],
        "detections": [{"alert_id": a.alert_id, "detector": a.detector.value, "rule_id": a.rule_id,
                        "rule_name": a.rule_name, "severity": a.severity,
                        "techniques": technique_ids(a.detector.value, a.raw_alert)}
                       for a in verified_alerts],
        "knowledge": _retrieved(steps),
        "hypotheses": [{"summary": str(f.get("summary", "")), "status": "unverified model text"}
                       for f in findings],
        "verification": {**checked.summary(), "dropped_citations": list(checked.dropped_citations),
                         "dropped_claims": list(checked.dropped_claims)},
        "recommendations": recommend(techniques) if verified else [],
        "steps": steps, "trace": trace, "notes": notes, "id_map": kit.id_map,
        "usage": {"requests": run.requests, "tool_calls": run.tool_calls, "repairs": run.repairs,
                  "input_tokens": run.input_tokens, "output_tokens": run.output_tokens,
                  "wall_seconds": round(time.perf_counter() - started, 3)},
        "retrieval": retriever is not None,
        "note": "platform investigation output, not a study result; hypotheses are unverified",
    }
