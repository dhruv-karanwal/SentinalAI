"""C1 (2026-11-15, option a): the single agent gets the graph's ATT&CK search (prompt m5-v5).

The m5-v4 text is kept byte for byte (pinned sha256) so earlier runs stay reproducible; the graph
prompts stay wave-c-v2. Both arms reach ATT&CK through the same ``AttackSearchTool``; shared
notes (recall_notes / search_notes) stay graph-only, as documented in the methodology.
FakeClient and a stub retriever only: no network, no model.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.agent.agent import investigate
from app.agent.client import FakeClient
from app.agent.config import AgentConfig, ModelConfig, load_agent_settings
from app.agent.rag_tool import AttackSearchTool
from app.agent.tools import CaseToolkit
from app.study.variants import AlertPool, build_variants
from tests.test_variants import S2, aminer_id, pool, processed  # noqa: F401  (fixtures)

M5_V4_SHA256 = "c628767b3128a3970462b90bdbc88c5c63cf3d9c1527f04468c464bbfb8791b2"


class StubRetriever:
    def __init__(self) -> None:
        self.queries: list[str] = []

    def search(self, text: str, k: int = 5) -> list[dict[str, Any]]:
        self.queries.append(text)
        return [{"technique_id": "T1110", "name": "Brute Force", "tactics": ["credential-access"],
                 "score": 0.9, "text": "T1110 Brute Force. Adversaries may use brute force."}][:k]


def kit(p: AlertPool, attack: AttackSearchTool | None = None) -> CaseToolkit:
    alerts = list(p.alerts(build_variants(p, seed=7, shuffled_references=())["fused"]))
    return CaseToolkit(alerts, window_start=datetime.fromtimestamp(1700000100, tz=timezone.utc),
                       window_seconds=100.0, id_salt="t", attack=attack)


def test_m5_v4_text_is_preserved_and_m5_v5_is_current() -> None:
    from app.agent.graph import GRAPH_PROMPT_VERSION
    from app.agent.protocol import (PROMPT_VERSION, SINGLE_PROMPTS, SYSTEM_PROMPT,
                                    SYSTEM_PROMPT_M5_V4)
    assert hashlib.sha256(SYSTEM_PROMPT_M5_V4.encode()).hexdigest() == M5_V4_SHA256
    assert PROMPT_VERSION == "m5-v5" and GRAPH_PROMPT_VERSION == "wave-c-v2"
    assert SINGLE_PROMPTS["m5-v4"] == SYSTEM_PROMPT_M5_V4
    assert SINGLE_PROMPTS["m5-v5"] == SYSTEM_PROMPT and SYSTEM_PROMPT != SYSTEM_PROMPT_M5_V4
    assert "search_attack" in SYSTEM_PROMPT and "search_attack" not in SYSTEM_PROMPT_M5_V4
    # m5-v5 = m5-v4 plus the search_attack listing; nothing else changes
    for line in SYSTEM_PROMPT_M5_V4.splitlines():
        if line.startswith("Tools ("):
            continue
        assert line in SYSTEM_PROMPT, line


def test_single_toolkit_search_attack_uses_the_graph_tool(pool: AlertPool) -> None:  # noqa: F811
    retriever = StubRetriever()
    k = kit(pool, AttackSearchTool(retriever))
    out = json.loads(k.call("search_attack", {"text": "many failed logins", "k": 1}))
    assert out["techniques"][0]["technique_id"] == "T1110"
    assert retriever.queries == ["many failed logins"]
    assert "many failed logins" not in json.dumps(out)  # never echoes the query
    assert "search_attack" in k.tool_names


def test_single_toolkit_without_retrieval_says_unavailable(pool: AlertPool) -> None:  # noqa: F811
    out = json.loads(kit(pool).call("search_attack", {"text": "x"}))
    assert out == {"techniques": [], "note": "ATT&CK retrieval is not available"}


def test_agent_loop_runs_search_attack_and_logs_it(pool: AlertPool) -> None:  # noqa: F811
    k = kit(pool, AttackSearchTool(StubRetriever()))
    client = FakeClient([json.dumps({"action": "call_tool", "tool": "search_attack",
                                     "arguments": {"text": "brute force"}}),
                         json.dumps({"action": "final", "verdict": "benign", "findings": []})])
    run = investigate(client, k, AgentConfig(max_tool_calls=3, max_tokens_per_case=50_000),
                      ModelConfig(base_url=None, model=None, max_tokens=200))
    assert run.status == "ok" and run.tool_calls == 1
    assert run.request_log[0]["tool"] == "search_attack"
    assert "T1110" in client.calls[1][-1]["content"]


def test_matched_single_arm_gets_attack_search(processed: Path, samples_dir: Path,  # noqa: F811
                                               tmp_path: Path) -> None:
    from app.agent.matched import run_matched
    from tests.test_agent_runner import prepared
    from tests.test_wave_c_graph import route
    config_path, prep = prepared(processed, samples_dir, tmp_path, limit=1)
    settings = load_agent_settings(config_path)
    retriever = StubRetriever()
    single = FakeClient([json.dumps({"action": "call_tool", "tool": "search_attack",
                                     "arguments": {"text": "scan"}}),
                         json.dumps({"action": "final", "verdict": "benign", "findings": []})])
    graph = FakeClient([route("report_generation"),
                        json.dumps({"action": "final", "verdict": "benign", "findings": []})])
    report = run_matched(prep, settings, {"single": single, "graph": graph},
                         output_dir=tmp_path / "runs", study_config_path=config_path,
                         retriever=retriever, retrieval_mode="hybrid",
                         now=datetime(2026, 11, 15, tzinfo=timezone.utc))
    man = report["manifest"]
    assert man["prompt_versions"] == {"single": "m5-v5", "graph": "wave-c-v2"}
    assert man["tool_access"]["single"] == ["list_alerts", "get_alert", "search_alerts",
                                            "get_raw_log", "search_attack"]
    assert "recall_notes" in man["tool_access"]["graph"]
    assert retriever.queries == ["scan"]
    assert "T1110" in single.calls[1][-1]["content"]

