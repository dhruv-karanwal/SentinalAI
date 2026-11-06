"""Model endpoint and agent budget settings.

Both live in ``experiments/config/study.json`` (sections ``model`` and
``agent``) so a run's settings are versioned with the code; the endpoint
can be overridden from the environment (``SENTINEL_LLM_BASE_URL``,
``SENTINEL_LLM_MODEL``) so a local server can be tried without editing the
committed file. API keys are read **only** from the environment variable
named by ``model.api_key_env``; they are never stored in the config, never
written into run manifests and never logged.

No endpoint is configured in the committed file: until one is, the agent
runs only with the scripted :class:`app.agent.client.FakeClient` (tests,
``--fake-responses``) or in ``--dry-run`` mode.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from app.study.config import DEFAULT_STUDY_CONFIG

ENV_BASE_URL = "SENTINEL_LLM_BASE_URL"
ENV_MODEL = "SENTINEL_LLM_MODEL"


@dataclass(frozen=True)
class ModelConfig:
    """An OpenAI-compatible chat-completions endpoint (Ollama, llama.cpp, vLLM, hosted APIs)."""

    base_url: str | None
    model: str | None
    temperature: float = 0.0
    max_tokens: int = 1024  # per request (completion tokens)
    timeout_seconds: float = 120.0
    max_retries: int = 1  # extra attempts after a failed request; never more
    api_key_env: str = "SENTINEL_LLM_API_KEY"
    price_input_per_million: float = 0.0  # USD; 0 for a local model
    price_output_per_million: float = 0.0

    @property
    def configured(self) -> bool:
        return bool(self.base_url) and bool(self.model)

    def public(self) -> dict[str, Any]:
        """Settings safe to write into a manifest (no key: only the variable's name)."""
        return asdict(self)


@dataclass(frozen=True)
class AgentConfig:
    """Per-case and per-run budgets of the single tool-using agent."""

    max_tool_calls: int = 12  # per case
    max_tokens_per_case: int = 40_000  # input + output, all requests of a case
    max_tool_output_chars: int = 6_000  # longer tool outputs are truncated
    list_page_size: int = 25
    repair_retries: int = 1  # at most one repair retry per case for unparseable output
    run_token_budget: int = 200_000  # a run whose token bound exceeds this needs --confirm


@dataclass(frozen=True)
class AgentSettings:
    model: ModelConfig
    agent: AgentConfig


def _number(data: Mapping[str, Any], key: str, default: float, minimum: float,
            *, integer: bool = False, maximum: float | None = None) -> Any:
    value = data.get(key, default)
    ok = isinstance(value, int) if integer else isinstance(value, (int, float))
    if isinstance(value, bool) or not ok or value < minimum or (maximum is not None and value > maximum):
        bound = f">= {minimum}" + (f" and <= {maximum}" if maximum is not None else "")
        raise ValueError(f"{key} must be a{'n integer' if integer else ' number'} {bound}, got {value!r}")
    return value


def _optional_text(data: Mapping[str, Any], key: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"model.{key} must be a non-empty string or null")
    return value.strip()


def load_agent_settings(path: str | Path = DEFAULT_STUDY_CONFIG,
                        env: Mapping[str, str] | None = None) -> AgentSettings:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    model_data: dict[str, Any] = data.get("model", {})
    agent_data: dict[str, Any] = data.get("agent", {})
    if "api_key" in model_data:
        raise ValueError("model.api_key must not be in the config; put the key in the "
                         "environment variable named by model.api_key_env")
    key_env = model_data.get("api_key_env", "SENTINEL_LLM_API_KEY")
    if not isinstance(key_env, str) or not key_env:
        raise ValueError("model.api_key_env must be an environment variable name")
    model = ModelConfig(
        base_url=_optional_text(model_data, "base_url"),
        model=_optional_text(model_data, "model"),
        temperature=float(_number(model_data, "temperature", 0.0, 0.0, maximum=2.0)),
        max_tokens=_number(model_data, "max_tokens", 1024, 1, integer=True),
        timeout_seconds=float(_number(model_data, "timeout_seconds", 120.0, 1.0)),
        max_retries=_number(model_data, "max_retries", 1, 0, integer=True, maximum=3),
        api_key_env=key_env,
        price_input_per_million=float(_number(model_data, "price_input_per_million", 0.0, 0.0)),
        price_output_per_million=float(_number(model_data, "price_output_per_million", 0.0, 0.0)),
    )
    environ = os.environ if env is None else env
    overrides: dict[str, Any] = {}
    if environ.get(ENV_BASE_URL):
        overrides["base_url"] = environ[ENV_BASE_URL].strip()
    if environ.get(ENV_MODEL):
        overrides["model"] = environ[ENV_MODEL].strip()
    if overrides:
        model = replace(model, **overrides)
    agent = AgentConfig(
        max_tool_calls=_number(agent_data, "max_tool_calls", 12, 0, integer=True),
        max_tokens_per_case=_number(agent_data, "max_tokens_per_case", 40_000, 1, integer=True),
        max_tool_output_chars=_number(agent_data, "max_tool_output_chars", 6_000, 200, integer=True),
        list_page_size=_number(agent_data, "list_page_size", 25, 1, integer=True),
        repair_retries=_number(agent_data, "repair_retries", 1, 0, integer=True, maximum=1),
        run_token_budget=_number(agent_data, "run_token_budget", 200_000, 1, integer=True),
    )
    return AgentSettings(model, agent)


def api_key(model: ModelConfig, env: Mapping[str, str] | None = None) -> str | None:
    """The API key from the environment, or None (local servers need none)."""
    value = (os.environ if env is None else env).get(model.api_key_env)
    return value or None
