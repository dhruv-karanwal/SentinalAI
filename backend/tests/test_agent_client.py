"""Model client and agent settings. No network: the HTTP transport is injected."""

import json
from pathlib import Path

import pytest

from app.agent.client import (
    ChatResult,
    FakeClient,
    ModelRequestError,
    OpenAICompatibleClient,
    TransportError,
    estimate_tokens,
)
from app.agent.config import ModelConfig, load_agent_settings
from app.study.config import DEFAULT_STUDY_CONFIG

MODEL = ModelConfig(base_url="http://localhost:11434/v1/", model="test-model", max_retries=1,
                    timeout_seconds=5)
OK_BODY = {"choices": [{"message": {"role": "assistant", "content": "{\"action\": \"final\"}"},
                        "finish_reason": "stop"}],
           "usage": {"prompt_tokens": 11, "completion_tokens": 7}, "model": "test-model"}


class Transport:
    def __init__(self, replies: list[object]):
        self.replies = replies
        self.calls: list[tuple[str, dict[str, object], dict[str, str], float]] = []

    def __call__(self, url: str, body: bytes, headers: dict[str, str], timeout: float) -> bytes:
        self.calls.append((url, json.loads(body), headers, timeout))
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return json.dumps(reply).encode("utf-8")


def test_request_shape_and_usage() -> None:
    transport = Transport([OK_BODY])
    client = OpenAICompatibleClient(MODEL, api_key=None, transport=transport)
    result = client.chat([{"role": "user", "content": "hi"}], max_tokens=50, temperature=0.0)
    assert isinstance(result, ChatResult)
    assert (result.content, result.input_tokens, result.output_tokens, result.usage_reported) == (
        "{\"action\": \"final\"}", 11, 7, True)
    assert result.finish_reason == "stop" and result.attempts == 1
    url, body, headers, timeout = transport.calls[0]
    assert url == "http://localhost:11434/v1/chat/completions"
    assert body == {"model": "test-model", "messages": [{"role": "user", "content": "hi"}],
                    "temperature": 0.0, "max_tokens": 50, "stream": False}
    assert "Authorization" not in headers and timeout == 5


def test_api_key_goes_only_into_the_header_and_never_into_errors() -> None:
    secret = "sk-test-not-a-real-key"
    transport = Transport([TransportError("HTTP 500", retryable=True),
                           TransportError("HTTP 500", retryable=True)])
    client = OpenAICompatibleClient(MODEL, api_key=secret, transport=transport)
    with pytest.raises(ModelRequestError) as info:
        client.chat([{"role": "user", "content": "hi"}], max_tokens=5, temperature=0.0)
    assert secret not in str(info.value) and secret not in repr(client)
    assert transport.calls[0][2]["Authorization"] == f"Bearer {secret}"
    assert len(transport.calls) == 2  # 1 attempt + max_retries=1, never more


def test_non_retryable_error_is_not_retried() -> None:
    transport = Transport([TransportError("HTTP 400", retryable=False), OK_BODY])
    client = OpenAICompatibleClient(MODEL, api_key=None, transport=transport)
    with pytest.raises(ModelRequestError, match="400"):
        client.chat([{"role": "user", "content": "hi"}], max_tokens=5, temperature=0.0)
    assert len(transport.calls) == 1


def test_retry_then_success_and_missing_usage_is_estimated() -> None:
    body = {"choices": [{"message": {"content": "abcdefgh"}, "finish_reason": "stop"}]}
    transport = Transport([TransportError("timeout", retryable=True), body])
    client = OpenAICompatibleClient(MODEL, api_key=None, transport=transport)
    result = client.chat([{"role": "user", "content": "x" * 40}], max_tokens=5, temperature=0.0)
    assert result.attempts == 2 and not result.usage_reported
    assert result.output_tokens == estimate_tokens("abcdefgh") and result.input_tokens > 0


def test_malformed_response_is_an_error() -> None:
    client = OpenAICompatibleClient(MODEL, api_key=None, transport=Transport([{"nope": 1}]))
    with pytest.raises(ModelRequestError, match="choices"):
        client.chat([{"role": "user", "content": "hi"}], max_tokens=5, temperature=0.0)


def test_unconfigured_model_is_refused() -> None:
    with pytest.raises(ValueError, match="endpoint"):
        OpenAICompatibleClient(ModelConfig(base_url=None, model=None), api_key=None)


def test_fake_client_is_scripted_and_records_calls() -> None:
    fake = FakeClient(["one", lambda messages: f"saw {len(messages)}", ModelRequestError("down")])
    assert fake.chat([{"role": "user", "content": "a"}], max_tokens=5, temperature=0.0).content == "one"
    second = fake.chat([{"role": "user", "content": "a"}, {"role": "user", "content": "b"}],
                       max_tokens=5, temperature=0.0)
    assert second.content == "saw 2" and second.input_tokens == estimate_tokens("a") + estimate_tokens("b")
    with pytest.raises(ModelRequestError):
        fake.chat([], max_tokens=5, temperature=0.0)
    with pytest.raises(ModelRequestError, match="exhausted"):
        fake.chat([], max_tokens=5, temperature=0.0)
    assert len(fake.calls) == 4 and fake.model_id == "fake"


def test_committed_settings_have_no_endpoint_and_no_key(tmp_path: Path) -> None:
    settings = load_agent_settings(env={})
    assert not settings.model.configured  # FakeClient only until the user configures one
    assert settings.model.temperature == 0.0
    raw = json.loads(DEFAULT_STUDY_CONFIG.read_text(encoding="utf-8"))
    assert "api_key" not in raw["model"]
    env = {"SENTINEL_LLM_BASE_URL": "http://127.0.0.1:8080/v1", "SENTINEL_LLM_MODEL": "m"}
    assert load_agent_settings(env=env).model.configured
    raw["model"]["api_key"] = "sk-123"
    bad = tmp_path / "study.json"
    bad.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="api_key"):
        load_agent_settings(bad, env={})
    raw["model"].pop("api_key")
    raw["agent"]["repair_retries"] = 2
    bad.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="repair_retries"):
        load_agent_settings(bad, env={})
