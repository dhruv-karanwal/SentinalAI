"""Chat-completions clients: an OpenAI-compatible HTTP client and a scripted fake.

One wire format covers local servers (Ollama's ``/v1``, llama.cpp server,
vLLM) and hosted OpenAI-compatible APIs, so the study can swap models
without code changes. The client uses only the standard library
(``urllib``): the request is a single JSON POST, which does not justify a
dependency.

Rules:

- The API key is passed in by the caller (read from the environment, see
  app.agent.config) and only ever placed in the ``Authorization`` header.
  It is not stored in ``repr``, error messages or results.
- A failed request is retried at most ``ModelConfig.max_retries`` times,
  and only for retryable failures (timeouts, connection errors, HTTP 429
  and 5xx). Other HTTP errors fail at once.
- Token counts come from the response's ``usage`` when present; otherwise
  they are estimated (:func:`estimate_tokens`) and ``usage_reported`` is
  false, so a run manifest never presents an estimate as a measurement.

:class:`FakeClient` returns scripted replies (strings, callables of the
messages, or exceptions to raise) and is what every test uses. Tests never
touch the network.
"""

from __future__ import annotations

import json
import math
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from app.agent.config import ModelConfig

Message = Mapping[str, str]


def estimate_tokens(text: str) -> int:
    """Rough token count, ~4 characters per token (only when no usage is reported)."""
    return math.ceil(len(text) / 4)


def estimate_messages_tokens(messages: Sequence[Message]) -> int:
    return sum(estimate_tokens(m.get("content", "")) for m in messages)


@dataclass(frozen=True)
class ChatResult:
    content: str
    input_tokens: int
    output_tokens: int
    usage_reported: bool
    latency_seconds: float
    finish_reason: str | None = None
    model: str | None = None
    attempts: int = 1


class ModelRequestError(Exception):
    """The model request failed (after the allowed retries)."""


class TransportError(Exception):
    """One HTTP attempt failed; ``retryable`` says whether another attempt may help."""

    def __init__(self, message: str, *, retryable: bool):
        super().__init__(message)
        self.retryable = retryable


class ChatClient(Protocol):
    model_id: str

    def chat(self, messages: Sequence[Message], *, max_tokens: int,
             temperature: float) -> ChatResult: ...


Transport = Callable[[str, bytes, dict[str, str], float], bytes]


def urllib_transport(url: str, body: bytes, headers: dict[str, str], timeout: float) -> bytes:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (configured URL)
            data: bytes = response.read()
            return data
    except urllib.error.HTTPError as exc:
        raise TransportError(f"HTTP {exc.code}", retryable=exc.code == 429 or exc.code >= 500) from None
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        reason = getattr(exc, "reason", exc)
        raise TransportError(f"connection failed: {type(reason).__name__}", retryable=True) from None


class OpenAICompatibleClient:
    """POST ``{base_url}/chat/completions`` with ``model``, ``messages``, ``temperature``, ``max_tokens``."""

    def __init__(self, config: ModelConfig, *, api_key: str | None,
                 transport: Transport = urllib_transport):
        if not config.configured or config.base_url is None or config.model is None:
            raise ValueError("no model endpoint configured (model.base_url and model.model)")
        self._config = config
        self._api_key = api_key
        self._transport = transport
        self._url = config.base_url.rstrip("/") + "/chat/completions"
        self.model_id = config.model

    def __repr__(self) -> str:  # never shows the key
        return f"OpenAICompatibleClient(url={self._url!r}, model={self.model_id!r})"

    def chat(self, messages: Sequence[Message], *, max_tokens: int, temperature: float) -> ChatResult:
        body = json.dumps({"model": self.model_id, "messages": [dict(m) for m in messages],
                           "temperature": temperature, "max_tokens": max_tokens,
                           "stream": False}).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        attempts = 0
        start = time.perf_counter()
        while True:
            attempts += 1
            try:
                raw = self._transport(self._url, body, headers, self._config.timeout_seconds)
                break
            except TransportError as exc:
                if not exc.retryable or attempts > self._config.max_retries:
                    raise ModelRequestError(
                        f"request to {self._url} failed after {attempts} attempt(s): {exc}") from None
        latency = time.perf_counter() - start
        try:
            data = json.loads(raw)
            choice = data["choices"][0]
            content = choice["message"]["content"] or ""
        except (ValueError, KeyError, IndexError, TypeError):
            raise ModelRequestError("malformed response: no choices[0].message.content") from None
        usage = data.get("usage") or {}
        reported = isinstance(usage.get("prompt_tokens"), int) and isinstance(
            usage.get("completion_tokens"), int)
        return ChatResult(
            content=str(content),
            input_tokens=usage["prompt_tokens"] if reported else estimate_messages_tokens(messages),
            output_tokens=usage["completion_tokens"] if reported else estimate_tokens(str(content)),
            usage_reported=reported,
            latency_seconds=latency,
            finish_reason=choice.get("finish_reason"),
            model=data.get("model"),
            attempts=attempts,
        )


Scripted = str | Callable[[list[dict[str, str]]], str] | Exception


class FakeClient:
    """Deterministic scripted replies; token counts are estimates (``usage_reported`` false)."""

    model_id = "fake"

    def __init__(self, script: Sequence[Scripted]):
        self._script = list(script)
        self.calls: list[list[dict[str, str]]] = []

    def chat(self, messages: Sequence[Message], *, max_tokens: int, temperature: float) -> ChatResult:
        copied = [dict(m) for m in messages]
        self.calls.append(copied)
        if not self._script:
            raise ModelRequestError("FakeClient script exhausted")
        step = self._script.pop(0)
        if isinstance(step, Exception):
            raise step
        content = step(copied) if callable(step) else step
        return ChatResult(content=content, input_tokens=estimate_messages_tokens(copied),
                          output_tokens=estimate_tokens(content), usage_reported=False,
                          latency_seconds=0.0, finish_reason="stop", model="fake")
