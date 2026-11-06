"""Prometheus metrics (own registry, so tests and multiple apps do not collide).

API: request count and latency by method / route template / status.
Agents: tokens in/out, requests, latency, parse failures by agent name,
fed from run records (``record_case_run``).
"""

from __future__ import annotations

from typing import Any

from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest


class Metrics:
    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.requests = Counter("sentinel_http_requests_total", "HTTP requests",
                                ["method", "path", "status"], registry=self.registry)
        self.latency = Histogram("sentinel_http_request_seconds", "HTTP request latency",
                                 ["method", "path"], registry=self.registry)
        self.tokens = Counter("sentinel_agent_tokens_total", "LLM tokens", ["agent", "direction"],
                              registry=self.registry)
        self.agent_requests = Counter("sentinel_agent_requests_total", "LLM requests", ["agent"],
                                      registry=self.registry)
        self.agent_latency = Histogram("sentinel_agent_case_seconds", "LLM latency per case",
                                       ["agent"], registry=self.registry)
        self.parse_failures = Counter("sentinel_agent_parse_failures_total", "unparseable replies",
                                      ["agent"], registry=self.registry)
        self.unsupported = Counter("sentinel_verifier_dropped_claims_total",
                                   "claims dropped by the evidence verifier", ["agent"],
                                   registry=self.registry)

    @staticmethod
    def _route(path: str) -> str:
        # keep label cardinality bounded: ids become {id}
        parts = path.strip("/").split("/")
        return "/" + "/".join(p if i == 0 or p in {"search", "stats", "login", "me", "pdf", "csv",
                                                    "decide", "ask", "pending"} else "{id}"
                              for i, p in enumerate(parts)) if parts != [""] else "/"

    def observe_request(self, method: str, path: str, status: int, seconds: float) -> None:
        route = self._route(path)
        self.requests.labels(method, route, str(status)).inc()
        self.latency.labels(method, route).observe(seconds)

    def record_case_run(self, agent: str, record: dict[str, Any]) -> None:
        self.tokens.labels(agent, "in").inc(record.get("input_tokens", 0))
        self.tokens.labels(agent, "out").inc(record.get("output_tokens", 0))
        self.agent_requests.labels(agent).inc(record.get("requests", 0))
        self.agent_latency.labels(agent).observe(record.get("latency_seconds", 0.0))
        if record.get("parse_status") == "unparseable":
            self.parse_failures.labels(agent).inc()
        self.unsupported.labels(agent).inc(record.get("dropped_claims", 0))

    def render(self) -> str:
        return generate_latest(self.registry).decode()
