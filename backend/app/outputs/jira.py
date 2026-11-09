"""Jira adapter: a **disabled stub** (Wave D; first in the cut order after the copilot).

No Jira instance or API token is approved, so :meth:`JiraAdapter.create_issue`
always raises :class:`JiraDisabled` and nothing is sent anywhere. The
sample payload shows the shape a real adapter would post; it is SYNTHETIC
(``.example`` host, ``EXAMPLE`` project) and labelled so.
"""

from __future__ import annotations

from typing import Any


class JiraDisabled(RuntimeError):
    """The Jira adapter is a disabled stub; no request is ever made."""


class JiraAdapter:
    enabled = False
    base_url = "https://jira.example"  # placeholder, never contacted

    def sample_payload(self) -> dict[str, Any]:
        return {
            "fields": {"project": {"key": "EXAMPLE"}, "issuetype": {"name": "Incident"},
                       "summary": "SYNTHETIC: SentinelAI incident inc-000000 (severity High)",
                       "description": "SYNTHETIC sample payload; not real data."},
            "labels": ["SYNTHETIC"],
        }

    def create_issue(self, payload: dict[str, Any]) -> dict[str, Any]:
        raise JiraDisabled("the Jira adapter is a disabled stub (no instance or token approved)")
