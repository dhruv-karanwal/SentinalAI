"""Approval workflow and the gated executor (Wave D).

States: ``pending`` -> ``approved`` | ``rejected`` (decided once, by a
reviewer who is not the requester, with a reason), stored in the
``approvals`` table. Every API call that changes an approval is written to
``audit_log`` by the route (the API rule).

**Nothing executes without an approved record:** :meth:`ApprovalService.execute`
refuses anything not ``approved`` and anything already executed. The
executor is **simulated** in this build: it records who executed what and
when, and changes nothing outside SentinelAI (there are no firewall, EDR or
directory connectors). Only playbook actions that change state
(:data:`app.outputs.playbooks.STATE_CHANGING`) can be requested.
"""

from __future__ import annotations

from typing import Any

from app.outputs.playbooks import ACTION_TYPES, STATE_CHANGING
from app.storage.repository import Repository


class ApprovalError(Exception):
    """The workflow forbids this step (own request, not approved, already executed)."""


class ApprovalService:
    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    def request(self, incident_id: str, action: dict[str, Any], requested_by: str) -> int:
        kind = action.get("action_type")
        if kind not in ACTION_TYPES:
            raise ValueError(f"unknown action_type {kind!r}; known: {', '.join(ACTION_TYPES)}")
        if kind not in STATE_CHANGING:
            raise ValueError(f"{kind} changes nothing; it needs no approval")
        target = action.get("target")
        if target is not None and (not isinstance(target, str) or len(target) > 200):
            raise ValueError("target must be a string of at most 200 characters")
        extra = set(action) - {"action_type", "target", "note"}
        if extra:
            raise ValueError(f"unexpected action keys: {sorted(extra)}")
        if self.repo.get_incident(incident_id) is None:
            raise KeyError(f"no incident {incident_id}")
        return self.repo.request_approval(incident_id, dict(action), requested_by)

    def decide(self, approval_id: int, approved: bool, reviewer: str, reason: str) -> None:
        row = self.repo.get_approval(approval_id)
        if row is None:
            raise KeyError(f"no approval {approval_id}")
        if row["requested_by"] == reviewer:
            raise ApprovalError("a reviewer cannot decide their own request")
        self.repo.decide_approval(approval_id, approved, reviewer, reason)

    def execute(self, approval_id: int, executor: str) -> dict[str, Any]:
        row = self.repo.get_approval(approval_id)
        if row is None:
            raise KeyError(f"no approval {approval_id}")
        if row["status"] != "approved":
            raise ApprovalError(f"approval {approval_id} is not approved (status {row['status']}); "
                                "nothing executes without an approved record")
        if row.get("executed_utc") is not None:
            raise ApprovalError(f"approval {approval_id} was already executed")
        if not self.repo.mark_executed(approval_id, executor):
            raise ApprovalError(f"approval {approval_id} was already executed")
        return {"approval_id": approval_id, "executed": True, "mode": "simulated",
                "action": row["action"], "incident_id": row["incident_id"], "executed_by": executor,
                "note": "simulated: no connector exists, nothing outside SentinelAI was changed"}
