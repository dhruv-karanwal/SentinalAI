"""Playbook-style recommendations from ATT&CK technique ids (Wave D). Deterministic, no LLM.

Each row matches a technique id by prefix (``T1110`` matches ``T1110.001``)
and proposes response actions. The technique ids come only from the B1
deterministic mapping (Wazuh native ``rule.mitre.id`` and ``RULE_TABLE``),
so a recommendation is never guessed from free text.

Actions in :data:`STATE_CHANGING` change something outside SentinelAI
(firewall, host, account). They are **suggestions**: an action runs only
through the approval workflow (:mod:`app.outputs.approvals`), and in this
build the executor is simulated. ``manual_review`` changes nothing and needs
no approval. When no row matches, the only recommendation is a manual review.

Rows are general SOC practice (contain the source, the host or the account
the technique points at); they are written for the demo and are not
claimed to be complete or site-specific.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

STATE_CHANGING = frozenset({"block_source_ip", "isolate_host", "lock_account", "reset_credentials"})
ACTION_TYPES: tuple[str, ...] = ("block_source_ip", "isolate_host", "lock_account", "reset_credentials",
                                 "manual_review")


@dataclass(frozen=True)
class PlaybookRow:
    prefix: str
    name: str
    actions: tuple[tuple[str, str], ...]  # (action_type, title)


PLAYBOOK: tuple[PlaybookRow, ...] = (
    PlaybookRow("T1110", "Brute Force", (
        ("lock_account", "Lock or rate-limit the targeted account"),
        ("manual_review", "Check the authentication log for a success after the failures"))),
    PlaybookRow("T1078", "Valid Accounts", (
        ("reset_credentials", "Reset the credentials of the account that logged in"),
        ("manual_review", "Confirm with the account owner that the logins were theirs"))),
    PlaybookRow("T1505.003", "Web Shell", (
        ("isolate_host", "Isolate the web server from the network"),
        ("manual_review", "Look for unknown files in the web root and their upload requests"))),
    PlaybookRow("T1190", "Exploit Public-Facing Application", (
        ("block_source_ip", "Block the source address at the perimeter"),
        ("manual_review", "Check the application version and patch level"))),
    PlaybookRow("T1595", "Active Scanning", (
        ("block_source_ip", "Block the scanning source address at the perimeter"),)),
    PlaybookRow("T1046", "Network Service Discovery", (
        ("block_source_ip", "Block the scanning source address"),)),
    PlaybookRow("T1048", "Exfiltration Over Alternative Protocol", (
        ("isolate_host", "Isolate the host sending the data"),
        ("manual_review", "Size the transfer from DNS / network logs"))),
    PlaybookRow("T1068", "Exploitation for Privilege Escalation", (
        ("isolate_host", "Isolate the host"),
        ("manual_review", "List processes started with elevated privileges"))),
    PlaybookRow("T1059", "Command and Scripting Interpreter", (
        ("isolate_host", "Isolate the host running the commands"),)),
    PlaybookRow("T1003", "OS Credential Dumping", (
        ("reset_credentials", "Reset every credential stored on the host"),)),
)

FALLBACK = ("manual_review", "No playbook row matches the mapped techniques: review manually")


def _matches(prefix: str, technique: str) -> bool:
    return technique == prefix or technique.startswith(prefix + ".")


def recommend(technique_ids: Iterable[str]) -> list[dict[str, Any]]:
    """Recommendations in playbook order, one per (action_type, title), with the techniques behind them."""
    ids = sorted(set(technique_ids))
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for row in PLAYBOOK:
        hits = [t for t in ids if _matches(row.prefix, t)]
        if not hits:
            continue
        for action, title in row.actions:
            rec = out.setdefault((action, title), {
                "action_type": action, "title": title, "playbook": f"{row.prefix} {row.name}",
                "techniques": [], "requires_approval": action in STATE_CHANGING})
            rec["techniques"] = sorted(set(rec["techniques"]) | set(hits))
    if not out:
        action, title = FALLBACK
        return [{"action_type": action, "title": title, "playbook": None, "techniques": [],
                 "requires_approval": False}]
    return list(out.values())
