"""The investigation agent's tools for one case.

A :class:`CaseToolkit` is built from the case's :class:`Alert` records and
the window start only. It never receives ground truth, labels, the case id,
the phase, the case kind or the variant name, so it cannot reveal them;
``tests/test_agent_tools.py`` also scans every tool output for them.

What the agent sees of an alert (``get_alert``):

- ``alert_id``: an **opaque id** ``al-<hex>``, a salted SHA-256 of the real
  id (the salt is per run and case). Real Wazuh ids start with an epoch
  timestamp, and AMiner ids reveal nothing useful, so neither is shown.
  Any occurrence of a real id inside the record is replaced too.
- ``offset_seconds``: the alert time as seconds from the window start
  (can be negative or past the window end for noise-control alerts that
  were drawn from outside the window). No absolute timestamp is shown.
- detector, detector type, kind, rule id/name, severity, host ip.
- ``evidence``: raw log lines with every absolute time **masked** as
  ``<TIME>`` (:func:`mask_times`), log paths, log time offsets.
- ``raw_alert``: the detector's own record, with values under time-like
  keys turned into offsets (numbers, ISO strings) or masked, and every
  other string time-masked.

Masking replaces spans and never rewrites the rest of a line, so any quote
the agent takes from a masked line that avoids ``<TIME>`` is an exact
substring of the real line and verifies with the existing quote claims.
Field paths in the view (``rule_id``, ``raw_alert.rule.level``,
``evidence.log_lines.0``, ...) are the paths of the real flattened record,
so field-value claims are checked against the real record; claims about
masked or offset values cannot be supported and the prompt says so.

Dropped from the view: scenario, dataset name, source file and line,
id-derivation and selection flags, ``event_ids`` (always empty).

Tools (arguments are a JSON object; errors come back as ``{"error": ...}``
and never raise): ``list_alerts``, ``get_alert``, ``search_alerts``,
``get_raw_log``. Outputs longer than ``max_output_chars`` are truncated
with a marker. Outputs never echo the agent's arguments.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

from app.evaluation.case_scoring import flatten_record
from app.schemas.alert import Alert

TOOL_NAMES = ("list_alerts", "get_alert", "search_alerts", "get_raw_log")
TIME_MASK = "<TIME>"

_MONTH = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
_DAY = r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)"
_TIME_PATTERNS = [
    # ISO 8601 date-time or date: 2022-01-21T00:02:27.000000Z, 2023-11-14 22:15:00+0000, 2022-01-21
    r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?",
    # Apache: 14/Nov/2023:22:15:00 +0000
    rf"\d{{1,2}}/{_MONTH}/\d{{4}}:\d{{2}}:\d{{2}}:\d{{2}}(?: [+-]\d{{4}})?",
    # Suricata fast.log: 11/14/2023-22:15:00.000000
    r"\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}(?:\.\d+)?",
    # syslog / ctime: [Fri ]Jan 21 00:02:27[ 2022]
    rf"(?:{_DAY} )?{_MONTH} +\d{{1,2}} \d{{2}}:\d{{2}}:\d{{2}}(?:\.\d+)?(?: \d{{4}})?",
    # epoch seconds 2001-2033 (audit(1642723347.123:45), ids, counters)
    r"(?<![\d.])1[0-9]{9}(?:\.\d+)?(?![\d])",
]
_TIME_RE = re.compile("|".join(f"(?:{p})" for p in _TIME_PATTERNS))
_TIME_KEY_RE = re.compile(r"time|date", re.IGNORECASE)


def mask_times(text: str) -> str:
    """Replace every absolute date/time in ``text`` with ``<TIME>``; the rest is unchanged."""
    return _TIME_RE.sub(TIME_MASK, text)


def _round(seconds: float) -> float:
    return round(seconds, 3)


class ToolError(Exception):
    pass


class CaseToolkit:
    def __init__(self, alerts: Sequence[Alert], *, window_start: datetime, window_seconds: float,
                 id_salt: str, page_size: int = 25, max_output_chars: int = 6_000,
                 attack: Callable[[dict[str, Any]], str] | None = None):
        self._start = window_start.astimezone(timezone.utc)
        self._window_seconds = window_seconds
        self._page_size = page_size
        self._max_chars = max_output_chars
        ordered = sorted(alerts, key=lambda a: (a.timestamp, a.source_file, a.source_line))
        self._real_to_opaque = self._opaque_ids([a.alert_id for a in ordered], id_salt)
        self._opaque_to_real = {v: k for k, v in self._real_to_opaque.items()}
        # Longest first so an id that is a prefix of another is not replaced inside it.
        self._real_ids_by_length = sorted(self._real_to_opaque, key=len, reverse=True)
        self._views = [self._view(a) for a in ordered]
        self._by_opaque = {v["alert_id"]: v for v in self._views}
        self._flat = {v["alert_id"]: flatten_record(v) for v in self._views}
        self._tools: dict[str, Callable[[Mapping[str, Any]], Any]] = {
            "list_alerts": self._list_alerts, "get_alert": self._get_alert,
            "search_alerts": self._search_alerts, "get_raw_log": self._get_raw_log,
            "search_attack": self._search_attack}
        # search_attack (C1, m5-v5): the graph's AttackSearchTool; ATT&CK KB content only
        self._attack = attack

    # -- ids ---------------------------------------------------------------
    @staticmethod
    def _opaque_ids(real_ids: Sequence[str], salt: str) -> dict[str, str]:
        if len(set(real_ids)) != len(real_ids):
            raise ValueError("alert ids of a case must be unique")
        for length in range(8, 65, 4):
            ids = {r: "al-" + hashlib.sha256(f"{salt}\x00{r}".encode()).hexdigest()[:length]
                   for r in real_ids}
            if len(set(ids.values())) == len(ids):
                return ids
        raise ValueError("could not derive unique opaque ids")  # pragma: no cover (sha256)

    @property
    def alert_ids(self) -> tuple[str, ...]:
        """Opaque ids in time order."""
        return tuple(v["alert_id"] for v in self._views)

    @property
    def id_map(self) -> dict[str, str]:
        """Opaque id -> real alert id (for the run log and scoring; never shown to the agent)."""
        return dict(self._opaque_to_real)

    def resolve(self, opaque_id: str) -> str | None:
        return self._opaque_to_real.get(opaque_id)

    # -- sanitizing ----------------------------------------------------------
    def _offset(self, value: datetime) -> float:
        return _round((value.astimezone(timezone.utc) - self._start).total_seconds())

    def _text(self, text: str) -> str:
        for real in self._real_ids_by_length:
            if real in text:
                text = text.replace(real, self._real_to_opaque[real])
        return mask_times(text)

    def _time_value(self, value: Any) -> Any:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)) and 1e8 < value < 1e11:  # epoch seconds
            return _round(value - self._start.timestamp())
        if isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return self._text(value)
            if parsed.tzinfo is not None:
                return self._offset(parsed)
            return self._text(value)
        if isinstance(value, list):
            return [self._time_value(v) for v in value]
        return self._sanitize(value)

    def _sanitize(self, value: Any, key: str = "") -> Any:
        if _TIME_KEY_RE.search(key) and not isinstance(value, dict):
            return self._time_value(value)
        if isinstance(value, dict):
            return {k: self._sanitize(v, str(k)) for k, v in value.items()}
        if isinstance(value, list):
            return [self._sanitize(v, key) for v in value]
        if isinstance(value, str):
            return self._text(value)
        return value

    def _view(self, alert: Alert) -> dict[str, Any]:
        ev = alert.evidence
        return {
            "alert_id": self._real_to_opaque[alert.alert_id],
            "offset_seconds": self._offset(alert.timestamp),
            "detector": alert.detector.value,
            "detector_type": alert.detector_type.value,
            "kind": alert.kind.value,
            "rule_id": None if alert.rule_id is None else self._text(alert.rule_id),
            "rule_name": None if alert.rule_name is None else self._text(alert.rule_name),
            "severity": alert.severity,
            "host_ip": None if alert.host_ip is None else str(alert.host_ip),
            "evidence": {
                "log_lines": [self._text(line) for line in ev.log_lines],
                "log_paths": [self._text(p) for p in ev.log_paths],
                "log_offsets_seconds": [self._offset(t) for t in ev.log_timestamps],
            },
            "raw_alert": self._sanitize(alert.raw_alert),
        }

    # -- the agent's view of the case ------------------------------------------
    def brief(self, final: bool = True) -> str:
        # final=False: graph agents that end with a note or a route (pilot gate 2026-11-13)
        counts = Counter(v["detector"] for v in self._views)
        detectors = ", ".join(f"{d}: {n}" for d, n in sorted(counts.items())) or "none"
        return (f"Case window length: {self._window_seconds:.0f} seconds. Alerts available: "
                f"{len(self._views)} ({detectors}). Times are offsets in seconds from the window "
                f"start; absolute dates and times are masked as {TIME_MASK}. Use the tools to "
                + ("investigate, then give your final JSON answer." if final else "investigate."))

    def call(self, name: str, arguments: Mapping[str, Any]) -> str:
        tool = self._tools.get(name)
        try:
            if tool is None:
                raise ToolError(f"unknown tool {name!r}; available: {', '.join(self.tool_names)}")
            if not isinstance(arguments, Mapping):
                raise ToolError("arguments must be a JSON object")
            result = tool(arguments)
        except ToolError as exc:
            result = {"error": str(exc)}
        text = json.dumps(result, ensure_ascii=False)
        if len(text) > self._max_chars:
            text = text[: self._max_chars] + f"\n[output truncated at {self._max_chars} characters]"
        return text

    @property
    def tool_names(self) -> tuple[str, ...]:
        """Tools this toolkit answers: the four case tools plus search_attack (single agent, m5-v5)."""
        return (*TOOL_NAMES, "search_attack")

    def _search_attack(self, arguments: Mapping[str, Any]) -> Any:
        if self._attack is None:
            return {"techniques": [], "note": "ATT&CK retrieval is not available"}
        return json.loads(self._attack(dict(arguments)))

    # -- tools -------------------------------------------------------------------
    @staticmethod
    def _check_keys(arguments: Mapping[str, Any], allowed: set[str], required: set[str] = set()) -> None:
        unexpected = sorted(set(arguments) - allowed)
        if unexpected:
            raise ToolError(f"unexpected argument(s): {', '.join(unexpected)}; "
                            f"allowed: {', '.join(sorted(allowed))}")
        missing = sorted(required - set(arguments))
        if missing:
            raise ToolError(f"missing argument(s): {', '.join(missing)}")

    @staticmethod
    def _summary(view: Mapping[str, Any]) -> dict[str, Any]:
        keys = ("alert_id", "offset_seconds", "detector", "rule_id", "rule_name", "severity", "host_ip")
        return {k: view[k] for k in keys}

    def _page(self, views: Sequence[Mapping[str, Any]], arguments: Mapping[str, Any]) -> dict[str, Any]:
        page = arguments.get("page", 1)
        if isinstance(page, bool) or not isinstance(page, int) or page < 1:
            raise ToolError("page must be an integer >= 1")
        lo = (page - 1) * self._page_size
        chunk = views[lo: lo + self._page_size]
        return {"total": len(views), "page": page, "page_size": self._page_size,
                "has_more": lo + self._page_size < len(views),
                "alerts": [self._summary(v) for v in chunk]}

    def _number(self, arguments: Mapping[str, Any], key: str) -> float | None:
        value = arguments.get(key)
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ToolError(f"{key} must be a number")
        return float(value)

    def _list_alerts(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        self._check_keys(arguments, {"detector", "rule_id", "min_severity", "offset_min",
                                     "offset_max", "page"})
        detector, rule_id = arguments.get("detector"), arguments.get("rule_id")
        min_severity = self._number(arguments, "min_severity")
        lo, hi = self._number(arguments, "offset_min"), self._number(arguments, "offset_max")
        views = [v for v in self._views
                 if (detector is None or v["detector"] == detector)
                 and (rule_id is None or v["rule_id"] == str(rule_id))
                 and (min_severity is None or (v["severity"] is not None and v["severity"] >= min_severity))
                 and (lo is None or v["offset_seconds"] >= lo)
                 and (hi is None or v["offset_seconds"] <= hi)]
        return self._page(views, arguments)

    def _lookup(self, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        self._check_keys(arguments, {"alert_id"}, {"alert_id"})
        view = self._by_opaque.get(str(arguments["alert_id"]))
        if view is None:
            raise ToolError("unknown alert id; use an alert_id returned by list_alerts or search_alerts")
        return view

    def _get_alert(self, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._lookup(arguments)

    def _get_raw_log(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        view = self._lookup(arguments)
        return {"alert_id": view["alert_id"], **view["evidence"]}

    def _search_alerts(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        self._check_keys(arguments, {"text", "field", "page"}, {"text"})
        text, field = arguments["text"], arguments.get("field")
        if not isinstance(text, str) or not text:
            raise ToolError("text must be a non-empty string")
        if field is not None and not isinstance(field, str):
            raise ToolError("field must be a dotted field path, e.g. rule_name or raw_alert.rule.level")
        needle = text.casefold()

        def hit(flat: Mapping[str, str]) -> bool:
            if field is not None:
                values = [v for k, v in flat.items() if k == field or k.startswith(field + ".")]
            else:
                values = list(flat.values())
            return any(needle in v.casefold() for v in values)

        return self._page([v for v in self._views if hit(self._flat[v["alert_id"]])], arguments)
