"""Sigma rule engine over alert evidence log lines (Wave B2).

Why this exists: the AIT-ADS alerts carry the raw log lines that triggered
them (``AlertEvidence.log_lines`` with ``log_paths``). Running the approved
SigmaHQ rules over those lines gives the platform a further rule-based
detector, ``Detector.SIGMA``. It is an **additional source, never a study
variable**: the study variants iterate ``AIT_ADS_DETECTORS`` and leave Sigma
out unless a study config lists it explicitly.

Why only evidence lines: AIT-LDSv2 (the full logs) is not used (user
decision 2026-10-31). Sigma therefore sees only lines another detector
already alerted on; its hits are a re-detection over that evidence, not a
scan of the full logs. Reports say so.

pySigma (2.0.2) parses the rules; it ships no backend for in-process
matching, so this module evaluates ``rule.detection.parsed_condition``
itself: ``ConditionAND`` / ``ConditionOR`` / ``ConditionNOT`` over
``ConditionFieldEqualsValueExpression`` (field matches) and
``ConditionValueExpression`` (keywords).

Log types (chosen by the evidence ``log_path``, then the line must parse)
-------------------------------------------------------------------------
============== =================================================== =========================
log type       paths                                               parser
============== =================================================== =========================
apache_access  ``/var/log/apache2/*access*``, ``/var/log/horde/*access*``  Apache common/combined;
                                                                   ``other_vhosts_access.log``
                                                                   has a ``vhost:port`` prefix
apache_error   ``/var/log/apache2/*error*``, ``/var/log/horde/*error*``    whole line only
auditd         ``/var/log/audit/audit.log``                        ``key=value`` per record
syslog         ``syslog``, ``auth.log``, ``mail.log``, ``mail.info``,   ``Mon DD HH:MM:SS [host]
               ``mail.err``, ``user.log``, ``messages``, ``daemon.log``,  prog[pid]: msg``
               ``kern.log``, ``dnsmasq.log`` (under ``/var/log/``)
============== =================================================== =========================

Every other path (exim mainlog, openvpn, metricbeat JSON, Suricata
fast.log, ...) is *unclassified*: counted, never evaluated.

Field mapping (only fields a log line actually carries)
-------------------------------------------------------
- **webserver** (``category: webserver``) on ``apache_access``:
  ``c-ip`` = %h; ``cs-method``, ``cs-uri-query``, ``cs-uri-stem``,
  ``cs-version`` from the request line %r; ``sc-status`` = %>s;
  ``sc-bytes`` = %b; ``cs-referer`` and ``cs-user-agent`` (combined format
  only). ``cs-uri-query`` is the **whole request target** (path and query),
  because SigmaHQ's webserver rules match path patterns (``/../``,
  ``/wp-admin``) in that field; ``cs-uri-stem`` is the path before ``?``.
  The URI stays exactly as logged (no URL decoding). A request line of
  ``-`` gives no method/URI fields.
- **auditd** (``service: auditd``) on ``auditd``: a line can hold several
  records (``type=AVC ... type=SYSCALL ...``); each record is one event.
  Fields are the record's ``key=value`` pairs (``type`` included), quotes
  stripped; the pairs inside a quoted ``msg='...'`` are added too (first
  occurrence of a key wins). Hex-encoded values (EXECVE ``a0``, PROCTITLE)
  stay hex: decoding would change what the log says.
- **keyword rules** match the keyword as a substring (wildcards honoured)
  of the whole line, case-insensitively:
  ``product: linux`` without service/category and ``service: syslog`` run
  on ``syslog`` lines; ``service: apache`` on ``apache_error`` lines (the
  SigmaHQ apache rules state "collect the error.log file"); any other
  ``service: X`` on ``syslog`` lines whose program tag equals X
  (case-insensitive; e.g. ``sshd``, ``cron``).

Skipped rules, each counted by reason (never guessed into a mapping)
--------------------------------------------------------------------
- ``logsource_not_derivable:<category>``: ``process_creation``,
  ``file_event``, ``network_connection`` (EDR/Sysmon fields such as
  ``Image``/``CommandLine`` are not in these logs) and ``proxy`` (forward
  proxy fields such as a full ``c-uri`` with host; the Apache reverse proxy
  access log is not that).
- ``logsource_not_in_evidence:<service>``: e.g. ``nginx`` (no nginx logs).
- ``field_not_derivable``: a webserver rule naming a field outside the
  mapping above (e.g. ``cs-host``).
- ``unsupported_value``: placeholders, field references, comparisons,
  ``exists`` or other value types this evaluator does not implement.
- ``rule_error``: pySigma could not parse the rule or its condition.

Value semantics: strings (with ``*``/``?`` wildcards and the modifiers
pySigma already folded into them) match the whole field value,
case-insensitively (``SigmaCasedString``: case-sensitive); numbers compare
as their decimal text; ``|re`` uses Python ``re.search`` with the rule's
flags (case-sensitive by default); ``|cidr`` tests IP membership;
``null`` matches a missing or empty field. A field the event lacks never
matches.

Emitted alerts: one ``Alert`` per (rule, source alert) with at least one
matching event; ``alert_id = "sigma-" + sha256(rule id, source alert id)[:32]``
(``alert_id_derived``); time, host, dataset, source file/line copied from the
source alert; evidence = the matching lines and their paths with
``source_alert_id`` = the source alert's id; ``severity`` stays ``None``
(Sigma levels are words and are never mapped onto a number; the level, tags
and status are kept in ``raw_alert["sigma"]``).
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)

from app.schemas.alert import DETECTOR_TYPES, Alert, AlertEvidence, Detector

RULE_SUBDIRS = ("rules/linux", "rules/web")

WEBSERVER_FIELDS = frozenset({"c-ip", "cs-method", "cs-uri-query", "cs-uri-stem", "cs-version",
                              "sc-status", "sc-bytes", "cs-referer", "cs-user-agent"})
NOT_DERIVABLE_CATEGORIES = frozenset({"process_creation", "file_event", "network_connection",
                                      "proxy"})
SYSLOG_FILES = frozenset({"syslog", "auth.log", "mail.log", "mail.info", "mail.err", "user.log",
                          "messages", "daemon.log", "kern.log", "dnsmasq.log"})

_ACCESS = re.compile(
    r'^(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+)(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?')
_VHOST = re.compile(r"^(?P<vhost>\S+) (?P<rest>.*)$")
_SYSLOG = re.compile(r"^(?P<ts>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (?:(?P<host>[^\s:\[]+) )?"
                     r"(?P<prog>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$")
_AUDIT_SPLIT = re.compile(r"(?=(?:^|(?<=\s))type=[A-Z0-9_]+ msg=audit\()")
_KV = re.compile(r"""([A-Za-z0-9_-]+)=("[^"]*"|'[^']*'|\S+)""")


@dataclass(frozen=True)
class LogEvent:
    """One event derived from one evidence log line (auditd: one record)."""

    log_type: str
    line: str
    path: str
    fields: dict[str, str]
    program: str | None = None


def classify_path(path: str | None) -> str | None:
    if not path:
        return None
    p = PurePosixPath(path)
    parent, name = str(p.parent), p.name
    if parent in ("/var/log/apache2", "/var/log/horde"):
        if "access" in name:
            return "apache_access"
        if "error" in name:
            return "apache_error"
        return None
    if path == "/var/log/audit/audit.log":
        return "auditd"
    if parent == "/var/log" and name in SYSLOG_FILES:
        return "syslog"
    return None


def _parse_access(path: str, line: str) -> LogEvent | None:
    text = line
    if PurePosixPath(path).name == "other_vhosts_access.log":
        vm = _VHOST.match(line)
        if vm is None:
            return None
        text = vm.group("rest")
    m = _ACCESS.match(text)
    if m is None:
        return None
    fields = {"c-ip": m.group("ip"), "sc-status": m.group("status"), "sc-bytes": m.group("bytes")}
    parts = m.group("request").split(" ")
    if len(parts) == 3:
        fields["cs-method"], target, fields["cs-version"] = parts
        fields["cs-uri-query"] = target
        fields["cs-uri-stem"] = target.split("?", 1)[0]
    if m.group("referer") is not None:
        fields["cs-referer"] = m.group("referer")
        fields["cs-user-agent"] = m.group("ua")
    return LogEvent("apache_access", line, path, fields)


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _audit_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for key, raw in _KV.findall(text):
        fields.setdefault(key, _unquote(raw))
        if raw.startswith("'"):
            for k, v in _audit_fields(raw[1:-1]).items():
                fields.setdefault(k, v)
    return fields


def _parse_audit(path: str, line: str) -> list[LogEvent]:
    records = [r.strip() for r in _AUDIT_SPLIT.split(line) if r.strip()]
    events = []
    for record in records:
        fields = _audit_fields(record)
        if "type" in fields:
            events.append(LogEvent("auditd", line, path, fields))
    return events


def parse_events(path: str | None, line: str) -> list[LogEvent]:
    """All events of one evidence line ([] when its log type is unknown or it does not parse)."""
    log_type = classify_path(path)
    if log_type is None or path is None:
        return []
    if log_type == "apache_access":
        ev = _parse_access(path, line)
        return [ev] if ev else []
    if log_type == "apache_error":
        return [LogEvent("apache_error", line, path, {})]
    if log_type == "auditd":
        return _parse_audit(path, line)
    m = _SYSLOG.match(line)
    if m is None:
        return []
    return [LogEvent("syslog", line, path, {}, program=m.group("prog"))]


def parse_line(path: str | None, line: str) -> LogEvent | None:
    events = parse_events(path, line)
    return events[0] if events else None


# ---------------------------------------------------------------- rule compilation

class _Unsupported(Exception):
    pass


class _Skip(Exception):
    pass


Matcher = Callable[[LogEvent], bool]


def _wildcard_regex(value: SigmaString, *, anchored: bool) -> str:
    out = []
    for part in value.s:
        if isinstance(part, str):
            out.append(re.escape(part))
        elif part is SpecialChars.WILDCARD_MULTI:
            out.append(".*")
        elif part is SpecialChars.WILDCARD_SINGLE:
            out.append(".")
        else:
            raise _Unsupported("placeholder")
    body = "".join(out)
    return f"^(?:{body})$" if anchored else body


_RE_FLAGS = {SigmaRegularExpressionFlag.IGNORECASE: re.IGNORECASE,
             SigmaRegularExpressionFlag.MULTILINE: re.MULTILINE,
             SigmaRegularExpressionFlag.DOTALL: re.DOTALL}


def _value_test(value: Any) -> Callable[[str | None], bool]:
    if isinstance(value, SigmaNull):
        return lambda v: v is None or v == ""
    if isinstance(value, SigmaCasedString):
        pat = re.compile(_wildcard_regex(value, anchored=True), re.DOTALL)
        return lambda v: v is not None and pat.match(v) is not None
    if isinstance(value, SigmaString):
        if value.contains_placeholder():
            raise _Unsupported("placeholder")
        pat = re.compile(_wildcard_regex(value, anchored=True), re.IGNORECASE | re.DOTALL)
        return lambda v: v is not None and pat.match(v) is not None
    if isinstance(value, SigmaNumber):
        text = str(value.number)
        return lambda v: v is not None and v.strip() == text
    if isinstance(value, SigmaRegularExpression):
        flags = 0
        for f in value.flags:
            flags |= _RE_FLAGS[f]
        rx = re.compile(str(value.regexp), flags)
        return lambda v: v is not None and rx.search(v) is not None
    if isinstance(value, SigmaCIDRExpression):
        net = value.network

        def in_net(v: str | None) -> bool:
            if v is None:
                return False
            try:
                return ipaddress.ip_address(v) in net
            except ValueError:
                return False
        return in_net
    raise _Unsupported(type(value).__name__)


def _keyword_test(value: Any) -> Matcher:
    if isinstance(value, SigmaString) and not value.contains_placeholder():
        flags = re.DOTALL if isinstance(value, SigmaCasedString) else re.IGNORECASE | re.DOTALL
        pat = re.compile(_wildcard_regex(value, anchored=False), flags)
        return lambda ev: pat.search(ev.line) is not None
    if isinstance(value, SigmaNumber):
        text = str(value.number)
        return lambda ev: text in ev.line
    if isinstance(value, SigmaRegularExpression):
        rx = re.compile(str(value.regexp))
        return lambda ev: rx.search(ev.line) is not None
    raise _Unsupported(type(value).__name__)


def _compile(node: Any, fields_used: set[str]) -> Matcher:
    if isinstance(node, ConditionAND):
        parts = [_compile(a, fields_used) for a in node.args]
        return lambda ev: all(p(ev) for p in parts)
    if isinstance(node, ConditionOR):
        parts = [_compile(a, fields_used) for a in node.args]
        return lambda ev: any(p(ev) for p in parts)
    if isinstance(node, ConditionNOT):
        (inner,) = [_compile(a, fields_used) for a in node.args]
        return lambda ev: not inner(ev)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        name = node.field
        fields_used.add(name)
        test = _value_test(node.value)
        return lambda ev: test(ev.fields.get(name))
    if isinstance(node, ConditionValueExpression):
        return _keyword_test(node.value)
    raise _Unsupported(type(node).__name__)


@dataclass(frozen=True)
class CompiledRule:
    rule_id: str
    title: str
    level: str | None
    status: str | None
    tags: tuple[str, ...]
    path: str
    log_type: str
    program: str | None  # service rules on syslog: the program tag they need
    matcher: Matcher
    fields: tuple[str, ...] = ()  # fields the rule's conditions read (empty: keyword rule)

    def applies_to(self, event: LogEvent) -> bool:
        if event.log_type != self.log_type:
            return False
        return self.program is None or (event.program or "").lower() == self.program

    def __call__(self, event: LogEvent) -> bool:
        return self.applies_to(event) and self.matcher(event)


@dataclass
class RuleSet:
    compiled: list[CompiledRule]
    skipped: Counter[str]
    skipped_rules: list[dict[str, str]]
    total: int


def _target(rule: SigmaRule) -> tuple[str, str | None]:
    """(log_type, program) a rule runs on; raises _Skip with the reason."""
    ls = rule.logsource
    category, product, service = ls.category, ls.product, ls.service
    if category in NOT_DERIVABLE_CATEGORIES:
        raise _Skip(f"logsource_not_derivable:{category}")
    if category == "webserver" and service is None:
        return "apache_access", None
    if category is not None:
        raise _Skip(f"logsource_not_derivable:{category}")
    if service == "auditd":
        return "auditd", None
    if service == "apache":
        return "apache_error", None
    if service == "syslog" or (service is None and product == "linux"):
        return "syslog", None
    if service is not None and product == "linux":
        return "syslog", service.lower()
    raise _Skip(f"logsource_not_in_evidence:{service or product}")


def compile_rule(rule: SigmaRule, path: str) -> CompiledRule:
    log_type, program = _target(rule)
    fields_used: set[str] = set()
    try:
        conditions = [c.parse() for c in rule.detection.parsed_condition]
    except Exception as exc:  # pySigma raises many SigmaError subclasses
        raise _Skip("rule_error") from exc
    try:
        matchers = [_compile(c, fields_used) for c in conditions]
    except _Unsupported as exc:
        raise _Skip("unsupported_value") from exc
    if log_type == "apache_access" and not fields_used <= WEBSERVER_FIELDS:
        raise _Skip("field_not_derivable")
    if log_type in ("syslog", "apache_error") and fields_used:
        raise _Skip("field_not_derivable")  # keyword-only log types carry no fields

    def matcher(ev: LogEvent) -> bool:
        return any(m(ev) for m in matchers)

    return CompiledRule(
        rule_id=str(rule.id) if rule.id else PurePosixPath(path).stem,
        title=rule.title, level=str(rule.level) if rule.level else None,
        status=str(rule.status) if rule.status else None,
        tags=tuple(f"{t.namespace}.{t.name}" for t in rule.tags),
        path=path, log_type=log_type, program=program, matcher=matcher,
        fields=tuple(sorted(fields_used)))


def load_rules(repo_root: str | Path, subdirs: Iterable[str] = RULE_SUBDIRS) -> RuleSet:
    """Compile every ``*.yml`` under ``repo_root/<subdir>``; skipped rules are counted by reason."""
    root = Path(repo_root)
    compiled: list[CompiledRule] = []
    skipped: Counter[str] = Counter()
    skipped_rules: list[dict[str, str]] = []
    total = 0
    for sub in subdirs:
        base = root / sub
        if not base.is_dir():
            continue
        for file in sorted(base.rglob("*.yml")):
            total += 1
            rel = file.relative_to(root).as_posix()
            try:
                rule = SigmaRule.from_yaml(file.read_text(encoding="utf-8"))
                compiled.append(compile_rule(rule, rel))
            except _Skip as skip:
                reason = str(skip)
            except Exception:  # unparseable YAML / rule
                reason = "rule_error"
            else:
                continue
            skipped[reason] += 1
            skipped_rules.append({"path": rel, "reason": reason})
    return RuleSet(compiled, skipped, skipped_rules, total)


# ---------------------------------------------------------------- evaluation

def sigma_alert_id(rule_id: str, source_alert_id: str) -> str:
    digest = hashlib.sha256(f"{rule_id}\x00{source_alert_id}".encode()).hexdigest()
    return f"sigma-{digest[:32]}"


@dataclass
class SigmaRun:
    alerts: list[Alert]
    per_rule: dict[str, dict[str, Any]]
    stats: dict[str, Any] = field(default_factory=dict)


class SigmaEngine:
    def __init__(self, rules: list[CompiledRule]):
        self.rules = rules
        self._by_type: dict[str, list[CompiledRule]] = {}
        for r in rules:
            self._by_type.setdefault(r.log_type, []).append(r)

    def _events(self, alert: Alert) -> list[LogEvent]:
        paths = alert.evidence.log_paths
        out: list[LogEvent] = []
        for i, line in enumerate(alert.evidence.log_lines):
            path = paths[i] if i < len(paths) else (paths[0] if len(paths) == 1 else None)
            out.extend(parse_events(path, line))
        return out

    def _emit(self, rule: CompiledRule, source: Alert, events: list[LogEvent]) -> Alert:
        lines, paths = [], []
        for ev in events:
            if ev.line not in lines:
                lines.append(ev.line)
                paths.append(ev.path)
        return Alert(
            alert_id=sigma_alert_id(rule.rule_id, source.alert_id), alert_id_derived=True,
            scenario=source.scenario, detector=Detector.SIGMA,
            detector_type=DETECTOR_TYPES[Detector.SIGMA], timestamp=source.timestamp,
            rule_id=rule.rule_id, rule_name=rule.title, severity=None, host_ip=source.host_ip,
            evidence=AlertEvidence(source_alert_id=source.alert_id, log_lines=lines, log_paths=paths),
            raw_alert={"sigma": {"id": rule.rule_id, "title": rule.title, "level": rule.level,
                                 "status": rule.status, "tags": list(rule.tags), "file": rule.path},
                       "log_type": rule.log_type},
            dataset_name=source.dataset_name, source_file=source.source_file,
            source_line=source.source_line)

    def evaluate(self, alert: Alert, events: list[LogEvent] | None = None) -> list[Alert]:
        events = self._events(alert) if events is None else events
        out = []
        for rule in self.rules:
            matched = [ev for ev in events if rule(ev)]
            if matched:
                out.append(self._emit(rule, alert, matched))
        return out

    def run(self, alerts: Iterable[Alert]) -> SigmaRun:
        per_rule: dict[str, dict[str, Any]] = {
            r.rule_id: {"title": r.title, "file": r.path, "log_type": r.log_type, "level": r.level,
                      "events_evaluated": 0, "hits": 0} for r in self.rules}
        by_type: Counter[str] = Counter()
        out: list[Alert] = []
        sources = no_lines = lines_total = unclassified = 0
        for alert in alerts:
            sources += 1
            if not alert.evidence.log_lines:
                no_lines += 1
                continue
            lines_total += len(alert.evidence.log_lines)
            events = self._events(alert)
            parsed_lines = {ev.line for ev in events}
            unclassified += sum(1 for line in alert.evidence.log_lines if line not in parsed_lines)
            by_type.update(ev.log_type for ev in events)
            for rule in self.rules:
                n = sum(1 for ev in events if rule.applies_to(ev))
                per_rule[rule.rule_id]["events_evaluated"] += n
            for hit in self.evaluate(alert, events):
                per_rule[str(hit.rule_id)]["hits"] += 1
                out.append(hit)
        stats = {"source_alerts": sources, "alerts_without_lines": no_lines,
                 "log_lines": lines_total, "lines_unclassified": unclassified,
                 "events_by_log_type": dict(sorted(by_type.items())), "sigma_alerts": len(out)}
        return SigmaRun(out, per_rule, stats)
