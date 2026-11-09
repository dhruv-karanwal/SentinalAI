"""Sigma engine (Wave B2): log-line parsing, rule compilation, evaluation, emitted alerts.

All rules here are SYNTHETIC test rules written for these tests; the real
SigmaHQ rules are only loaded by ``test_real_rules_load`` when present.
"""

from __future__ import annotations

import inspect
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.detection import sigma_engine as se
from app.schemas.alert import (
    AIT_ADS_DETECTORS,
    DETECTOR_TYPES,
    Alert,
    AlertEvidence,
    Detector,
    DetectorType,
)

T0 = datetime(2022, 1, 21, tzinfo=timezone.utc)
REAL_RULES = Path(__file__).resolve().parents[2] / "data" / "raw" / "sigma" / "repo"

APACHE = ('172.19.131.174 - - [24/Jan/2022:03:57:01 +0000] "GET /wp-admin/../../etc/passwd?x=1 '
          'HTTP/1.1" 404 360 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"')
VHOST = ('cloud.example:443 172.24.251.86 - - [27/Jan/2022:12:29:48 +0000] "POST /sdk HTTP/1.1" '
         '404 8829 "-" "curl/7.1"')
NO_REQUEST = '172.19.131.174 - - [21/Jan/2022:06:42:58 +0000] "-" 408 575 "-" "-"'
AUDIT = ('type=AVC msg=audit(1642745318.249:857): apparmor="STATUS" operation="profile_replace" '
         'name="/sbin/dhclient" pid=18508 comm="apparmor_parser" type=SYSCALL '
         'msg=audit(1642745318.249:857): arch=c000003e syscall=1 exe="/usr/sbin/apparmor_parser" '
         'key=(null)')
AUDIT_USER = ("type=USER_ACCT msg=audit(1642723201.745:569): pid=4388 uid=0 "
              "msg='op=PAM:accounting acct=\"www-data\" exe=\"/usr/sbin/cron\" res=success'")
SYSLOG = "Jan 21 08:05:20 intranet-server sshd[7708]: Corrupted MAC on input from 10.0.0.1"
SYSLOG_NOHOST = "Jan 21 00:00:09 dnsmasq[3326]: query[A] example.test from 10.0.0.2"
ERROR_LOG = "[Mon Jan 24 03:57:26.696483 2022] [core:notice] [pid 1] exit signal Segmentation Fault (11)"


def write_rule(root: Path, name: str, body: str) -> Path:
    path = root / "rules" / "linux" / f"{name}.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"title: {name}\nid: 00000000-0000-0000-0000-{abs(hash(name)) % 10**12:012d}\n"
                    f"status: test\nlevel: high\ntags:\n  - attack.t1190\n{body}", encoding="utf-8")
    return path


def make_alert(lines: list[str], paths: list[str], alert_id: str = "w-1",
               detector: Detector = Detector.WAZUH) -> Alert:
    return Alert(alert_id=alert_id, scenario="synthetic", detector=detector,
                 detector_type=DETECTOR_TYPES[detector], timestamp=T0, rule_id="31101",
                 host_ip="10.0.0.5", evidence=AlertEvidence(source_alert_id=alert_id, log_lines=lines,
                                                            log_paths=paths),
                 raw_alert={"id": alert_id}, dataset_name="synthetic-ait-ads-format",
                 source_file="synthetic_wazuh.json", source_line=7)


WEB = "logsource:\n  category: webserver\n"
LINUX_KW = "logsource:\n  product: linux\n"


# ---------------------------------------------------------------- parsing

def test_parse_apache_combined() -> None:
    ev = se.parse_line("/var/log/apache2/intranet-access.log", APACHE)
    assert ev is not None and ev.log_type == "apache_access"
    assert ev.fields["c-ip"] == "172.19.131.174"
    assert ev.fields["cs-method"] == "GET"
    assert ev.fields["cs-uri-query"] == "/wp-admin/../../etc/passwd?x=1"
    assert ev.fields["cs-uri-stem"] == "/wp-admin/../../etc/passwd"
    assert ev.fields["sc-status"] == "404"
    assert ev.fields["cs-user-agent"] == "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
    assert ev.fields["cs-referer"] == "-"


def test_parse_apache_vhost_and_missing_request() -> None:
    ev = se.parse_line("/var/log/apache2/other_vhosts_access.log", VHOST)
    assert ev is not None and ev.fields["c-ip"] == "172.24.251.86" and ev.fields["cs-method"] == "POST"
    ev = se.parse_line("/var/log/apache2/proxy-access-access.log", NO_REQUEST)
    assert ev is not None and "cs-method" not in ev.fields and ev.fields["sc-status"] == "408"


def test_parse_auditd_splits_records_and_reads_quoted_msg() -> None:
    events = se.parse_events("/var/log/audit/audit.log", AUDIT)
    assert [e.fields["type"] for e in events] == ["AVC", "SYSCALL"]
    assert events[1].fields["exe"] == "/usr/sbin/apparmor_parser"
    assert events[0].fields["comm"] == "apparmor_parser"
    (user,) = se.parse_events("/var/log/audit/audit.log", AUDIT_USER)
    assert user.fields["exe"] == "/usr/sbin/cron" and user.fields["acct"] == "www-data"
    assert user.fields["op"] == "PAM:accounting"


def test_parse_syslog_with_and_without_host() -> None:
    ev = se.parse_line("/var/log/auth.log", SYSLOG)
    assert ev is not None and ev.log_type == "syslog" and ev.program == "sshd"
    ev = se.parse_line("/var/log/dnsmasq.log", SYSLOG_NOHOST)
    assert ev is not None and ev.program == "dnsmasq"


def test_unclassified_paths_give_no_event() -> None:
    assert se.parse_events("/var/log/exim4/mainlog", "2022-01-21 00:16:22 Start queue run") == []
    assert se.parse_events("/var/log/suricata/fast.log", "01/21/2022 [**] x") == []
    assert se.parse_events(None, APACHE) == []
    ev = se.parse_line("/var/log/apache2/intranet-error.log", ERROR_LOG)
    assert ev is not None and ev.log_type == "apache_error"


# ---------------------------------------------------------------- compilation

def test_skip_reasons_are_counted(tmp_path: Path) -> None:
    write_rule(tmp_path, "proc", "logsource:\n  product: linux\n  category: process_creation\n"
               "detection:\n  sel:\n    Image|endswith: /bash\n  condition: sel\n")
    write_rule(tmp_path, "proxy", "logsource:\n  category: proxy\n"
               "detection:\n  sel:\n    c-useragent: x\n  condition: sel\n")
    write_rule(tmp_path, "nginx", "logsource:\n  product: nginx\n  service: nginx\n"
               "detection:\n  keywords:\n    - core dumped\n  condition: keywords\n")
    write_rule(tmp_path, "webhost", WEB + "detection:\n  sel:\n    cs-host: x\n  condition: sel\n")
    write_rule(tmp_path, "ok", WEB + "detection:\n  sel:\n    cs-method: GET\n  condition: sel\n")
    rules = se.load_rules(tmp_path)
    assert [r.title for r in rules.compiled] == ["ok"]
    assert rules.total == 5
    assert rules.skipped == {"logsource_not_derivable:process_creation": 1,
                             "logsource_not_derivable:proxy": 1,
                             "logsource_not_in_evidence:nginx": 1,
                             "field_not_derivable": 1}


def test_unparseable_rule_is_counted_not_raised(tmp_path: Path) -> None:
    write_rule(tmp_path, "bad", "logsource:\n  category: webserver\ndetection:\n  condition: nope\n")
    rules = se.load_rules(tmp_path)
    assert rules.compiled == [] and rules.skipped == {"rule_error": 1}


# ---------------------------------------------------------------- evaluation

def _hits(tmp_path: Path, body: str, path: str, line: str) -> bool:
    write_rule(tmp_path, "r", body)
    rules = se.load_rules(tmp_path)
    assert len(rules.compiled) == 1, rules.skipped
    engine = se.SigmaEngine(rules.compiled)
    return bool(engine.evaluate(make_alert([line], [path])))


ACCESS = "/var/log/apache2/intranet-access.log"


@pytest.mark.parametrize("detection,expected", [
    ("sel:\n    cs-uri-query|contains: '/../../'\n  condition: sel", True),
    ("sel:\n    cs-uri-query|contains: '/NOPE/'\n  condition: sel", False),
    ("sel:\n    cs-method: get\n  condition: sel", True),                       # case-insensitive
    ("sel:\n    cs-user-agent|re: 'nmap'\n  condition: sel", False),             # regex is case-sensitive
    ("sel:\n    cs-user-agent|re: 'Nmap'\n  condition: sel", True),
    ("sel:\n    sc-status: 404\n  condition: sel", True),                        # SigmaNumber
    ("sel:\n    c-ip|cidr: '172.19.0.0/16'\n  condition: sel", True),
    ("sel:\n    c-ip|cidr: '10.0.0.0/8'\n  condition: sel", False),
    ("sel:\n    cs-method: GET\n  f:\n    sc-status: 404\n  condition: sel and not f", False),
    ("sel:\n    cs-method: POST\n  f:\n    sc-status: 404\n  condition: sel or f", True),
    ("sel:\n    cs-uri-query|contains|all:\n      - passwd\n      - wp-admin\n  condition: sel", True),
    ("sel:\n    cs-uri-query|endswith: '?x=1'\n  condition: sel", True),
    ("sel:\n    cs-uri-query|startswith: '/etc'\n  condition: sel", False),
    ("sel:\n    cs-referer: null\n  condition: sel", False),
    ("keywords:\n    - 'scripting engine'\n  condition: keywords", True),     # keyword = substring
])
def test_webserver_conditions(tmp_path: Path, detection: str, expected: bool) -> None:
    assert _hits(tmp_path, WEB + "detection:\n  " + detection + "\n", ACCESS, APACHE) is expected


def test_keyword_rule_runs_only_on_its_log_type(tmp_path: Path) -> None:
    body = LINUX_KW + "detection:\n  keywords:\n    - 'Corrupted MAC'\n  condition: keywords\n"
    assert _hits(tmp_path, body, "/var/log/auth.log", SYSLOG)
    assert not _hits(tmp_path, body, ACCESS, APACHE + " Corrupted MAC")


def test_service_rule_needs_matching_program(tmp_path: Path) -> None:
    body = ("logsource:\n  product: linux\n  service: sshd\n"
            "detection:\n  keywords:\n    - 'Corrupted MAC'\n  condition: keywords\n")
    assert _hits(tmp_path, body, "/var/log/auth.log", SYSLOG)
    assert not _hits(tmp_path, body, "/var/log/auth.log", SYSLOG.replace("sshd[", "cron["))


def test_apache_service_rule_runs_on_error_log(tmp_path: Path) -> None:
    body = ("logsource:\n  product: apache\n  service: apache\n"
            "detection:\n  keywords:\n    - 'exit signal Segmentation Fault'\n  condition: keywords\n")
    assert _hits(tmp_path, body, "/var/log/apache2/intranet-error.log", ERROR_LOG)
    assert not _hits(tmp_path, body, ACCESS, APACHE)


def test_auditd_fields(tmp_path: Path) -> None:
    body = ("logsource:\n  product: linux\n  service: auditd\n"
            "detection:\n  sel:\n    type: SYSCALL\n    exe|endswith: '/apparmor_parser'\n"
            "  condition: sel\n")
    assert _hits(tmp_path, body, "/var/log/audit/audit.log", AUDIT)
    # AND inside one record: the AVC record has no exe, the SYSCALL record has it
    body2 = body.replace("type: SYSCALL", "type: AVC")
    assert not _hits(tmp_path, body2, "/var/log/audit/audit.log", AUDIT)


# ---------------------------------------------------------------- emitted alerts

def test_emitted_alert_shape(tmp_path: Path) -> None:
    write_rule(tmp_path, "r", WEB + "detection:\n  sel:\n    cs-method: GET\n  condition: sel\n")
    engine = se.SigmaEngine(se.load_rules(tmp_path).compiled)
    source = make_alert(["not a log line", APACHE], ["/x/unknown.log", ACCESS])
    (out,) = engine.evaluate(source)
    assert out.detector is Detector.SIGMA and out.detector_type is DetectorType.RULE_BASED
    assert out.alert_id.startswith("sigma-") and out.alert_id_derived
    assert out.alert_id == engine.evaluate(source)[0].alert_id  # deterministic
    assert out.evidence.source_alert_id == "w-1"
    assert out.evidence.log_lines == [APACHE] and out.evidence.log_paths == [ACCESS]
    assert out.severity is None  # Sigma levels are words; never mapped onto a number
    assert out.raw_alert["sigma"]["level"] == "high"
    assert out.raw_alert["sigma"]["tags"] == ["attack.t1190"]
    assert out.timestamp == source.timestamp and out.host_ip == source.host_ip
    assert (out.source_file, out.source_line) == (source.source_file, source.source_line)
    assert out.rule_name == "r"


def test_run_counts(tmp_path: Path) -> None:
    write_rule(tmp_path, "r", WEB + "detection:\n  sel:\n    cs-method: GET\n  condition: sel\n")
    engine = se.SigmaEngine(se.load_rules(tmp_path).compiled)
    alerts = [make_alert([APACHE], [ACCESS], "a"), make_alert([SYSLOG], ["/var/log/auth.log"], "b"),
              make_alert([], [], "c")]
    run = engine.run(alerts)
    assert len(run.alerts) == 1
    assert run.stats["source_alerts"] == 3
    assert run.stats["events_by_log_type"] == {"apache_access": 1, "syslog": 1}
    assert run.stats["lines_unclassified"] == 0
    assert run.stats["alerts_without_lines"] == 1
    (entry,) = run.per_rule.values()
    assert entry["title"] == "r" and entry["hits"] == 1 and entry["events_evaluated"] == 1


# ---------------------------------------------------------------- separation

def test_engine_never_touches_labels() -> None:
    source = inspect.getsource(se)
    for word in ("ground_truth", "GroundTruth", "TruthStore", "event_label", "time_label"):
        assert word not in source


def test_sigma_is_not_an_ait_ads_detector() -> None:
    assert Detector.SIGMA not in AIT_ADS_DETECTORS
    assert DETECTOR_TYPES[Detector.SIGMA] is DetectorType.RULE_BASED
    assert [d.value for d in AIT_ADS_DETECTORS] == ["wazuh", "suricata", "aminer"]


@pytest.mark.skipif(not (REAL_RULES / "rules").is_dir(), reason="approved SigmaHQ rules not present")
def test_real_rules_load() -> None:
    rules = se.load_rules(REAL_RULES)
    assert rules.total == 256
    assert len(rules.compiled) + sum(rules.skipped.values()) == 256
    assert rules.skipped.get("rule_error", 0) == 0
