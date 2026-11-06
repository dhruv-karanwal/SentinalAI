"""Enrichment (stage 2): derived context from fields the alert already carries.

Rule: never invent. Every value is read from the alert or computed from a
value it carries (e.g. an IP's address class via :mod:`ipaddress`); a value
that is not present is ``None``. Geo data comes only from Wazuh's own
``GeoLocation`` field; there is no GeoIP database lookup.

Output keys (all always present):

- ``event_type``: Wazuh first rule group, Suricata ``alert.category``,
  AMiner ``AnalysisComponentType``; else None.
- ``source``: detector, detector type, log path(s), agent name, hostname,
  program name (as carried).
- ``time``: alert timestamp (ISO UTC), hour of day UTC, first/last evidence
  log timestamp.
- ``network``: src/dst IP and port as carried (Suricata ``src_ip``/
  ``dest_ip``, Wazuh ``data.srcip``/``dstip``), protocol, and per IP its
  version, private/global/loopback class.
- ``geo``: Wazuh ``GeoLocation`` (country, city, lat/lon) or None.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from app.schemas.alert import Alert, Detector


def _get(record: Any, *path: str) -> Any:
    cur = record
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return None if cur in ("", None) else cur


def ip_info(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return {"value": str(value), "valid": False}
    scope = ("loopback" if ip.is_loopback else "private" if ip.is_private else
             "global" if ip.is_global else "other")
    return {"value": str(ip), "valid": True, "version": ip.version, "scope": scope}


def _port(value: Any) -> int | None:
    try:
        port = int(str(value))
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def enrich(alert: Alert) -> dict[str, Any]:
    raw = alert.raw_alert
    if alert.detector is Detector.WAZUH:
        groups = _get(raw, "rule", "groups")
        event_type = groups[0] if isinstance(groups, list) and groups else None
        src, dst = _get(raw, "data", "srcip"), _get(raw, "data", "dstip")
        sport, dport = _get(raw, "data", "srcport"), _get(raw, "data", "dstport")
        proto = _get(raw, "data", "protocol")
    elif alert.detector is Detector.SURICATA:
        event_type = _get(raw, "data", "alert", "category")
        src, dst = _get(raw, "data", "src_ip"), _get(raw, "data", "dest_ip")
        sport, dport = _get(raw, "data", "src_port"), _get(raw, "data", "dest_port")
        proto = _get(raw, "data", "proto")
    else:
        event_type = _get(raw, "AnalysisComponent", "AnalysisComponentType")
        src = dst = sport = dport = proto = None
    geo_raw = _get(raw, "GeoLocation")
    geo = None
    if isinstance(geo_raw, dict):
        loc_raw = geo_raw.get("location")
        loc: dict[str, Any] = loc_raw if isinstance(loc_raw, dict) else {}
        geo = {"country": geo_raw.get("country_name"), "city": geo_raw.get("city_name"),
               "region": geo_raw.get("region_name"), "lat": loc.get("lat"), "lon": loc.get("lon")}
    stamps = sorted(alert.evidence.log_timestamps)
    return {
        "event_type": event_type,
        "source": {
            "detector": alert.detector.value, "detector_type": alert.detector_type.value,
            "log_paths": list(alert.evidence.log_paths),
            "agent_name": _get(raw, "agent", "name"),
            "hostname": _get(raw, "predecoder", "hostname"),
            "program": _get(raw, "predecoder", "program_name"),
        },
        "time": {
            "timestamp": alert.timestamp.isoformat(), "hour_utc": alert.timestamp.hour,
            "first_log": stamps[0].isoformat() if stamps else None,
            "last_log": stamps[-1].isoformat() if stamps else None,
        },
        "network": {
            "host": ip_info(alert.host_ip), "src": ip_info(src), "dst": ip_info(dst),
            "src_port": _port(sport), "dst_port": _port(dport),
            "protocol": str(proto) if proto is not None else None,
        },
        "geo": geo,
    }
