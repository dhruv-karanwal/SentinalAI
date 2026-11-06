"""Indicator-of-compromise store and matcher.

The local store is a JSON file ``{"indicators": [{"type": ip|domain|url|
sha256|md5, "value": ..., "source": ..., "description": ...}]}``. Matching
is exact (domains and hashes case-insensitive, IPs compared as parsed
addresses, a listed domain also matches its subdomains). Values come from
the enrichment's network fields, Suricata http/tls/dns fields and tokens of
the raw log lines.

Feed adapters (OTX, MISP, VirusTotal) are **disabled stubs**: they need API
keys, which are not approved. ``offline_sample()`` returns a clearly labelled
SYNTHETIC sample (reserved TEST-NET / .example values) shaped like their
output, so the pipeline runs without network access. It is not threat intel.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.schemas.alert import Alert

IOC_TYPES = ("ip", "domain", "url", "sha256", "md5")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
_HEX = re.compile(r"\b[0-9a-f]{64}\b|\b[0-9a-f]{32}\b", re.I)


@dataclass(frozen=True)
class Indicator:
    type: str
    value: str
    source: str
    description: str = ""

    @staticmethod
    def normalize(kind: str, value: str) -> str:
        if kind not in IOC_TYPES:
            raise ValueError(f"unknown indicator type {kind!r}")
        value = value.strip()
        if kind == "ip":
            return str(ipaddress.ip_address(value))
        return value.lower() if kind in ("domain", "sha256", "md5") else value


class IocStore:
    def __init__(self, indicators: list[Indicator] | None = None) -> None:
        self._by_type: dict[str, dict[str, Indicator]] = {t: {} for t in IOC_TYPES}
        for ind in indicators or []:
            self.add(ind)

    def add(self, ind: Indicator) -> None:
        value = Indicator.normalize(ind.type, ind.value)
        self._by_type[ind.type][value] = Indicator(ind.type, value, ind.source, ind.description)

    def __len__(self) -> int:
        return sum(len(v) for v in self._by_type.values())

    @classmethod
    def load(cls, path: str | Path) -> IocStore:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls([Indicator(d["type"], d["value"], d.get("source", "local"),
                              d.get("description", "")) for d in data["indicators"]])

    def _lookup(self, kind: str, value: str) -> Indicator | None:
        try:
            norm = Indicator.normalize(kind, value)
        except ValueError:
            return None
        hit = self._by_type[kind].get(norm)
        if hit is None and kind == "domain":
            parts = norm.split(".")
            for i in range(1, len(parts) - 1):
                hit = self._by_type["domain"].get(".".join(parts[i:]))
                if hit:
                    break
        return hit

    def match_alert(self, alert: Alert,
                    enrichment: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        candidates: list[tuple[str, str, str]] = []  # (type, value, where)
        net = (enrichment or {}).get("network") or {}
        for side in ("host", "src", "dst"):
            info = net.get(side)
            if info and info.get("valid"):
                candidates.append(("ip", str(info["value"]), f"network.{side}"))
        data = alert.raw_alert.get("data")
        data = data if isinstance(data, dict) else {}
        for path, kind in ((("http", "hostname"), "domain"), (("tls", "sni"), "domain"),
                           (("dns", "rrname"), "domain"), (("http", "url"), "url")):
            cur: Any = data
            for key in path:
                cur = cur.get(key) if isinstance(cur, dict) else None
            if isinstance(cur, str) and cur:
                candidates.append((kind, cur, "data." + ".".join(path)))
        for n, line in enumerate(alert.evidence.log_lines):
            candidates.extend(("ip", m, f"log_lines[{n}]") for m in _IP.findall(line))
            candidates.extend(("domain", m, f"log_lines[{n}]") for m in _DOMAIN.findall(line))
            candidates.extend(("md5" if len(m) == 32 else "sha256", m, f"log_lines[{n}]")
                              for m in _HEX.findall(line))
        hits: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for kind, value, where in candidates:
            ind = self._lookup(kind, value)
            if ind and (ind.type, ind.value) not in seen:
                seen.add((ind.type, ind.value))
                hits.append({"type": ind.type, "indicator": ind.value, "observed": value,
                             "where": where, "source": ind.source, "description": ind.description})
        return hits


class FeedAdapter:
    """Base of the external feed adapters. Disabled: no API keys are approved."""

    name = "feed"
    enabled = False

    def fetch(self) -> list[Indicator]:
        raise RuntimeError(f"{self.name} adapter is disabled (needs an API key; not approved). "
                           "Use offline_sample() for a labelled synthetic sample.")

    def offline_sample(self) -> list[Indicator]:
        source = f"{self.name}:offline-sample"
        return [Indicator("ip", "203.0.113.66", source,
                          "SYNTHETIC sample indicator (TEST-NET-3 address), not real threat intel"),
                Indicator("domain", "malicious.example", source,
                          "SYNTHETIC sample indicator (reserved .example domain)")]


class OtxAdapter(FeedAdapter):
    name = "otx"


class MispAdapter(FeedAdapter):
    name = "misp"


class VirusTotalAdapter(FeedAdapter):
    name = "virustotal"


FEEDS: tuple[type[FeedAdapter], ...] = (OtxAdapter, MispAdapter, VirusTotalAdapter)
