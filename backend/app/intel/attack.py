"""MITRE ATT&CK enterprise knowledge base (local STIX 2.1 bundle) and alert mapping.

Source: ``data/raw/mitre/enterprise-attack.json`` from GitHub
``mitre-attack/attack-stix-data`` (approved download; version and sha256 in
docs/session-notes.md). Revoked and deprecated objects are excluded.

Mapping an alert to techniques is deterministic and never uses an LLM:

1. ``native``: ids the detector itself attached (Wazuh ``rule.mitre.id``).
2. ``rule_table``: :data:`RULE_TABLE`, a short documented table keyed on
   detector categories (Suricata ``alert.category``) for which the technique
   is unambiguous. Everything else stays unmapped (an empty list), never a
   guess. AMiner anomalies are not mapped: an anomaly type says nothing about
   the adversary technique.

Ids not present in the loaded ATT&CK version are kept but flagged
``known=False``.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.schemas.alert import Alert, Detector

DEFAULT_STIX = Path(__file__).resolve().parents[3] / "data" / "raw" / "mitre" / "enterprise-attack.json"

# (detector, field, value) -> technique ids. Keep short; every row is a documented choice.
RULE_TABLE: dict[tuple[str, str, str], tuple[str, ...]] = {
    # Suricata ET "Web Application Attack" = attacks on an exposed web app.
    ("suricata", "category", "Web Application Attack"): ("T1190",),  # Exploit Public-Facing Application
}


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactics: tuple[str, ...]
    description: str
    platforms: tuple[str, ...]
    data_sources: tuple[str, ...]
    detection: str
    is_subtechnique: bool
    url: str | None

    def text(self) -> str:
        """Retrieval text (the Wave C RAG chunks start from this)."""
        return (f"{self.technique_id} {self.name}\nTactics: {', '.join(self.tactics)}\n"
                f"Platforms: {', '.join(self.platforms)}\n{self.description}\n"
                f"Detection: {self.detection}").strip()


@dataclass
class AttackKB:
    techniques: dict[str, Technique]
    tactics: dict[str, str]  # shortname -> display name
    version: str | None
    sha256: str | None = None
    groups: dict[str, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def from_stix(cls, path: str | Path = DEFAULT_STIX) -> AttackKB:
        raw = Path(path).read_bytes()
        bundle = json.loads(raw)
        techniques: dict[str, Technique] = {}
        tactics: dict[str, str] = {}
        groups: dict[str, dict[str, Any]] = {}
        version = None
        for obj in bundle.get("objects", []):
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            kind = obj.get("type")
            ext = next((r for r in obj.get("external_references", [])
                        if r.get("source_name") == "mitre-attack"), None)
            if kind == "x-mitre-collection":
                version = obj.get("x_mitre_version")
            elif kind == "x-mitre-tactic" and ext:
                tactics[obj["x_mitre_shortname"]] = obj["name"]
            elif kind == "attack-pattern" and ext and str(ext.get("external_id", "")).startswith("T"):
                tid = str(ext["external_id"])
                techniques[tid] = Technique(
                    technique_id=tid, name=obj["name"],
                    tactics=tuple(p["phase_name"] for p in obj.get("kill_chain_phases", [])
                                  if p.get("kill_chain_name") == "mitre-attack"),
                    description=obj.get("description", ""),
                    platforms=tuple(obj.get("x_mitre_platforms", [])),
                    data_sources=tuple(obj.get("x_mitre_data_sources", [])),
                    detection=obj.get("x_mitre_detection", ""),
                    is_subtechnique=bool(obj.get("x_mitre_is_subtechnique")),
                    url=ext.get("url"))
            elif kind == "intrusion-set" and ext:
                groups[str(ext["external_id"])] = {"name": obj["name"],
                                                   "aliases": obj.get("aliases", [])}
        return cls(techniques, tactics, version, hashlib.sha256(raw).hexdigest(), groups)

    def get(self, technique_id: str) -> Technique | None:
        return self.techniques.get(technique_id)

    def parent(self, technique_id: str) -> Technique | None:
        return self.techniques.get(technique_id.split(".")[0])


_SIGMA_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")


def _native_ids_raw(detector: str, raw: Mapping[str, Any]) -> list[str]:
    if detector == Detector.SIGMA.value:
        # Sigma rules carry their own ATT&CK tags (attack.t1190): native ids, like Wazuh's
        # rule.mitre.id. Tactic tags (attack.execution) are not technique ids and are ignored.
        sigma = raw.get("sigma")
        tags = sigma.get("tags") if isinstance(sigma, dict) else None
        matches = (_SIGMA_TAG.match(str(t)) for t in tags) if isinstance(tags, list) else ()
        return [m.group(1).upper() for m in matches if m]
    if detector != Detector.WAZUH.value:
        return []
    rule = raw.get("rule")
    mitre = rule.get("mitre") if isinstance(rule, dict) else None
    ids = mitre.get("id") if isinstance(mitre, dict) else None
    return [str(i) for i in ids] if isinstance(ids, list) else []


def _table_ids_raw(detector: str, raw: Mapping[str, Any]) -> list[str]:
    if detector == Detector.SURICATA.value:
        data = raw.get("data")
        inner = data.get("alert") if isinstance(data, dict) else None
        category = inner.get("category") if isinstance(inner, dict) else None
        return list(RULE_TABLE.get(("suricata", "category", str(category)), ()))
    return []


def technique_ids(detector: str, raw_alert: Mapping[str, Any]) -> list[str]:
    """Technique ids of a stored record (detector name + ``raw_alert`` dict), native first.

    The same rules as :func:`map_alert`, without building an ``Alert`` model: the console's
    per-scenario index maps every stored alert this way.
    """
    out: list[str] = []
    for tid in _native_ids_raw(detector, raw_alert) + _table_ids_raw(detector, raw_alert):
        if tid not in out:
            out.append(tid)
    return out


def map_alert(alert: Alert, kb: AttackKB | None = None) -> list[dict[str, Any]]:
    """Technique mappings of an alert: id, name, tactics, source, known."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    det, raw = alert.detector.value, alert.raw_alert
    for source, ids in (("native", _native_ids_raw(det, raw)), ("rule_table", _table_ids_raw(det, raw))):
        for tid in ids:
            if tid in seen:
                continue
            seen.add(tid)
            tech = kb.get(tid) if kb else None
            out.append({"technique_id": tid, "name": tech.name if tech else None,
                        "tactics": list(tech.tactics) if tech else [], "source": source,
                        "known": (tech is not None) if kb else None})
    return out
