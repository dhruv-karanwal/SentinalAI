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


def _native_ids(alert: Alert) -> list[str]:
    if alert.detector is not Detector.WAZUH:
        return []
    rule = alert.raw_alert.get("rule")
    mitre = rule.get("mitre") if isinstance(rule, dict) else None
    ids = mitre.get("id") if isinstance(mitre, dict) else None
    return [str(i) for i in ids] if isinstance(ids, list) else []


def _table_ids(alert: Alert) -> list[str]:
    if alert.detector is Detector.SURICATA:
        data = alert.raw_alert.get("data")
        inner = data.get("alert") if isinstance(data, dict) else None
        category = inner.get("category") if isinstance(inner, dict) else None
        return list(RULE_TABLE.get(("suricata", "category", str(category)), ()))
    return []


def map_alert(alert: Alert, kb: AttackKB | None = None) -> list[dict[str, Any]]:
    """Technique mappings of an alert: id, name, tactics, source, known."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for source, ids in (("native", _native_ids(alert)), ("rule_table", _table_ids(alert))):
        for tid in ids:
            if tid in seen:
                continue
            seen.add(tid)
            tech = kb.get(tid) if kb else None
            out.append({"technique_id": tid, "name": tech.name if tech else None,
                        "tactics": list(tech.tactics) if tech else [], "source": source,
                        "known": (tech is not None) if kb else None})
    return out
