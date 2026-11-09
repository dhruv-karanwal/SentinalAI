"""Alert features for the ML detection baselines (Wave B4). Label-free by construction.

:func:`raw_features` takes alerts (and an optional IOC store) and nothing
else; it cannot see labels. The exact list is :data:`FEATURE_NAMES`, pinned
by ``tests/test_ml_baselines.py`` together with the forbidden names (labels,
phase, scenario, alert id, raw timestamps, source file/line).

=================  ============================================================
feature            value (from the alert only)
=================  ============================================================
detector           wazuh | suricata | aminer (categorical)
severity           detector-native level (Wazuh ``rule.level``, Suricata
                   ``alert.severity``); ``-1`` when the detector has none
has_severity       1 if the detector carries a severity, else 0
rule_id            rule / signature id (categorical)
category           Wazuh first rule group, Suricata ``alert.category``, AMiner
                   ``AnalysisComponentType`` (enrichment ``event_type``)
aminer_component   AMiner ``AnalysisComponentType``; ``n/a`` for other detectors
attack_mapped      1 if B1 ``map_alert`` finds a technique (native / rule table)
ioc_match          1 if the IOC store matches (feeds are disabled: 0 unless a
                   local indicator file is given)
host_count_60s     alerts on the same ``host_ip`` with a timestamp strictly
host_count_600s    earlier, within 60 s / 600 s (past only, no lookahead;
                   alerts at the same instant do not count); 0 without host
evidence_lines     number of evidence log lines
evidence_chars     total characters of the evidence log lines
=================  ============================================================

``-1`` for a missing severity is an encoding (paired with ``has_severity``),
not an imputed value. Encoding: :class:`FeatureEncoder` is fitted on the
training split only; categories never seen in training map to
:data:`UNKNOWN_CODE`. Trees need no scaling, so no scaler is used.
"""

from __future__ import annotations

import bisect
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np

from app.intel.attack import map_alert
from app.intel.ioc import IocStore
from app.platform.enrichment import enrich
from app.schemas.alert import Alert, Detector

FEATURE_NAMES: tuple[str, ...] = (
    "detector", "severity", "has_severity", "rule_id", "category", "aminer_component",
    "attack_mapped", "ioc_match", "host_count_60s", "host_count_600s", "evidence_lines",
    "evidence_chars",
)
CATEGORICAL: tuple[str, ...] = ("detector", "rule_id", "category", "aminer_component")
WINDOWS = (60, 600)
UNKNOWN_CODE = -1.0


def raw_features(alerts: Sequence[Alert], iocs: IocStore | None = None) -> list[dict[str, Any]]:
    """One feature dict per alert, in input order."""
    times_by_host: dict[str, list[float]] = {}
    for a in alerts:
        if a.host_ip is not None:
            times_by_host.setdefault(str(a.host_ip), []).append(a.timestamp.timestamp())
    for ts in times_by_host.values():
        ts.sort()
    rows = []
    for a in alerts:
        e = enrich(a)
        aminer = a.detector is Detector.AMINER
        counts = {}
        for w in WINDOWS:
            n = 0
            if a.host_ip is not None:
                ts, t = times_by_host[str(a.host_ip)], a.timestamp.timestamp()
                n = bisect.bisect_left(ts, t) - bisect.bisect_left(ts, t - w)
            counts[f"host_count_{w}s"] = n
        rows.append({
            "detector": a.detector.value,
            "severity": a.severity if a.severity is not None else -1,
            "has_severity": int(a.severity is not None),
            "rule_id": a.rule_id or a.rule_name or "n/a",
            "category": str(e["event_type"]) if e["event_type"] is not None else "n/a",
            "aminer_component": (str(e["event_type"]) if aminer and e["event_type"] is not None
                                 else "n/a"),
            "attack_mapped": int(bool(map_alert(a))),
            "ioc_match": int(bool(iocs.match_alert(a, e))) if iocs else 0,
            **counts,
            "evidence_lines": len(a.evidence.log_lines),
            "evidence_chars": sum(len(line) for line in a.evidence.log_lines),
        })
    return rows


@dataclass
class FeatureEncoder:
    """Ordinal codes for categorical columns, fitted on the training rows only."""

    vocab: dict[str, dict[str, int]]

    @classmethod
    def fit(cls, rows: Sequence[dict[str, Any]]) -> FeatureEncoder:
        vocab: dict[str, dict[str, int]] = {}
        for col in CATEGORICAL:
            values = sorted({str(r[col]) for r in rows})
            vocab[col] = {v: i for i, v in enumerate(values)}
        return cls(vocab)

    def transform(self, rows: Sequence[dict[str, Any]]) -> np.ndarray[Any, np.dtype[np.float64]]:
        x = np.zeros((len(rows), len(FEATURE_NAMES)), dtype=np.float64)
        for i, r in enumerate(rows):
            for j, name in enumerate(FEATURE_NAMES):
                if name in self.vocab:
                    code = self.vocab[name].get(str(r[name]))
                    x[i, j] = UNKNOWN_CODE if code is None else code
                else:
                    x[i, j] = float(r[name])
        return x
