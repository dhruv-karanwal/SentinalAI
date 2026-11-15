"""Operational ML detection (C4, 2026-11-15): a saved, versioned model bundle and its inference.

Label-free: training (which needs labels) lives in :func:`app.detection.ml_baselines.train_bundle`;
this module only saves, loads and scores. A bundle holds two models fitted on the same features:

- ``hist_gradient_boosting``: supervised; its score is ``predict_proba`` of the attack class. It is
  **not calibrated** (two flood-heavy dev scenarios) and is never shown as a probability;
- ``isolation_forest``: unsupervised; its score is ``-score_samples`` (higher = more anomalous) and
  ``flag`` is scikit-learn's own ``contamination="auto"`` decision. An anomaly is not an attack.

Files: ``<dir>/<version>/model.joblib`` and ``metadata.json``. ``load_bundle`` checks the joblib
file's sha256 against the metadata **before** unpickling (a pickle runs code: only files this code
wrote, unchanged, are loaded). Scores never change triage severity (``INFLUENCES_SEVERITY``); the
console shows them next to the rule-based findings, labelled with the model version and whether the
scored scenario was in the training data (in-sample scores say little).

Explanation per alert: the alert's values of the bundle's most important features (permutation
importance on the training data, global, in-sample). It is not a per-alert attribution.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib

from app.detection.features import FEATURE_NAMES, FeatureEncoder, raw_features
from app.schemas.alert import Alert

MODEL_FILE = "model.joblib"
METADATA_FILE = "metadata.json"
INFLUENCES_SEVERITY = False
EXPLAIN_TOP = 3


class BundleError(Exception):
    pass


@dataclass
class ModelBundle:
    version: str
    features: tuple[str, ...]
    vocab: dict[str, dict[str, int]]
    models: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)

    def columns(self) -> list[int]:
        return [FEATURE_NAMES.index(f) for f in self.features]


def bundle_version(metadata: dict[str, Any]) -> str:
    digest = hashlib.sha256(json.dumps(metadata, sort_keys=True).encode()).hexdigest()[:12]
    return f"ml-{metadata['created_utc'][:10]}-{digest}"


def save_bundle(bundle: ModelBundle, root: str | Path) -> Path:
    out = Path(root) / bundle.version
    out.mkdir(parents=True, exist_ok=False)  # versions are immutable
    path = out / MODEL_FILE
    joblib.dump({"models": bundle.models, "vocab": bundle.vocab, "features": list(bundle.features)}, path)
    meta = {**bundle.metadata, "version": bundle.version, "features": list(bundle.features),
            "model_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "influences_severity": INFLUENCES_SEVERITY}
    (out / METADATA_FILE).write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return out


def load_bundle(path: str | Path) -> ModelBundle:
    d = Path(path)
    try:
        meta = json.loads((d / METADATA_FILE).read_text(encoding="utf-8"))
        raw = (d / MODEL_FILE).read_bytes()
    except OSError as exc:
        raise BundleError(f"no model bundle in {d}: {exc}") from exc
    if hashlib.sha256(raw).hexdigest() != meta.get("model_sha256"):
        raise BundleError(f"{d / MODEL_FILE} does not match its metadata sha256; refusing to load it")
    data = joblib.load(d / MODEL_FILE)
    return ModelBundle(str(meta["version"]), tuple(data["features"]), data["vocab"], data["models"], meta)


def latest_bundle(root: str | Path) -> Path | None:
    dirs = sorted((p for p in Path(root).glob("ml-*") if (p / METADATA_FILE).exists()),
                  key=lambda p: json.loads((p / METADATA_FILE).read_text(encoding="utf-8"))["created_utc"])
    return dirs[-1] if dirs else None


def score_alerts(bundle: ModelBundle, alerts: Sequence[Alert], *, in_sample: bool) -> list[dict[str, Any]]:
    """One row per (alert, model). ``alerts`` must be the whole time-ordered scenario pool: the
    per-host counts look at earlier alerts of the same list."""
    ordered = sorted(alerts, key=lambda a: (a.timestamp, a.source_file, a.source_line, a.alert_id))
    rows = raw_features(ordered)
    x = FeatureEncoder(bundle.vocab).transform(rows)[:, bundle.columns()]
    top = [f for f in bundle.metadata.get("importance_order", list(bundle.features))
           if f in bundle.features][:EXPLAIN_TOP]
    out: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()
    hgb = bundle.models.get("hist_gradient_boosting")
    forest = bundle.models.get("isolation_forest")
    hgb_scores = hgb.predict_proba(x)[:, 1] if hgb is not None else None
    hgb_flags = hgb.predict(x) if hgb is not None else None
    if_scores = -forest.score_samples(x) if forest is not None else None
    if_flags = forest.predict(x) == -1 if forest is not None else None
    for i, a in enumerate(ordered):
        explanation = {f: rows[i][f] for f in top}
        if hgb_scores is not None and hgb_flags is not None:
            out.append({"alert_id": a.alert_id, "model": "hist_gradient_boosting",
                        "score": round(float(hgb_scores[i]), 6), "flag": bool(hgb_flags[i]),
                        "kind": "supervised score (uncalibrated)", "in_sample": in_sample,
                        "explanation": explanation, "scored_utc": now})
        if if_scores is not None and if_flags is not None:
            out.append({"alert_id": a.alert_id, "model": "isolation_forest",
                        "score": round(float(if_scores[i]), 6), "flag": bool(if_flags[i]),
                        "kind": "anomaly score (not an attack verdict)", "in_sample": in_sample,
                        "explanation": explanation, "scored_utc": now})
    return out
