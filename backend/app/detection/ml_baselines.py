"""ML detection baselines on AIT-ADS dev scenarios (Wave B4). Off-the-shelf models only.

Labelled everywhere: **detection baselines, dev scenarios, not paper results**.
CICIDS2017 is not available (its download needs a registration form).

- Alerts: the investigation-eligible pool of each dev scenario (same pool
  as the study and the Sigma dev baseline).
- Features: :mod:`app.detection.features` (label-free), computed per
  scenario over the whole time-ordered pool, so trailing-window counts in a
  test split may use earlier (training-period) alerts but never later ones.
- Labels: only through :func:`app.detection.labels.dev_labels` (truth area),
  used as the supervised target at training time and as truth at
  evaluation time. Target = ``event_label`` attack (alerts without a
  verified event label are left out of training and of event-label
  scoring); ``time_label`` is the sensitivity check on the same predictions.
- Models, seeded with the study seed (``variants.seed``):
  ``IsolationForest(n_estimators=200, contamination="auto")`` fitted on the
  training features without labels (prediction -1 = attack; "auto" is
  scikit-learn's own threshold, so the base rate is never fed in), and
  ``HistGradientBoostingClassifier`` (defaults). XGBoost is installed but
  not used: one supervised model was asked for, and HistGradientBoosting
  needs no extra dependency.
- Splits: (a) time split inside each scenario: alerts before
  ``t_min + 0.6 * (t_max - t_min)`` train, the rest test (60/40 of the
  *timeline*, not of the alert count); (b) cross-scenario: train on one dev
  scenario, test on the other, both directions.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest

from app.alert_pipeline import iter_alert_file
from app.detection.features import FEATURE_NAMES, FeatureEncoder, raw_features
from app.detection.labels import TruthLabels, dev_labels
from app.evaluation.metrics import triage_scores
from app.intel.ioc import IocStore
from app.schemas.alert import INVESTIGATION_SELECTION, Alert
from app.storage.repository import TruthStore
from app.study.config import StudyConfig
from app.study.variants import scores_dict

RESULT_LABEL = "detection baselines, dev scenarios, not paper results"
TRAIN_FRACTION = 0.6


def _key(a: Alert) -> tuple[Any, ...]:
    return (a.timestamp, a.source_file, a.source_line, a.alert_id)


def time_split(alerts: Sequence[Alert], fraction: float = TRAIN_FRACTION) -> tuple[list[Alert], list[Alert]]:
    ordered = sorted(alerts, key=_key)
    if not ordered:
        return [], []
    t0, t1 = ordered[0].timestamp, ordered[-1].timestamp
    cutoff = t0 + (t1 - t0) * fraction
    return [a for a in ordered if a.timestamp < cutoff], [a for a in ordered if a.timestamp >= cutoff]


def feature_rows(alerts: Sequence[Alert], iocs: IocStore | None = None) -> dict[str, dict[str, Any]]:
    """Features per scenario over its time-ordered alerts, keyed by alert id."""
    by_scenario: dict[str, list[Alert]] = {}
    for a in alerts:
        by_scenario.setdefault(a.scenario, []).append(a)
    out: dict[str, dict[str, Any]] = {}
    for items in by_scenario.values():
        items = sorted(items, key=_key)
        out.update(zip((a.alert_id for a in items), raw_features(items, iocs)))
    return out


def _balance(alerts: Sequence[Alert], labels: dict[str, TruthLabels]) -> dict[str, Any]:
    ev = [labels[a.alert_id].event_attack for a in alerts]
    tm = [labels[a.alert_id].time_attack for a in alerts]
    return {"n": len(alerts),
            "event_label": {"attack": sum(v is True for v in ev), "benign": sum(v is False for v in ev),
                            "unavailable": sum(v is None for v in ev)},
            "time_label": {"attack": sum(tm), "benign": len(tm) - sum(tm)}}


def _score(test: Sequence[Alert], predicted: np.ndarray[Any, Any],
           labels: dict[str, TruthLabels]) -> dict[str, Any]:
    pred = {a.alert_id: bool(p) for a, p in zip(test, predicted)}
    scored = [a.alert_id for a in test if labels[a.alert_id].event_attack is not None]
    event = triage_scores({i: pred[i] for i in scored},
                          {i: bool(labels[i].event_attack) for i in scored})
    time_ = triage_scores(pred, {a.alert_id: labels[a.alert_id].time_attack for a in test})
    return {"event_label": scores_dict(event), "time_label": scores_dict(time_)}


def fit_and_score(train: Sequence[Alert], test: Sequence[Alert], labels: dict[str, TruthLabels], *,
                  seed: int, rows: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    missing = [a.alert_id for a in (*train, *test) if a.alert_id not in labels]
    if missing:
        raise ValueError(f"{len(missing)} alerts have no truth row (first: {missing[0]})")
    rows = rows if rows is not None else feature_rows([*train, *test])
    tr_rows, te_rows = [rows[a.alert_id] for a in train], [rows[a.alert_id] for a in test]
    enc = FeatureEncoder.fit(tr_rows)  # training split only
    x_tr, x_te = enc.transform(tr_rows), enc.transform(te_rows)
    models: dict[str, Any] = {}

    forest = IsolationForest(n_estimators=200, contamination="auto", random_state=seed)
    forest.fit(x_tr)
    models["isolation_forest"] = _score(test, forest.predict(x_te) == -1, labels)

    idx = [i for i, a in enumerate(train) if labels[a.alert_id].event_attack is not None]
    y = np.array([bool(labels[train[i].alert_id].event_attack) for i in idx])
    if len(set(y.tolist())) < 2:
        models["hist_gradient_boosting"] = {"skipped": "training split has a single event_label class"}
    else:
        clf = HistGradientBoostingClassifier(random_state=seed)
        clf.fit(x_tr[idx], y)
        models["hist_gradient_boosting"] = _score(test, clf.predict(x_te), labels)

    unseen = {col: sum(1 for r in te_rows if str(r[col]) not in enc.vocab[col]) for col in enc.vocab}
    return {"label": RESULT_LABEL, "features": list(FEATURE_NAMES), "seed": seed,
            "class_balance": {"train": _balance(train, labels), "test": _balance(test, labels)},
            "test_rows_with_unseen_category": unseen, "models": models}


def load_pool(processed_dir: str | Path, scenario: str) -> list[Alert]:
    return list(iter_alert_file(Path(processed_dir) / f"{scenario}.alerts.jsonl",
                                INVESTIGATION_SELECTION))


def run_ml_baselines(processed_dir: str | Path, truth: TruthStore, config: StudyConfig,
                     scenarios: Sequence[str], fraction: float = TRAIN_FRACTION) -> dict[str, Any]:
    for s in scenarios:
        config.split.require_dev(s)  # before any file is read
    pools = {s: load_pool(processed_dir, s) for s in scenarios}
    labels: dict[str, TruthLabels] = {}
    for s in scenarios:
        labels.update(dev_labels(truth, s, config))
    rows = feature_rows([a for p in pools.values() for a in p])
    seed = config.variant_seed
    splits: dict[str, Any] = {}
    for s in scenarios:
        train, test = time_split(pools[s], fraction)
        splits[f"time:{s}"] = {"train": s, "test": s, "rule": f"first {fraction:.0%} of the timeline",
                               "cutoff": (test[0].timestamp.isoformat() if test else None),
                               **fit_and_score(train, test, labels, seed=seed, rows=rows)}
    for a in scenarios:
        for b in scenarios:
            if a != b:
                splits[f"cross:{a}->{b}"] = {"train": a, "test": b, "rule": "cross-scenario",
                                             **fit_and_score(pools[a], pools[b], labels, seed=seed,
                                                             rows=rows)}
    return {"label": RESULT_LABEL, "scenarios": list(scenarios), "features": list(FEATURE_NAMES),
            "splits": splits}
