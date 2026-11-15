"""ML detection baselines on AIT-ADS dev scenarios (Waves B4, B4 fixes). Off-the-shelf models only.

Labelled everywhere: **detection baselines, dev scenarios, not paper results**.
CICIDS2017 is not available (its download needs a registration form).

- Alerts: the investigation-eligible pool of each dev scenario (same pool
  as the study and the Sigma dev baseline).
- Features: :mod:`app.detection.features` (label-free), computed per
  scenario over the whole time-ordered pool; trailing-window counts look
  only at strictly earlier alerts.
- Labels: only through :func:`app.detection.labels.dev_labels` (truth area),
  used as the supervised target at training time and as truth at
  evaluation time. Target = ``event_label`` attack (alerts without a
  verified event label are left out of training and of event-label
  scoring); ``time_label`` is the sensitivity check on the same predictions.
- Models, seeded with the study seed (``variants.seed``):
  ``IsolationForest(n_estimators=200, contamination="auto")`` fitted on the
  training features without labels (prediction -1 = attack; "auto" is
  scikit-learn's own threshold, so the base rate is never fed in), and
  ``HistGradientBoostingClassifier`` (defaults).
- Splits (B4 fixes, 2026-11-10):

  (a) **cross-scenario, the primary split**: train on one dev scenario,
      test on the other, both directions;
  (b) **leave-one-phase-out** inside each scenario: for every labels.csv
      phase that holds alerts, train on every other alert of the scenario
      and test on the alerts inside that phase's interval; the fold
      predictions are pooled (each tested alert is predicted exactly once)
      and also reported per phase. Alerts outside every phase are training
      data only, so the pooled scores measure separation *inside* attack
      windows (event-attack vs event-benign alerts there), not the
      false-positive rate on quiet periods; that is stated with the numbers.

  The old 60/40 timeline split was removed: on both dev scenarios its
  training part held no attack alert (HistGradientBoosting could not train).
- Feature sets: ``all`` and the ablation ``no_detector_rule_id``
  (:data:`ABLATION_DROPPED` removed), to see how much of the cross-scenario
  F1 is detector/rule identity. Both F1s are reported.
- Importances: scikit-learn ``permutation_importance`` of the
  HistGradientBoosting model on the test split (event-labelled rows, F1,
  5 repeats, seeded), cross-scenario splits only. They describe this model
  on this split, nothing causal.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

import time

import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from app.alert_pipeline import iter_alert_file
from app.detection.features import CATEGORICAL, FEATURE_NAMES, FeatureEncoder, raw_features
from app.detection.labels import TruthLabels, dev_labels
from app.evaluation.metrics import triage_scores
from app.intel.ioc import IocStore
from app.schemas.alert import INVESTIGATION_SELECTION, Alert
from app.storage.repository import TruthStore
from app.study.config import StudyConfig
from app.study.variants import scores_dict

RESULT_LABEL = "detection baselines, dev scenarios, not paper results"
ABLATION_DROPPED: tuple[str, ...] = ("detector", "rule_id")
FEATURE_SETS: dict[str, tuple[str, ...]] = {
    "all": FEATURE_NAMES,
    "no_detector_rule_id": tuple(f for f in FEATURE_NAMES if f not in ABLATION_DROPPED),
}
IMPORTANCE_REPEATS = 5
MODELS = ("isolation_forest", "hist_gradient_boosting")
# Comparison (C4, 2026-11-15): is the dependence on the per-host alert rate a property of one model
# or of the data? A linear model (one-hot categoricals, scaled numerics, class_weight="balanced"
# so the minority class is not ignored) and a bagged forest are fitted on the same splits.
COMPARISON_MODELS = ("isolation_forest", "hist_gradient_boosting", "logistic_regression", "random_forest")
SUPERVISED = ("hist_gradient_boosting", "logistic_regression", "random_forest")
COMPARISON_FEATURE_SETS: dict[str, tuple[str, ...]] = {
    "all": FEATURE_NAMES,
    # the B4 importances pointed at the per-host alert rate; this set tests that dependence directly
    "no_host_counts": tuple(f for f in FEATURE_NAMES if f not in ("host_count_60s", "host_count_600s")),
}


def _key(a: Alert) -> tuple[Any, ...]:
    return (a.timestamp, a.source_file, a.source_line, a.alert_id)


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


def _ranking(scores: dict[str, float] | None, ids: Sequence[str], truth: dict[str, bool]) -> dict[str, Any]:
    """Threshold-free metrics of a score (higher = more attack-like); None with one class or no score."""
    if scores is None or len({truth[i] for i in ids}) < 2:
        return {"pr_auc": None, "roc_auc": None}
    y = [truth[i] for i in ids]
    x = [scores[i] for i in ids]
    return {"pr_auc": round(float(average_precision_score(y, x)), 4),
            "roc_auc": round(float(roc_auc_score(y, x)), 4)}


def _with_rates(d: dict[str, Any]) -> dict[str, Any]:
    n = d["tp"] + d["fp"] + d["fn"] + d["tn"]
    d["accuracy"] = round((d["tp"] + d["tn"]) / n, 4) if n else None
    d["fpr"] = round(d["fp"] / (d["fp"] + d["tn"]), 4) if d["fp"] + d["tn"] else None
    return d


def _score_pred(pred: dict[str, bool], ids: Sequence[str], labels: dict[str, TruthLabels],
                scores: dict[str, float] | None = None) -> dict[str, Any]:
    scored = [i for i in ids if labels[i].event_attack is not None]
    ev_truth = {i: bool(labels[i].event_attack) for i in scored}
    tm_truth = {i: labels[i].time_attack for i in ids}
    event = triage_scores({i: pred[i] for i in scored}, ev_truth)
    time_ = triage_scores({i: pred[i] for i in ids}, tm_truth)
    return {"event_label": {**_with_rates(scores_dict(event)), **_ranking(scores, scored, ev_truth)},
            "time_label": {**_with_rates(scores_dict(time_)), **_ranking(scores, list(ids), tm_truth)}}


def _columns(features: Sequence[str]) -> list[int]:
    unknown = [f for f in features if f not in FEATURE_NAMES]
    if unknown:
        raise ValueError(f"unknown features: {unknown}")
    return [FEATURE_NAMES.index(f) for f in features]


def _linear(features: Sequence[str], seed: int) -> Pipeline:
    cat = [k for k, f in enumerate(features) if f in CATEGORICAL]
    num = [k for k, f in enumerate(features) if f not in CATEGORICAL]
    prep = ColumnTransformer([("cat", OneHotEncoder(handle_unknown="ignore"), cat),
                              ("num", StandardScaler(), num)])
    return Pipeline([("prep", prep), ("clf", LogisticRegression(max_iter=1000, class_weight="balanced",
                                                                random_state=seed))])


def _supervised(name: str, features: Sequence[str], seed: int) -> Any:
    if name == "hist_gradient_boosting":
        return HistGradientBoostingClassifier(random_state=seed)
    if name == "random_forest":
        return RandomForestClassifier(n_estimators=200, random_state=seed, n_jobs=1)
    return _linear(features, seed)


def _predict(train: Sequence[Alert], test: Sequence[Alert], labels: dict[str, TruthLabels], *,
             seed: int, rows: dict[str, dict[str, Any]], features: Sequence[str],
             importances: bool, models: Sequence[str] = MODELS
             ) -> tuple[dict[str, dict[str, bool] | str], dict[str, Any]]:
    """Per model: alert id -> predicted attack, or a skip reason. Extras: scores, timing,
    importances, unseen categories. Encoders and scalers are fitted on the training split only."""
    cols = _columns(features)
    tr_rows, te_rows = [rows[a.alert_id] for a in train], [rows[a.alert_id] for a in test]
    enc = FeatureEncoder.fit(tr_rows)  # training split only
    x_tr, x_te = enc.transform(tr_rows)[:, cols], enc.transform(te_rows)[:, cols]
    ids = [a.alert_id for a in test]
    preds: dict[str, dict[str, bool] | str] = {}
    scores: dict[str, dict[str, float]] = {}
    timing: dict[str, dict[str, float]] = {}
    extras: dict[str, Any] = {
        "unseen": {col: sum(1 for r in te_rows if str(r[col]) not in enc.vocab[col])
                   for col in enc.vocab if col in features},
        "scores": scores, "timing": timing}

    if "isolation_forest" in models:
        t0 = time.perf_counter()
        forest = IsolationForest(n_estimators=200, contamination="auto", random_state=seed)
        forest.fit(x_tr)
        t1 = time.perf_counter()
        preds["isolation_forest"] = dict(zip(ids, (bool(p) for p in forest.predict(x_te) == -1)))
        scores["isolation_forest"] = dict(zip(ids, (float(-v) for v in forest.score_samples(x_te))))
        timing["isolation_forest"] = {"fit_seconds": round(t1 - t0, 4),
                                      "predict_seconds": round(time.perf_counter() - t1, 4)}

    idx = [i for i, a in enumerate(train) if labels[a.alert_id].event_attack is not None]
    y = np.array([bool(labels[train[i].alert_id].event_attack) for i in idx])
    for name in (m for m in models if m in SUPERVISED):
        if len(set(y.tolist())) < 2:
            preds[name] = "training split has a single event_label class"
            continue
        t0 = time.perf_counter()
        clf = _supervised(name, features, seed)
        clf.fit(x_tr[idx], y)
        t1 = time.perf_counter()
        preds[name] = dict(zip(ids, (bool(p) for p in clf.predict(x_te))))
        scores[name] = dict(zip(ids, (float(v) for v in clf.predict_proba(x_te)[:, 1])))
        timing[name] = {"fit_seconds": round(t1 - t0, 4), "predict_seconds": round(time.perf_counter() - t1, 4)}
        if importances and name == "hist_gradient_boosting":
            te_idx = [i for i, a in enumerate(test) if labels[a.alert_id].event_attack is not None]
            y_te = np.array([bool(labels[test[i].alert_id].event_attack) for i in te_idx])
            if te_idx and len(set(y_te.tolist())) == 2:
                res = permutation_importance(clf, x_te[te_idx], y_te, scoring="f1",
                                             n_repeats=IMPORTANCE_REPEATS, random_state=seed)
                table = [{"feature": f, "mean": round(float(m), 6), "std": round(float(s), 6)}
                         for f, m, s in zip(features, res.importances_mean, res.importances_std)]
                extras["permutation_importance"] = sorted(table, key=lambda r: (-r["mean"], r["feature"]))
            else:
                extras["permutation_importance"] = {"skipped": "test split has a single event_label class"}
    return preds, extras


def fit_and_score(train: Sequence[Alert], test: Sequence[Alert], labels: dict[str, TruthLabels], *,
                  seed: int, rows: dict[str, dict[str, Any]] | None = None,
                  features: Sequence[str] = FEATURE_NAMES, importances: bool = False,
                  models: Sequence[str] = MODELS) -> dict[str, Any]:
    missing = [a.alert_id for a in (*train, *test) if a.alert_id not in labels]
    if missing:
        raise ValueError(f"{len(missing)} alerts have no truth row (first: {missing[0]})")
    rows = rows if rows is not None else feature_rows([*train, *test])
    preds, extras = _predict(train, test, labels, seed=seed, rows=rows, features=features,
                             importances=importances, models=models)
    ids = [a.alert_id for a in test]
    out: dict[str, Any] = {}
    for name, p in preds.items():
        out[name] = ({"skipped": p} if isinstance(p, str)
                     else _score_pred(p, ids, labels, extras["scores"].get(name)))
    if "permutation_importance" in extras and "skipped" not in out.get("hist_gradient_boosting", {"skipped": 1}):
        out["hist_gradient_boosting"]["permutation_importance"] = extras["permutation_importance"]
    result = {"label": RESULT_LABEL, "features": list(features), "seed": seed,
              "class_balance": {"train": _balance(train, labels), "test": _balance(test, labels)},
              "test_rows_with_unseen_category": extras["unseen"], "models": out}
    if tuple(models) != MODELS:  # comparison runs also report timing (the default output is unchanged)
        result["timing"] = extras["timing"]
    return result


def lopo_folds(alerts: Sequence[Alert], labels: dict[str, TruthLabels]
               ) -> list[tuple[str, list[Alert], list[Alert]]]:
    """(phase, train, test) per phase holding alerts, phases in first-seen time order."""
    ordered = sorted(alerts, key=_key)
    phases: list[str] = []
    for a in ordered:
        ph = labels[a.alert_id].phase
        if ph is not None and ph not in phases:
            phases.append(ph)
    return [(ph, [a for a in ordered if labels[a.alert_id].phase != ph],
             [a for a in ordered if labels[a.alert_id].phase == ph]) for ph in phases]


def lopo_scores(alerts: Sequence[Alert], labels: dict[str, TruthLabels], *, seed: int,
                rows: dict[str, dict[str, Any]] | None = None,
                features: Sequence[str] = FEATURE_NAMES) -> dict[str, Any]:
    """Leave-one-phase-out: pooled fold predictions plus per-phase scores."""
    rows = rows if rows is not None else feature_rows(alerts)
    pooled: dict[str, dict[str, bool]] = {m: {} for m in MODELS}
    skipped: dict[str, list[str]] = {m: [] for m in MODELS}
    per_phase = []
    for phase, train, test in lopo_folds(alerts, labels):
        preds, _ = _predict(train, test, labels, seed=seed, rows=rows, features=features,
                            importances=False)
        ids = [a.alert_id for a in test]
        phase_models: dict[str, Any] = {}
        for name, p in preds.items():
            if isinstance(p, str):
                skipped[name].append(phase)
                phase_models[name] = {"skipped": p}
            else:
                pooled[name].update(p)
                phase_models[name] = _score_pred(p, ids, labels)
        bal = _balance(test, labels)
        per_phase.append({"phase": phase, "n_test": len(test), "event_attack": bal["event_label"]["attack"],
                          "event_benign": bal["event_label"]["benign"], "models": phase_models})
    pooled_scores: dict[str, Any] = {}
    for name in MODELS:
        ids = sorted(pooled[name])
        pooled_scores[name] = ({**_score_pred(pooled[name], ids, labels), "phases_skipped": skipped[name]}
                               if ids else {"skipped": "every fold skipped"})
    return {"label": RESULT_LABEL, "rule": "leave-one-phase-out (test = alerts inside the phase)",
            "features": list(features), "seed": seed, "pooled": pooled_scores, "per_phase": per_phase}


def load_pool(processed_dir: str | Path, scenario: str) -> list[Alert]:
    return list(iter_alert_file(Path(processed_dir) / f"{scenario}.alerts.jsonl",
                                INVESTIGATION_SELECTION))


def run_ml_baselines(processed_dir: str | Path, truth: TruthStore, config: StudyConfig,
                     scenarios: Sequence[str]) -> dict[str, Any]:
    for s in scenarios:
        config.split.require_dev(s)  # before any file is read
    pools = {s: load_pool(processed_dir, s) for s in scenarios}
    labels: dict[str, TruthLabels] = {}
    for s in scenarios:
        labels.update(dev_labels(truth, s, config))
    rows = feature_rows([a for p in pools.values() for a in p])
    seed = config.variant_seed
    splits: dict[str, Any] = {}
    for set_name, feats in FEATURE_SETS.items():
        for a in scenarios:
            for b in scenarios:
                if a != b:
                    splits[f"cross:{a}->{b}:{set_name}"] = {
                        "train": a, "test": b, "rule": "cross-scenario (primary)", "feature_set": set_name,
                        **fit_and_score(pools[a], pools[b], labels, seed=seed, rows=rows, features=feats,
                                        importances=True)}
    lopo: dict[str, Any] = {}
    for set_name, feats in FEATURE_SETS.items():
        for s in scenarios:
            lopo[f"lopo:{s}:{set_name}"] = {"scenario": s, "feature_set": set_name,
                                            **lopo_scores(pools[s], labels, seed=seed, rows=rows,
                                                          features=feats)}
    comparison: dict[str, Any] = {}
    for set_name, feats in COMPARISON_FEATURE_SETS.items():
        for a in scenarios:
            for b in scenarios:
                if a != b:
                    comparison[f"cross:{a}->{b}:{set_name}"] = {
                        "train": a, "test": b, "feature_set": set_name,
                        **fit_and_score(pools[a], pools[b], labels, seed=seed, rows=rows, features=feats,
                                        models=COMPARISON_MODELS)}
    return {"label": RESULT_LABEL, "scenarios": list(scenarios), "features": list(FEATURE_NAMES),
            "feature_sets": {k: list(v) for k, v in FEATURE_SETS.items()},
            "splits": splits, "lopo": lopo,
            "comparison": {"note": ("four models on the cross-scenario splits, with and without the "
                                    "per-host rate features; scores are uncalibrated; dev scenarios "
                                    "only"), "models": list(COMPARISON_MODELS), "splits": comparison}}


def train_bundle(processed_dir: str | Path, truth: TruthStore, config: StudyConfig,
                 scenarios: Sequence[str], *, features: Sequence[str] = FEATURE_NAMES,
                 now: Any = None) -> Any:
    """Fit the operational bundle (C4) on the pooled dev scenarios; labels only via dev_labels.

    Evaluation stays with :func:`run_ml_baselines` (cross-scenario and leave-one-phase-out): this
    model is trained on everything it is given, so its scores on those scenarios are in-sample.
    The metadata records the training scenarios, class balance, seed, versions and the in-sample
    permutation importance order used for the per-alert explanation.
    """
    import sklearn
    from datetime import datetime, timezone

    from app.detection.ml_model import ModelBundle, bundle_version

    for s in scenarios:
        config.split.require_dev(s)  # before any file is read
    pools = {s: load_pool(processed_dir, s) for s in scenarios}
    labels: dict[str, TruthLabels] = {}
    for s in scenarios:
        labels.update(dev_labels(truth, s, config))
    alerts = [a for s in scenarios for a in pools[s]]
    rows: dict[str, dict[str, Any]] = {}
    for s in scenarios:  # per-host counts per scenario (separate networks, separate clocks)
        rows.update(feature_rows(pools[s]))
    cols = _columns(features)
    train_rows = [rows[a.alert_id] for a in alerts]
    enc = FeatureEncoder.fit(train_rows)
    x = enc.transform(train_rows)[:, cols]
    seed = config.variant_seed
    idx = [i for i, a in enumerate(alerts) if labels[a.alert_id].event_attack is not None]
    y = np.array([bool(labels[alerts[i].alert_id].event_attack) for i in idx])
    if len(set(y.tolist())) < 2:
        raise ValueError("the training data has a single event_label class")
    t0 = time.perf_counter()
    hgb = HistGradientBoostingClassifier(random_state=seed).fit(x[idx], y)
    forest = IsolationForest(n_estimators=200, contamination="auto", random_state=seed).fit(x)
    fit_seconds = round(time.perf_counter() - t0, 2)
    imp = permutation_importance(hgb, x[idx], y, scoring="f1", n_repeats=3, random_state=seed)
    order = [f for _, f in sorted(zip(imp.importances_mean, features), key=lambda t: (-t[0], t[1]))]
    created = (now or datetime.now(timezone.utc)).isoformat()
    meta = {"created_utc": created, "label": RESULT_LABEL, "trained_on": list(scenarios),
            "rows": len(alerts), "event_labelled_rows": len(idx), "event_attack_rows": int(y.sum()),
            "seed": seed, "sklearn": sklearn.__version__, "models": ["hist_gradient_boosting",
                                                                  "isolation_forest"],
            "fit_seconds": fit_seconds, "importance_order": order,
            "importance_note": "permutation importance on the training data (in-sample, global)",
            "evaluation": "see ml-baselines (cross-scenario, leave-one-phase-out); not re-measured here"}
    return ModelBundle(bundle_version(meta), tuple(features), enc.vocab,
                       {"hist_gradient_boosting": hgb, "isolation_forest": forest}, meta)
