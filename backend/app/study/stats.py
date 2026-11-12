"""Statistics of the final study: paired bootstrap CIs, Holm correction, effect sizes.

Why paired: every arm and every variant is scored on the **same cases**, so a
comparison is a difference of per-case values (b - a) on the case pairs both
sides scored. Pairs where either side is ``None`` (a metric undefined for
that case, e.g. citation precision when nothing was cited) are dropped and
counted (``dropped_pairs``); nothing is imputed.

- :func:`paired_bootstrap`: percentile CI of the mean difference from
  ``resamples`` (default 10,000) resamples of the case pairs with
  replacement, seeded (``numpy.random.default_rng(seed)``), optionally
  stratified (resampled within each stratum, e.g. scenario, so every
  resample keeps the per-scenario case counts). Two-sided bootstrap p-value
  ``min(1, 2 * min(#{d* <= 0} + 1, #{d* >= 0} + 1) / (R + 1))``: identical
  arms give p = 1, a difference that never crosses zero gives about 2/(R+1).
- :func:`holm`: Holm-Bonferroni step-down adjustment over a declared family
  (monotone, capped at 1).
- :func:`effect_sizes`: mean difference, Cohen's d_z (mean / sd of the
  differences; ``None`` when the sd is 0) and, for 0/1 outcomes, the
  discordant pair counts.
- :func:`compare_family`: runs every declared :class:`PairedComparison` over
  per-case rows and adjusts the family with Holm.

The comparison family is declared in ``experiments/config/statistics.json``
before the held-out runs (it is hashed into the protocol freeze), never
chosen after looking at results.
"""

from __future__ import annotations

import csv
import json
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

REPO = Path(__file__).resolve().parents[3]
DEFAULT_STATISTICS_CONFIG = REPO / "experiments" / "config" / "statistics.json"


@dataclass(frozen=True)
class BootstrapResult:
    n: int
    dropped_pairs: int
    mean_a: float | None
    mean_b: float | None
    difference: float | None  # mean(b - a)
    ci_low: float | None
    ci_high: float | None
    p_value: float | None
    resamples: int
    confidence: float
    seed: int


@dataclass(frozen=True)
class PairedComparison:
    name: str
    metric: str
    a: tuple[str, str]  # (variant, arm)
    b: tuple[str, str]
    note: str = ""


@dataclass(frozen=True)
class StatisticsConfig:
    seed: int
    resamples: int
    confidence: float
    family: tuple[PairedComparison, ...]
    stratify_by: str | None = "scenario"


def load_statistics_config(path: str | Path = DEFAULT_STATISTICS_CONFIG) -> StatisticsConfig:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    family = tuple(
        PairedComparison(c["name"], c["metric"], (c["a"]["variant"], c["a"]["arm"]),
                         (c["b"]["variant"], c["b"]["arm"]), c.get("note", ""))
        for c in data["family"])
    names = [c.name for c in family]
    if len(set(names)) != len(names):
        raise ValueError("comparison names in the family must be unique")
    resamples = int(data["resamples"])
    confidence = float(data["confidence"])
    if resamples < 100 or not 0.5 < confidence < 1:
        raise ValueError("resamples must be >= 100 and confidence in (0.5, 1)")
    return StatisticsConfig(int(data["seed"]), resamples, confidence, family,
                            data.get("stratify_by", "scenario"))


def _pairs(a: Sequence[float | None], b: Sequence[float | None],
           strata: Sequence[str] | None) -> tuple[np.ndarray, np.ndarray, list[str], int]:
    if len(a) != len(b) or (strata is not None and len(strata) != len(a)):
        raise ValueError("paired samples must have the same length")
    keep = [i for i in range(len(a)) if a[i] is not None and b[i] is not None]
    xa = np.array([float(v) for v in (a[i] for i in keep) if v is not None], dtype=np.float64)
    xb = np.array([float(v) for v in (b[i] for i in keep) if v is not None], dtype=np.float64)
    st = [strata[i] for i in keep] if strata is not None else ["all"] * len(keep)
    return xa, xb, st, len(a) - len(keep)


def paired_bootstrap(a: Sequence[float | None], b: Sequence[float | None], *, seed: int,
                     resamples: int = 10_000, confidence: float = 0.95,
                     strata: Sequence[str] | None = None) -> BootstrapResult:
    xa, xb, st, dropped = _pairs(a, b, strata)
    n = len(xa)
    if n == 0:
        return BootstrapResult(0, dropped, None, None, None, None, None, None, resamples,
                               confidence, seed)
    d = xb - xa
    rng = np.random.default_rng(seed)
    groups: dict[str, list[int]] = {}
    for i, s in enumerate(st):
        groups.setdefault(s, []).append(i)
    sums = np.zeros(resamples, dtype=float)
    for s in sorted(groups):
        idx = np.array(groups[s])
        draws = rng.integers(0, len(idx), size=(resamples, len(idx)))
        sums += d[idx][draws].sum(axis=1)
    means = sums / n
    alpha = 1 - confidence
    lo, hi = np.quantile(means, [alpha / 2, 1 - alpha / 2])
    diff = float(d.mean())
    # snap float noise so a constant difference reports exactly that constant
    lo, hi = (diff if math.isclose(lo, diff, abs_tol=1e-12) else float(lo),
              diff if math.isclose(hi, diff, abs_tol=1e-12) else float(hi))
    below = int(np.sum(means <= 1e-12))
    above = int(np.sum(means >= -1e-12))
    p = min(1.0, 2 * min(below + 1, above + 1) / (resamples + 1))
    return BootstrapResult(n, dropped, float(xa.mean()), float(xb.mean()), diff, lo, hi, p,
                           resamples, confidence, seed)


def holm(p_values: Mapping[str, float]) -> dict[str, float]:
    """Holm-Bonferroni adjusted p-values (step-down, monotone, capped at 1)."""
    order = sorted(p_values, key=lambda k: (p_values[k], k))
    m = len(order)
    adjusted: dict[str, float] = {}
    running = 0.0
    for rank, key in enumerate(order):
        running = max(running, min(1.0, (m - rank) * p_values[key]))
        adjusted[key] = running
    return adjusted


def effect_sizes(a: Sequence[float | None], b: Sequence[float | None]) -> dict[str, Any]:
    xa, xb, _, dropped = _pairs(a, b, None)
    if len(xa) == 0:
        return {"n": 0, "dropped_pairs": dropped, "mean_difference": None, "cohens_dz": None,
                "discordant_a_better": None, "discordant_b_better": None}
    d = xb - xa
    sd = float(d.std(ddof=1)) if len(d) > 1 else 0.0
    binary = bool(np.all(np.isin(xa, (0.0, 1.0))) and np.all(np.isin(xb, (0.0, 1.0))))
    return {
        "n": len(d), "dropped_pairs": dropped, "mean_difference": float(d.mean()),
        "cohens_dz": float(d.mean()) / sd if sd > 0 else None,
        "discordant_a_better": int(np.sum((xa == 1) & (xb == 0))) if binary else None,
        "discordant_b_better": int(np.sum((xa == 0) & (xb == 1))) if binary else None,
    }


def _side(rows: Iterable[Mapping[str, Any]], variant: str, arm: str,
          metric: str) -> dict[str, tuple[Any, str]]:
    return {str(r["case_key"]): (r.get(metric), str(r.get("scenario", "all")))
            for r in rows if r["variant"] == variant and r["arm"] == arm}


def compare_family(rows: Sequence[Mapping[str, Any]], config: StatisticsConfig) -> list[dict[str, Any]]:
    """Every declared comparison over per-case rows, Holm-adjusted across the family.

    Rows need ``variant``, ``arm``, ``case_key`` (same key = same case on
    both sides, e.g. scenario/truncation/repeat/case id) and the metric.
    Comparisons without any pair are reported with ``p_value`` None and are
    left out of the Holm family (recorded as ``in_family = False``).
    """
    out: list[dict[str, Any]] = []
    for i, c in enumerate(config.family):
        sa = _side(rows, *c.a, c.metric)
        sb = _side(rows, *c.b, c.metric)
        keys = sorted(set(sa) & set(sb))
        va = [sa[k][0] for k in keys]
        vb = [sb[k][0] for k in keys]
        strata = [sa[k][1] for k in keys] if config.stratify_by else None
        res = paired_bootstrap(va, vb, seed=config.seed + i, resamples=config.resamples,
                               confidence=config.confidence, strata=strata)
        out.append({"name": c.name, "metric": c.metric, "a": "/".join(c.a), "b": "/".join(c.b),
                    "note": c.note, "unmatched_cases": len(set(sa) ^ set(sb)),
                    **res.__dict__, **{f"effect_{k}": v for k, v in effect_sizes(va, vb).items()
                                       if k not in ("n", "dropped_pairs")}})
    adjusted = holm({r["name"]: r["p_value"] for r in out if r["p_value"] is not None})
    for r in out:
        r["in_family"] = r["name"] in adjusted
        r["p_holm"] = adjusted.get(r["name"], float("nan")) if r["in_family"] else None
    return out


def write_paired_csv(rows: Sequence[Mapping[str, Any]], path: str | Path) -> Path:
    """Per-case paired data, one row per (case, variant, arm), columns in first-seen order."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    fields: list[str] = []
    for r in rows:
        fields.extend(k for k in r if k not in fields)
    with out.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k) for k in fields})
    return out
