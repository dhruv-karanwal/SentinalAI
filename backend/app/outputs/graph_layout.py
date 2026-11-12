"""Deterministic force layout for entity graphs (console v2: incident graph, report PDF).

The console draws the same graph in the browser (``frontend/src/lib/graph.ts``) and the report
PDF draws it here, so the two must place every node at the same position. Both use only
``+ - * /`` and ``sqrt`` on IEEE doubles in the same order, start from positions derived from
an FNV-1a hash of the node id (no random numbers) and run a fixed number of iterations, so the
results agree bit for bit; ``tests/test_analytics.py`` checks this module against the fixture
the frontend test also reads (``frontend/src/lib/graph.fixture.json``).

Algorithm: Fruchterman-Reingold with linear cooling and a weak pull to the centre.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from math import sqrt

ITERATIONS = 150
PAD = 16.0
GRAVITY = 0.02


def fnv1a(text: str) -> int:
    """32-bit FNV-1a over UTF-16 code units (what JavaScript's charCodeAt returns)."""
    h = 0x811C9DC5
    data = text.encode("utf-16-le")
    for i in range(0, len(data), 2):
        h ^= data[i] | (data[i + 1] << 8)
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


@dataclass(frozen=True)
class Placed:
    id: str
    x: float
    y: float


def layout(node_ids: Sequence[str], edges: Sequence[tuple[str, str]], width: float,
           height: float, iterations: int = ITERATIONS) -> list[Placed]:
    """Positions inside ``[PAD, width - PAD] x [PAD, height - PAD]``, in ``node_ids`` order."""
    n = len(node_ids)
    if n == 0:
        return []
    index = {nid: i for i, nid in enumerate(node_ids)}
    w = width - 2 * PAD
    h = height - 2 * PAD
    xs: list[float] = []
    ys: list[float] = []
    for nid in node_ids:
        hv = fnv1a(nid)
        xs.append(PAD + ((hv & 0xFFFF) / 65535) * w)
        ys.append(PAD + ((hv >> 16) / 65535) * h)
    if n == 1:
        return [Placed(node_ids[0], width / 2, height / 2)]
    k = sqrt((w * h) / n)
    pairs = [(index[a], index[b]) for a, b in edges if a in index and b in index and a != b]
    cx = width / 2
    cy = height / 2
    t0 = w / 10
    for it in range(iterations):
        dx = [0.0] * n
        dy = [0.0] * n
        for i in range(n):
            for j in range(i + 1, n):
                ddx = xs[i] - xs[j]
                ddy = ys[i] - ys[j]
                d2 = ddx * ddx + ddy * ddy
                if d2 < 1e-9:
                    ddx = 0.01 * (i - j)
                    ddy = 0.01
                    d2 = ddx * ddx + ddy * ddy
                d = sqrt(d2)
                f = (k * k) / d
                fx = (ddx / d) * f
                fy = (ddy / d) * f
                dx[i] += fx
                dy[i] += fy
                dx[j] -= fx
                dy[j] -= fy
        for a, b in pairs:
            ddx = xs[a] - xs[b]
            ddy = ys[a] - ys[b]
            d = sqrt(ddx * ddx + ddy * ddy)
            if d < 1e-9:
                continue
            f = (d * d) / k
            fx = (ddx / d) * f
            fy = (ddy / d) * f
            dx[a] -= fx
            dy[a] -= fy
            dx[b] += fx
            dy[b] += fy
        temp = t0 * (1 - it / iterations)
        for i in range(n):
            dx[i] -= (xs[i] - cx) * GRAVITY * k
            dy[i] -= (ys[i] - cy) * GRAVITY * k
            length = sqrt(dx[i] * dx[i] + dy[i] * dy[i])
            if length > 0:
                step = length if length < temp else temp
                xs[i] += (dx[i] / length) * step
                ys[i] += (dy[i] / length) * step
            xs[i] = PAD if xs[i] < PAD else (width - PAD if xs[i] > width - PAD else xs[i])
            ys[i] = PAD if ys[i] < PAD else (height - PAD if ys[i] > height - PAD else ys[i])
    return [Placed(nid, xs[i], ys[i]) for i, nid in enumerate(node_ids)]


@dataclass(frozen=True)
class LabelBox:
    id: str
    x0: float
    y0: float
    x1: float
    y1: float
    anchor: str


def _hit(a: tuple[float, float, float, float], b: tuple[float, float, float, float]) -> bool:
    return not (a[2] <= b[0] or b[2] <= a[0] or a[3] <= b[1] or b[3] <= a[1])


def place_labels(nodes: Sequence[tuple[str, float, float, float, str]], width: float, height: float,
                 char_w: float, line_h: float, gap: float = 3.0) -> list[LabelBox]:
    """Greedy label placement without overlap (console graph and report PDF).

    ``nodes`` are ``(id, x, y, radius, text)`` in priority order (most alerts first). Each label tries
    right, left, below, above its node; a spot is taken only if it stays inside the plot and hits no
    placed label and no other node. A label that fits nowhere is left out (the console shows it on
    hover and focus; the adjacency table always has every name). Deterministic: no randomness.
    """
    node_boxes = [(nid, (x - r, y - r, x + r, y + r)) for nid, x, y, r, _ in nodes]
    placed: list[LabelBox] = []
    for nid, x, y, r, text in nodes:
        w = len(text) * char_w
        h = line_h
        candidates = [
            ("start", (x + r + gap, y - h / 2, x + r + gap + w, y + h / 2)),
            ("end", (x - r - gap - w, y - h / 2, x - r - gap, y + h / 2)),
            ("middle", (x - w / 2, y + r + gap, x + w / 2, y + r + gap + h)),
            ("middle", (x - w / 2, y - r - gap - h, x + w / 2, y - r - gap)),
        ]
        for anchor, box in candidates:
            if box[0] < 0 or box[1] < 0 or box[2] > width or box[3] > height:
                continue
            if any(_hit(box, (p.x0, p.y0, p.x1, p.y1)) for p in placed):
                continue
            if any(other != nid and _hit(box, nb) for other, nb in node_boxes):
                continue
            placed.append(LabelBox(nid, box[0], box[1], box[2], box[3], anchor))
            break
    return placed
