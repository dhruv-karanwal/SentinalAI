"""Incident reports (Wave D): one deterministic JSON body, rendered as CSV and PDF.

The body is built from the incident row and its stored alerts only, so it
holds **no labels**: ``Alert`` has no label fields and the truth area is
never read here (the report is a platform output, not a study result).

Sections:

- ``incident``: id, scenario, first/last time, severity (+ the triage row
  that set it), status, alert count, entities, triage gap;
- ``timeline``: every alert in time order (time, id, detector, rule,
  native severity, host, mapped techniques), capped at
  :data:`MAX_ROWS` rows with the number left out recorded;
- ``citations``: the evidence each timeline alert carries (first log line,
  cut at :data:`EXCERPT_CHARS`, and its log paths), same order and cap;
- ``techniques``: ATT&CK ids from the deterministic B1 mapping, with counts;
- ``recommendations``: :func:`app.outputs.playbooks.recommend` of those ids;
- ``findings`` (optional): an agent's cited ids and claims after the
  evidence verifier (kept and dropped, with reasons);
- ``charts`` (optional, added by the API since d2): the alert timeline binned by detector and
  the entity graph with node positions (``analytics.report_charts``); the console preview and
  the PDF draw these same numbers and positions;
- ``notice``: recommendations are suggestions; nothing executes without an
  approved record.

No generation time is put in the body (``reports.created_utc`` holds it),
so the same inputs give the same body.
"""

from __future__ import annotations

import csv
import io
from collections import Counter
from collections.abc import Sequence
from typing import Any
from xml.sax.saxutils import escape

from app.agent.verifier import verify_answer
from app.intel.attack import AttackKB, map_alert
from app.outputs.playbooks import recommend
from app.schemas.alert import Alert

REPORT_VERSION = "d2"
MAX_ROWS = 500
EXCERPT_CHARS = 300
CSV_COLUMNS = ("ts", "alert_id", "detector", "rule_id", "rule_name", "severity", "host_ip", "techniques")
NOTICE = ("Recommendations are playbook suggestions from the deterministic ATT&CK mapping. Nothing "
          "executes without an approved record in the approval workflow; in this build execution "
          "is simulated.")


def _key(a: Alert) -> tuple[Any, ...]:
    return (a.timestamp, a.source_file, a.source_line, a.alert_id)


def build_report(incident: dict[str, Any], alerts: Sequence[Alert], *,
                 findings: dict[str, Any] | None = None, kb: AttackKB | None = None) -> dict[str, Any]:
    ordered = sorted(alerts, key=_key)
    detail = incident.get("detail") or {}
    techniques: Counter[str] = Counter()
    timeline, citations = [], []
    for i, a in enumerate(ordered):
        tids = [m["technique_id"] for m in map_alert(a, kb)]
        techniques.update(tids)
        if i >= MAX_ROWS:
            continue
        timeline.append({"ts": a.timestamp.isoformat(), "alert_id": a.alert_id, "detector": a.detector.value,
                         "rule_id": a.rule_id, "rule_name": a.rule_name, "severity": a.severity,
                         "host_ip": None if a.host_ip is None else str(a.host_ip), "techniques": tids})
        line = a.evidence.log_lines[0] if a.evidence.log_lines else ""
        citations.append({"alert_id": a.alert_id, "detector": a.detector.value, "rule_id": a.rule_id,
                          "evidence_excerpt": line[:EXCERPT_CHARS],
                          "excerpt_truncated": len(line) > EXCERPT_CHARS,
                          "log_paths": list(a.evidence.log_paths)})
    body: dict[str, Any] = {
        "report_version": REPORT_VERSION,
        "incident": {
            "incident_id": incident["incident_id"], "scenario": incident["scenario"],
            "first_ts": str(incident["first_ts"]), "last_ts": str(incident["last_ts"]),
            "severity": incident["severity"], "severity_row": detail.get("severity_row"),
            "status": incident.get("status"), "alerts": len(ordered),
            "detectors": dict(sorted(Counter(a.detector.value for a in ordered).items())),
            "entities": list(detail.get("entities", [])), "gap_seconds": detail.get("gap_seconds"),
        },
        "timeline": timeline,
        "timeline_rows_omitted": max(0, len(ordered) - MAX_ROWS),
        "citations": citations,
        "techniques": [{"technique_id": t, "alerts": n} for t, n in sorted(techniques.items())],
        "recommendations": recommend(techniques),
        "notice": NOTICE,
    }
    if findings is not None:
        checked = verify_answer(list(findings.get("cited", [])), list(findings.get("claims", [])), ordered)
        body["findings"] = {
            "cited": checked.cited, "claims": [vars(c) | {} for c in checked.claims],
            "dropped_citations": checked.dropped_citations, "dropped_claims": checked.dropped_claims,
            "verification": checked.summary()}
    return body


def render_csv(body: dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(CSV_COLUMNS), lineterminator="\n")
    w.writeheader()
    for row in body["timeline"]:
        w.writerow({**{k: row.get(k) for k in CSV_COLUMNS}, "techniques": ";".join(row["techniques"])})
    return buf.getvalue()


# Print colours for the PDF charts (the light-theme detector tokens of the console) and the dash
# pattern that also tells the detectors apart without colour.
DETECTOR_PRINT = {"wazuh": ("#086a58", None), "suricata": ("#a3407a", (4, 2)),
                  "aminer": ("#756600", (1, 2)), "sigma": ("#5c6670", (6, 2, 1, 2))}


def _chart_flowables(charts: dict[str, Any], width_pt: float) -> list[Any]:
    """reportlab drawings of the report's timeline and entity graph (no labels, no raw text)."""
    from reportlab.graphics.shapes import Circle, Drawing, Line, Rect, String
    from reportlab.lib import colors

    out: list[Any] = []
    ts = charts.get("timeseries") or {}
    series: dict[str, list[int]] = ts.get("series") or {}
    if series:
        n = int(ts["bins"])
        h, left, bottom, top = 120.0, 36.0, 22.0, 8.0
        d = Drawing(width_pt, h)
        totals = [sum(v[i] for v in series.values()) for i in range(n)]
        peak = max(totals) or 1
        plot_w = width_pt - left - 8
        bw = plot_w / n
        for i in range(n):
            y = bottom
            for det, values in series.items():
                c = values[i]
                if not c:
                    continue
                bh = (h - bottom - top) * c / peak
                colour, _ = DETECTOR_PRINT.get(det, ("#5c6670", None))
                d.add(Rect(left + i * bw, y, max(bw - 0.5, 0.5), bh, fillColor=colors.HexColor(colour),
                           strokeColor=None))
                y += bh
        d.add(Line(left, bottom, left + plot_w, bottom, strokeColor=colors.grey, strokeWidth=0.5))
        d.add(String(2, h - top - 6, f"{peak:,}", fontSize=6))
        d.add(String(2, bottom - 2, "0", fontSize=6))
        d.add(String(left, 6, f"{ts['start']}  ->  {ts['end']}  (UTC; bins of {ts['bin_seconds']} s; "
                     "alerts per bin, stacked by detector)", fontSize=6))
        x = left + plot_w - 4
        for det in reversed(list(series)):
            colour, _ = DETECTOR_PRINT.get(det, ("#5c6670", None))
            label = f"{det} {sum(series[det]):,}"
            x -= 6 + 3.2 * len(label)
            d.add(Rect(x, h - 8, 5, 5, fillColor=colors.HexColor(colour), strokeColor=None))
            d.add(String(x + 7, h - 8, label, fontSize=6))
        out.append(d)
    g = charts.get("graph") or {}
    nodes = g.get("nodes") or []
    if nodes:
        gw, gh = float(g["width"]), float(g["height"])
        scale = min(1.0, width_pt / gw)
        d = Drawing(gw * scale, gh * scale + 14)
        pos = {n["id"]: (n["x"] * scale, (gh - n["y"]) * scale + 14) for n in nodes}
        top_edge = max((e["alerts"] for e in g["edges"]), default=1)
        for e in g["edges"]:
            det = max(e["by_detector"].items(), key=lambda kv: kv[1])[0]
            colour, dash = DETECTOR_PRINT.get(det, ("#5c6670", None))
            (x1, y1), (x2, y2) = pos[e["source"]], pos[e["target"]]
            d.add(Line(x1, y1, x2, y2, strokeColor=colors.HexColor(colour), strokeDashArray=dash,
                       strokeWidth=0.75 + 3.25 * (e["alerts"] / top_edge) ** 0.5))
        for n in nodes:
            x, y = pos[n["id"]]
            host = n["kind"] == "host"
            d.add(Circle(x, y, 4, fillColor=colors.white if host else colors.HexColor("#1b1f24"),
                         strokeColor=colors.HexColor("#1b1f24"), strokeWidth=1))
            d.add(String(x + 6, y - 2, f"{n['value']} ({n['alerts']:,})", fontSize=5.5))
        d.add(String(0, 2, f"Entity graph: {g['nodes_shown']} of {g['nodes_total']} nodes; hollow = host, "
                     "filled = source IP; edge width = alerts, colour and dash = main detector", fontSize=6))
        out.append(d)
    return out


def render_pdf(body: dict[str, Any]) -> bytes:
    """A4 PDF via reportlab; ``invariant=1`` makes the bytes depend on the body only."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    small = styles["BodyText"].clone("small", fontSize=7, leading=9)

    def p(text: Any, style: Any = small) -> Paragraph:
        return Paragraph(escape("" if text is None else str(text)), style)

    def table(rows: list[list[Any]], widths: list[float]) -> Table:
        t = Table([[p(c) for c in r] for r in rows], colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                               ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                               ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        return t

    inc = body["incident"]
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, invariant=1, title=f"Incident {inc['incident_id']}",
                            leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm, bottomMargin=15 * mm)
    story: list[Any] = [p(f"SentinelAI incident report {inc['incident_id']}", styles["Title"]),
                        p(body["notice"], styles["Italic"]), Spacer(1, 4 * mm),
                        p("Incident", styles["Heading2"]),
                        table([["field", "value"]] + [[k, v] for k, v in inc.items()], [40 * mm, 140 * mm]),
                        p("ATT&CK techniques (deterministic mapping)", styles["Heading2"]),
                        table([["technique", "alerts"]] + [[t["technique_id"], t["alerts"]]
                                                          for t in body["techniques"]] or [["none", ""]],
                              [40 * mm, 30 * mm]),
                        p("Recommendations", styles["Heading2"]),
                        table([["action", "recommendation", "techniques", "approval"]]
                              + [[r["action_type"], r["title"], ", ".join(r["techniques"]),
                                  "required" if r["requires_approval"] else "no"]
                                 for r in body["recommendations"]],
                              [32 * mm, 90 * mm, 35 * mm, 20 * mm])]
    if body.get("charts"):
        story += [p("Charts", styles["Heading2"]), *_chart_flowables(body["charts"], 180 * mm)]
    if "findings" in body:
        v = body["findings"]["verification"]
        story += [p("Agent findings after the evidence verifier", styles["Heading2"]),
                  p(f"citations kept {v['citations_kept']}, dropped {v['citations_dropped']}; "
                    f"claims kept {v['claims_kept']}, dropped {v['claims_dropped']}", styles["BodyText"])]
    story += [p("Timeline", styles["Heading2"]),
              table([["time", "alert", "detector", "rule", "sev", "host"]]
                    + [[r["ts"], r["alert_id"], r["detector"], f"{r['rule_id'] or ''} {r['rule_name'] or ''}",
                        r["severity"], r["host_ip"]] for r in body["timeline"]],
                    [34 * mm, 42 * mm, 16 * mm, 52 * mm, 10 * mm, 26 * mm])]
    if body["timeline_rows_omitted"]:
        story.append(p(f"{body['timeline_rows_omitted']} more alerts not shown (cap {MAX_ROWS}).",
                       styles["Italic"]))
    story += [p("Citations (evidence the alerts carry)", styles["Heading2"]),
              table([["alert", "evidence excerpt"]]
                    + [[c["alert_id"], c["evidence_excerpt"]] for c in body["citations"]],
                    [42 * mm, 138 * mm])]
    doc.build(story)
    return buf.getvalue()
