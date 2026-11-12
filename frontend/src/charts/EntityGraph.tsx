// Entity graph: hosts (circles) and source IPs (squares) as nodes, one edge per (source IP, host)
// pair. Edge width = alert count (square root), edge colour and dash = the detector with the most
// alerts on that edge. Layout: the deterministic force layout shared with the report PDF
// (lib/graph.ts). The first 60 nodes are drawn; "Show more" adds 60. Every node is a focusable
// button; activating one filters the alert table. The adjacency table is the text alternative.

import { useMemo, useState } from 'react';

import { Button, detectorName } from '../components/ui.tsx';
import { useElementSize } from '../hooks.ts';
import { fmtInt } from '../lib/format.ts';
import { layout, placeLabels } from '../lib/graph.ts';
import { ChartFrame, DETECTOR_DASH, DETECTOR_ORDER, TONE_VAR, detectorTone, useTip, type LegendItem } from './ChartFrame.tsx';

export interface GraphNode {
  id: string;
  kind: string;
  value: string;
  alerts: number;
  by_detector: Record<string, number>;
  x?: number;
  y?: number;
}

export interface GraphEdge {
  source: string;
  target: string;
  alerts: number;
  by_detector: Record<string, number>;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  nodes_total: number;
  width?: number;
  height?: number;
}

export const GRAPH_STEP = 60;
export const GRAPH_W = 480;
export const GRAPH_H = 320;
/** approximate advance of the 10 px monospace label font (.graph-label) */
const LABEL_CHAR_W = 6.2;

export function mainDetector(by: Record<string, number>): string {
  let best = '';
  let n = -1;
  for (const d of [...DETECTOR_ORDER, ...Object.keys(by).sort()]) {
    const v = by[d] ?? -1;
    if (v > n) {
      best = d;
      n = v;
    }
  }
  return best;
}

interface Props {
  graph: GraphData;
  title: string;
  question: string;
  selected?: string | null;
  onPick?: (node: GraphNode | null) => void;
  /** true: draw the stored positions (report snapshot); false: lay out here */
  fixed?: boolean;
}

export function EntityGraph({ graph, title, question, selected = null, onPick, fixed = false }: Props) {
  const [limit, setLimit] = useState(GRAPH_STEP);
  const nodes = useMemo(() => graph.nodes.slice(0, fixed ? graph.nodes.length : limit), [graph.nodes, limit, fixed]);
  const keep = useMemo(() => new Set(nodes.map((n) => n.id)), [nodes]);
  const edges = useMemo(() => graph.edges.filter((e) => keep.has(e.source) && keep.has(e.target)), [graph.edges, keep]);
  const W = graph.width ?? GRAPH_W;
  const H = graph.height ?? GRAPH_H;
  const pos = useMemo(() => {
    const m = new Map<string, { x: number; y: number }>();
    if (fixed) for (const n of nodes) m.set(n.id, { x: n.x ?? W / 2, y: n.y ?? H / 2 });
    else
      for (const p of layout(
        nodes.map((n) => n.id),
        edges.map((e) => [e.source, e.target] as const),
        W,
        H,
      ))
        m.set(p.id, p);
    return m;
  }, [nodes, edges, fixed, W, H]);
  const dets = useMemo(() => {
    const s = new Set(edges.map((e) => mainDetector(e.by_detector)));
    return DETECTOR_ORDER.filter((d) => s.has(d));
  }, [edges]);
  const legend: LegendItem[] = [
    { key: 'host', label: 'host', tone: 'muted', mark: 'hollow' },
    { key: 'ip', label: 'source IP', tone: 'muted', mark: 'square' },
    ...dets.map((d) => ({ key: d, label: `${detectorName(d)} edge`, tone: detectorTone(d), mark: 'line' as const, dash: DETECTOR_DASH[d] })),
  ];
  const names = new Map(graph.nodes.map((n) => [n.id, `${n.kind === 'host' ? 'host' : 'IP'} ${n.value}`]));
  const table = {
    columns: ['source IP', 'host', 'alerts', 'by detector'],
    rows: edges.map((e) => [names.get(e.source) ?? e.source, names.get(e.target) ?? e.target, fmtInt(e.alerts), Object.entries(e.by_detector).map(([d, v]) => `${detectorName(d)} ${fmtInt(v)}`).join(', ')]),
  };
  const more = graph.nodes.length - nodes.length;
  return (
    <ChartFrame
      title={title}
      question={question}
      legend={legend}
      table={table}
      empty={graph.nodes.length === 0 ? 'No host or source IP on these alerts.' : undefined}
      actions={
        !fixed && (more > 0 || limit > GRAPH_STEP) ? (
          <>
            <span className="faint num">
              {fmtInt(nodes.length)} of {fmtInt(graph.nodes_total)} nodes
            </span>
            {more > 0 && <Button onClick={() => setLimit((l) => l + GRAPH_STEP)}>Show {Math.min(GRAPH_STEP, more)} more</Button>}
          </>
        ) : (
          <span className="faint num">
            {fmtInt(nodes.length)} of {fmtInt(graph.nodes_total)} nodes
          </span>
        )
      }
      note={`Node size and edge width grow with the alert count (square root).${onPick ? " Click or press Enter on a node to filter the alerts to it." : " Hover or focus a node for its counts."}`}
    >
      <GraphSvg nodes={nodes} edges={edges} pos={pos} W={W} H={H} selected={selected} onPick={onPick} />
    </ChartFrame>
  );
}

function GraphSvg({ nodes, edges, pos, W, H, selected, onPick }: { nodes: GraphNode[]; edges: GraphEdge[]; pos: Map<string, { x: number; y: number }>; W: number; H: number; selected: string | null; onPick?: (n: GraphNode | null) => void }) {
  const [ref, size] = useElementSize<HTMLDivElement>();
  const tip = useTip();
  const [hover, setHover] = useState<string | null>(null);
  const width = Math.max(240, size.width);
  // fit the pane: never taller than 300 px; x and y scale separately (a node-link diagram has no true aspect)
  const height = Math.min((width * H) / W, 300);
  const kx = width / W;
  const ky = height / H;
  const maxEdge = Math.max(1, ...edges.map((e) => e.alerts));
  const maxNode = Math.max(1, ...nodes.map((n) => n.alerts));
  const focus = hover ?? selected;
  const linked = useMemo(() => {
    const s = new Set<string>();
    if (focus) for (const e of edges) if (e.source === focus || e.target === focus) s.add(e.source).add(e.target);
    return s;
  }, [edges, focus]);
  // labels without overlap: most alerts first, each tries right / left / below / above its node;
  // one that fits nowhere is shown only on hover or focus (the table under the graph has all names)
  const radius = (n: GraphNode) => 3.5 + 6 * Math.sqrt(n.alerts / maxNode);
  const boxes = useMemo(() => {
    const order = [...nodes].sort((a, b) => b.alerts - a.alerts || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    const items = order.flatMap((n) => {
      const p = pos.get(n.id);
      return p ? [{ id: n.id, x: p.x * kx, y: p.y * ky, r: radius(n), text: n.value }] : [];
    });
    return new Map(placeLabels(items, width, height, LABEL_CHAR_W, 13).map((b) => [b.id, b]));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes, pos, kx, ky, width, height, maxNode]);
  const hiddenLabels = nodes.length - boxes.size;
  const lines = (n: GraphNode) => [
    `${n.kind === 'host' ? 'Host' : 'Source IP'} ${n.value}`,
    `${fmtInt(n.alerts)} alerts`,
    ...Object.entries(n.by_detector).map(([d, v]) => `${detectorName(d)}: ${fmtInt(v)}`),
  ];
  return (
    <div ref={ref} className="chart-plot">
      <svg width={width} height={height} className="chart-svg graph" role="group" aria-label="Entity graph">
        {edges.map((e) => {
          const a = pos.get(e.source);
          const b = pos.get(e.target);
          if (!a || !b) return null;
          const d = mainDetector(e.by_detector);
          const dim = focus && !(e.source === focus || e.target === focus);
          return (
            <line
              key={`${e.source}>${e.target}`}
              x1={a.x * kx}
              y1={a.y * ky}
              x2={b.x * kx}
              y2={b.y * ky}
              stroke={TONE_VAR[detectorTone(d)]}
              strokeWidth={0.75 + 3.25 * Math.sqrt(e.alerts / maxEdge)}
              strokeDasharray={DETECTOR_DASH[d]}
              strokeOpacity={dim ? 0.25 : 0.9}
              onPointerEnter={(ev) => tip.show({ x: ev.clientX, y: ev.clientY }, [`${e.source.replace(/^ip:/, 'IP ')} → ${e.target.replace(/^host:/, 'host ')}`, `${fmtInt(e.alerts)} alerts`, ...Object.entries(e.by_detector).map(([dd, v]) => `${detectorName(dd)}: ${fmtInt(v)}`)])}
              onPointerLeave={() => tip.hide()}
            />
          );
        })}
        {nodes.map((n) => {
          const p = pos.get(n.id);
          if (!p) return null;
          const r = radius(n);
          const box = boxes.get(n.id);
          const dim = focus && focus !== n.id && !linked.has(n.id);
          const sel = selected === n.id;
          const x = p.x * kx;
          const y = p.y * ky;
          return (
            <g
              key={n.id}
              className="graph-node"
              tabIndex={0}
              role="button"
              aria-pressed={sel}
              aria-label={`${lines(n).join(', ')}. Enter filters the alerts.`}
              opacity={dim ? 0.35 : 1}
              onClick={() => onPick?.(sel ? null : n)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  onPick?.(sel ? null : n);
                  e.preventDefault();
                }
              }}
              onPointerEnter={(e) => {
                setHover(n.id);
                tip.show(e.currentTarget, lines(n));
              }}
              onPointerLeave={() => {
                setHover(null);
                tip.hide();
              }}
              onFocus={(e) => {
                setHover(n.id);
                tip.show(e.currentTarget, lines(n));
              }}
              onBlur={() => {
                setHover(null);
                tip.hide();
              }}
            >
              {n.kind === 'host' ? (
                <circle cx={x} cy={y} r={r} fill="var(--surface)" stroke="var(--text)" strokeWidth={sel ? 3 : 1.5} />
              ) : (
                <rect x={x - r * 0.85} y={y - r * 0.85} width={r * 1.7} height={r * 1.7} fill="var(--text)" stroke={sel ? 'var(--accent)' : 'var(--text)'} strokeWidth={sel ? 3 : 1} />
              )}
              {box ? (
                <text x={box.anchor === 'start' ? box.x0 : box.anchor === 'end' ? box.x1 : (box.x0 + box.x1) / 2} y={box.y1 - 3} textAnchor={box.anchor} className="graph-label mono">
                  {n.value}
                </text>
              ) : (
                (focus === n.id || sel) && (
                  <text x={x + r + 3} y={y + 4} className="graph-label graph-label-float mono">
                    {n.value}
                  </text>
                )
              )}
            </g>
          );
        })}
      </svg>
      {hiddenLabels > 0 && (
        <div className="axis-caption faint">
          {fmtInt(hiddenLabels)} of {fmtInt(nodes.length)} labels hidden to avoid overlap; hover or focus a node to read it, or open the table under the chart.
        </div>
      )}
    </div>
  );
}
