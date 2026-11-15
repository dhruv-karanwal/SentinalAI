// Investigation workspace logic (C2, 2026-11-15): polling cadence, status lines, step summaries.
// Pure functions over the API's investigation records; the component renders text nodes only.

export type InvestigationStatus = 'running' | 'completed' | 'failed' | 'interrupted';

export interface InvestigationEvent {
  type: 'reply' | 'tool_result' | 'message';
  text: string;
  action?: string;
  tool?: string;
  agent?: string;
  arguments?: unknown;
}

export interface InvestigationStep {
  node: string;
  events: InvestigationEvent[];
}

export interface StepSummary {
  node: string;
  label: string;
  toolCalls: number;
  tools: string[];
  ended: 'route' | 'note' | 'final' | 'unparseable' | 'none';
  routedTo: string | null;
}

const NODE_LABELS: Record<string, string> = {
  single_agent: 'Single agent',
  supervisor: 'Supervisor',
  log_analysis: 'Log analysis',
  correlation: 'Correlation',
  knowledge_retrieval: 'Knowledge retrieval',
  anomaly_analysis: 'Anomaly analysis',
  investigation: 'Investigation',
  report_generation: 'Report generation',
  verifier: 'Evidence verifier',
};

export function nodeLabel(node: string): string {
  return NODE_LABELS[node] ?? node;
}

export function isTerminal(status: string): boolean {
  return status !== 'running';
}

/** Poll quickly at first, then back off: 1 s for 10 s, 2 s up to a minute, then 5 s. */
export function pollDelay(elapsedMs: number): number {
  if (elapsedMs < 10_000) return 1_000;
  if (elapsedMs < 60_000) return 2_000;
  return 5_000;
}

export function summarizeStep(step: InvestigationStep): StepSummary {
  const tools: string[] = [];
  let toolCalls = 0;
  let ended: StepSummary['ended'] = 'none';
  let routedTo: string | null = null;
  for (const e of step.events) {
    if (e.type !== 'reply') continue;
    if (e.action === 'call_tool') {
      toolCalls += 1;
      if (e.tool && !tools.includes(e.tool)) tools.push(e.tool);
    } else if (e.action === 'route') {
      ended = 'route';
      routedTo = e.agent ?? null;
    } else if (e.action === 'note' || e.action === 'final' || e.action === 'unparseable') {
      ended = e.action;
    }
  }
  return { node: step.node, label: nodeLabel(step.node), toolCalls, tools, ended, routedTo };
}

/** One line that says what is happening, in words (never a bare spinner). */
export function statusLine(
  inv: { status: string; started_utc: string; completed_utc: string | null; error: string | null },
  now: number,
): string {
  const started = Date.parse(inv.started_utc);
  const secs = (end: number) => Math.max(0, Math.round((end - started) / 1000));
  switch (inv.status) {
    case 'running':
      return `Running for ${secs(now)} s: the agents are reading the incident's alerts. Results appear when the run ends.`;
    case 'completed':
      return `Completed in ${inv.completed_utc ? secs(Date.parse(inv.completed_utc)) : '?'} s.`;
    case 'interrupted':
      return 'Interrupted: the API stopped while this investigation ran. Start a new one.';
    default:
      return `Failed${inv.error ? `: ${inv.error}` : ''}. Nothing from this run is treated as a finding.`;
  }
}

/** The opaque ids the agents saw, mapped back to stored alert ids (for the evidence links). */
export function realId(idMap: Record<string, string>, opaque: string): string | null {
  return idMap[opaque] ?? null;
}

/** What a data-source name is, for labels: the two dev scenarios, a synthetic sample, or another replay. */
export function scenarioKind(name: string | null | undefined): string {
  if (!name) return 'no data source';
  if (name === 'russellmitchell' || name === 'shaw') return 'dev scenario';
  if (name.startsWith('synthetic')) return 'synthetic sample, not real telemetry';
  return 'replayed scenario';
}

/** One sentence per ML model for the incident header; says plainly that severity ignores it. */
export function mlLine(m: { model: string; scored: number; alerts: number; flagged: number; max_score: number; in_sample: boolean }): string {
  const name = m.model === 'hist_gradient_boosting' ? 'HistGB score' : m.model === 'isolation_forest' ? 'Isolation forest' : m.model;
  const what = m.model === 'isolation_forest' ? 'unusual (anomaly, not an attack verdict)' : 'attack-like (uncalibrated)';
  const sample = m.in_sample ? '; in-sample: this scenario was in the training data' : '';
  return `${name}: ${m.flagged} of ${m.scored} scored alerts ${what}, max ${m.max_score.toFixed(2)}${m.scored < m.alerts ? ` (${m.alerts - m.scored} not scored)` : ''}${sample}.`;
}
