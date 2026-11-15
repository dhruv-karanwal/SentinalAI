// Typed client for the SentinelAI API (backend/app/api/app.py), reached through the /api proxy.
// The token lives in memory only (DESIGN.md section 7): a reload asks for sign-in again.

import type { InvestigationStep } from './lib/investigation.ts';

export type Role = 'analyst' | 'manager' | 'admin' | 'executive';

export interface Session {
  username: string;
  role: Role;
}

const PERMISSIONS: Record<string, readonly Role[]> = {
  'read.raw': ['analyst', 'manager', 'admin'],
  'incident.update': ['analyst', 'manager', 'admin'],
  'incident.build': ['analyst', 'manager', 'admin'],
  'report.create': ['analyst', 'manager', 'admin'],
  'approval.request': ['analyst', 'manager', 'admin'],
  'approval.decide': ['manager', 'admin'],
  'action.execute': ['manager', 'admin'],
  'copilot.ask': ['analyst', 'manager', 'admin'],
  'investigation.run': ['analyst', 'manager', 'admin'],
  'audit.read': ['manager', 'admin'],
  'user.manage': ['admin'],
};

/** Mirrors PERMISSIONS in backend/app/api/auth.py; the API stays the authority (403 is shown, not hidden). */
export function can(role: Role, permission: string): boolean {
  return PERMISSIONS[permission]?.includes(role) ?? false;
}

export class ApiError extends Error {
  status: number;
  path: string;
  constructor(status: number, path: string, message: string) {
    super(message);
    this.status = status;
    this.path = path;
  }
}

let token: string | null = null;
let onUnauthorized: (() => void) | null = null;

export function setToken(value: string | null): void {
  token = value;
}

export function setUnauthorizedHandler(fn: (() => void) | null): void {
  onUnauthorized = fn;
}

async function request<T>(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`/api${path}`, {
      method,
      signal,
      headers: {
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') throw err;
    throw new ApiError(0, path, 'the API did not answer (is `app.main serve` running on 127.0.0.1:8000?)');
  }
  if (!res.ok) {
    let message = res.statusText;
    try {
      const data: unknown = await res.json();
      if (data && typeof data === 'object' && 'detail' in data) {
        const detail = (data as { detail: unknown }).detail;
        message = typeof detail === 'string' ? detail : JSON.stringify(detail);
      }
    } catch {
      // a proxy error page or an empty body: keep the status text
    }
    if (res.status === 401 && path !== '/auth/login') onUnauthorized?.();
    throw new ApiError(res.status, path, message || `HTTP ${res.status}`);
  }
  return (await res.json()) as T;
}

const qs = (params: Record<string, string | number | null | undefined>): string => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== null && v !== undefined && v !== '') p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : '';
};

// ---- shapes (only the fields the console reads) -------------------------------------------

export interface TimelineEntry {
  alert_id: string;
  detector: string;
  level: string;
  rule_id: string | null;
  rule_name: string | null;
  ts: string;
}

export interface IncidentDetail {
  chain_id?: string;
  detectors?: Record<string, number>;
  entities?: string[];
  gap_seconds?: number;
  max_span_seconds?: number | null;
  segment?: [number, number];
  severity_row?: string;
  timeline?: TimelineEntry[];
  /** C6 (2026-11-15); absent on incidents built before it: rebuild to see it */
  correlation?: {
    strength: 'strong' | 'moderate' | 'weak' | 'single alert';
    reason: string;
    links: number;
    linked_by: Record<string, number>;
    shared_indicators: { entity: string; alerts: number }[];
    source_ips: string[];
    max_link_gap_seconds: number | null;
    gap_limit_seconds: number;
    cross_detector_links: number;
    method: string;
    confidence_note: string;
  };
}

export interface Incident {
  incident_id: string;
  scenario: string;
  first_ts: string;
  last_ts: string;
  severity: string;
  status: string;
  alert_ids: string[];
  detail: IncidentDetail;
  created_utc: string;
}

export interface AlertRecord {
  alert_id: string;
  detector: string;
  kind?: string;
  timestamp?: string;
  rule_id?: string | null;
  rule_name?: string | null;
  severity?: number | null;
  host_ip?: string | null;
  evidence?: { source_alert_id?: string | null; log_lines?: string[]; log_paths?: string[]; log_timestamps?: string[] };
  raw_alert?: unknown;
}

export interface AlertRow {
  alert_id: string;
  scenario: string;
  detector: string;
  detector_type: string;
  kind: string;
  ts: string;
  rule_id: string | null;
  rule_name: string | null;
  severity: number | null;
  host_ip: string | null;
  source: string;
  enrichment?: unknown;
  /** absent for roles without read.raw */
  record?: AlertRecord;
}

export interface SearchHit {
  alert_id: string;
  scenario: string;
  detector: string;
  ts: string;
  rule_name: string | null;
  snippet?: string;
}

export interface Recommendation {
  action_type: string;
  title: string;
  playbook: string | null;
  techniques: string[];
  requires_approval: boolean;
}

export interface ReportBody {
  report_version?: string | number;
  incident: {
    incident_id: string;
    scenario: string;
    first_ts: string;
    last_ts: string;
    severity: string;
    status: string | null;
    alerts: number;
    detectors: Record<string, number>;
    entities: string[];
    gap_seconds: number | null;
  };
  timeline: Array<{
    ts: string;
    alert_id: string;
    detector: string;
    rule_id: string | null;
    rule_name: string | null;
    severity: number | null;
    host_ip: string | null;
    techniques: string[];
  }>;
  timeline_rows_omitted: number;
  citations: Array<{
    alert_id: string;
    detector: string;
    rule_id: string | null;
    evidence_excerpt: string;
    excerpt_truncated: boolean;
    log_paths: string[];
  }>;
  techniques: Array<{ technique_id: string; alerts: number }>;
  recommendations: Recommendation[];
  notice?: string;
  charts?: { timeseries: TimeSeries; graph: GraphPayload };
}

export interface Report {
  report_id: string;
  incident_id: string;
  body: ReportBody;
  object_key: string | null;
  created_utc: string;
}

export interface Approval {
  id: number;
  incident_id: string;
  action: { action_type: string; target?: string | null; note?: string | null };
  status: 'pending' | 'approved' | 'rejected';
  requested_by: string;
  reviewer: string | null;
  reason: string | null;
  created_utc: string;
  decided_utc: string | null;
  executed_utc: string | null;
  executed_by: string | null;
}

export interface Claim {
  record_id: string;
  field: string;
  value: string;
  kind: string;
}

export interface DroppedClaim {
  record_id: string;
  kind: string;
  field: string;
  reason: string;
}

export interface InvestigationRow {
  investigation_id: string;
  incident_id: string;
  workflow: 'single' | 'graph';
  status: 'running' | 'completed' | 'failed' | 'interrupted';
  requested_by: string;
  model_id: string | null;
  started_utc: string;
  completed_utc: string | null;
  error: string | null;
}

export interface InvestigationResult {
  workflow: 'single' | 'graph';
  status: string;
  parse_status: string | null;
  prompt_version: string;
  error: string | null;
  conclusion: { verdict: string | null; verified: boolean; cited_alert_ids: string[]; note: string };
  observed: { record_id: string; kind: string; field: string; value: string }[];
  detections: { alert_id: string; detector: string; rule_id: string | null; rule_name: string | null;
    severity: number | null; techniques: string[] }[];
  knowledge: { technique_id: string; name: string | null; tactics: string[]; excerpt: string | null;
    retrieved_by: string[] }[];
  hypotheses: { summary: string; status: string }[];
  verification: { citations_kept: number; citations_dropped: number; claims_checked: number;
    claims_kept: number; claims_dropped: number; dropped_citations: string[]; dropped_claims: DroppedClaim[] };
  recommendations: { action_type: string; title: string; playbook: string | null; techniques: string[];
    requires_approval: boolean }[];
  steps: InvestigationStep[];
  trace: string[];
  notes: { n: number; agent: string; text: string; alert_ids: string[] }[];
  id_map: Record<string, string>;
  usage: { requests: number; tool_calls: number; repairs: number; input_tokens: number;
    output_tokens: number; wall_seconds: number };
  retrieval: boolean;
  note: string;
}

export interface IncidentMl {
  incident_id: string;
  influences_severity: boolean;
  note: string;
  models: { model_version: string; model: string; kind: string; alerts: number; scored: number; flagged: number;
    max_score: number; in_sample: boolean;
    top: { alert_id: string; score: number; flag: boolean; explanation: Record<string, unknown> }[] }[];
}

export interface Investigation extends InvestigationRow {
  result: InvestigationResult | null;
}

export interface CopilotAnswer {
  status: string;
  parse_status: string | null;
  verdict: string | null;
  answer: string[];
  cited_alert_ids: string[];
  verification: {
    citations_kept: number;
    citations_dropped: number;
    claims_checked: number;
    claims_kept: number;
    claims_dropped: number;
  };
  /** returned by API builds that include the verifier detail */
  claims?: Claim[];
  dropped_citations?: string[];
  dropped_claims?: DroppedClaim[];
  tool_calls: number;
  input_tokens: number;
  output_tokens: number;
  error: string | null;
  note: string;
}

export interface AuditEntry {
  id: number;
  ts: string;
  username: string;
  role: string;
  action: string;
  target: string | null;
  detail: unknown;
}

export interface ScenarioRow {
  scenario: string;
  alerts: number;
}


// ---- console v2 shapes ---------------------------------------------------------------------

export interface TimeSeries {
  start: string | null;
  end: string | null;
  bin_seconds: number | null;
  bins: number;
  series: Record<string, number[]>;
  total: number;
}

export interface Technique {
  technique_id: string;
  name: string | null;
  alerts: number;
}

export interface TacticCol {
  tactic: string;
  name: string;
  alerts: number;
  techniques: Technique[];
}

export interface ChainStage extends TacticCol {
  first_ts: string | null;
  last_ts: string | null;
}

export interface EntityRow {
  value: string;
  alerts: number;
  by_detector: Record<string, number>;
  severity: string | null;
  incidents: number;
}

export interface DetectorRow {
  detector: string;
  alerts: number;
  mapped: number;
  mapped_share: number;
  ioc: number | null;
  ioc_share: number | null;
  duplicates: number;
  duplicate_share: number;
  aggregates: number;
}

export interface QueueStatus {
  by_severity_status: Record<string, Record<string, number>>;
  age_in_queue: Record<string, Record<string, number>>;
  age_buckets: string[];
  open_by_severity: Record<string, number>;
  oldest_unreviewed_high: { incident_id: string; created_utc: string; age_seconds: number; alerts: number } | null;
  pending_approvals: number;
  incidents: number;
}

export interface Overview {
  scenario: string;
  alerts: number;
  status: QueueStatus;
  timeseries: TimeSeries;
  incident_starts: { markers: Array<{ incident_id: string; ts: string; severity: string }>; low_not_marked: number; omitted: number };
  attack: { tactics: TacticCol[]; alerts: number; mapped_alerts: number; unmapped_alerts: number; kb_loaded: boolean; kb_version: string | null };
  entities: { host: { distinct: number; rows: EntityRow[] }; ip: { distinct: number; rows: EntityRow[] } };
  detectors: DetectorRow[];
  ioc_loaded: boolean;
  kill_chain: ChainStage[];
}

export interface AlertFilter {
  detector?: string | null;
  level?: string | null;
  rule_id?: string | null;
  technique?: string | null;
  host?: string | null;
  ip?: string | null;
  since?: string | null;
  until?: string | null;
}

export interface QueryRow extends AlertRow {
  src_ip: string | null;
  techniques: string[];
}

export interface FacetValue {
  value: string;
  count: number;
  label: string | null;
}

export type FacetName = 'detector' | 'level' | 'rule_id' | 'technique' | 'host';

export interface Facets {
  facets: Record<FacetName, { values: FacetValue[]; distinct: number; shown: number }>;
  total: number;
  timeseries: TimeSeries;
}

export interface IncidentSummaryRow {
  incident_id: string;
  scenario: string;
  first_ts: string;
  last_ts: string;
  severity: string;
  status: string | null;
  alerts: number;
  created_utc: string;
  detail: IncidentDetail & { features?: Record<string, unknown> };
}

export interface GraphPayload {
  nodes: Array<{ id: string; kind: string; value: string; alerts: number; by_detector: Record<string, number>; x?: number; y?: number }>;
  edges: Array<{ source: string; target: string; alerts: number; by_detector: Record<string, number> }>;
  nodes_total: number;
  nodes_omitted?: number;
  width?: number;
  height?: number;
  nodes_shown?: number;
}

export interface IncidentAnalysis {
  incident_id: string;
  summary: {
    severity: string;
    status: string | null;
    rule: { row: string; severity: string; rule: string } | null;
    inputs: { ioc_match?: boolean; detectors?: number; max_level?: string; attack_mapped?: boolean; size?: number } | null;
    first_ts: string;
    last_ts: string;
    alerts: number;
    alerts_found: number;
    detectors: Record<string, number>;
    detectors_agreeing: number;
    gap_seconds: number | null;
  };
  graph: GraphPayload;
  lanes: { start: string; end: string; bin_seconds: number; bins: number; lanes: Array<{ tactic: string; name: string; bins: Array<[number, number]> }>; unmapped_alerts: number };
  timeseries: TimeSeries;
  kill_chain: ChainStage[];
}

export interface EntityView {
  kind: string;
  value: string;
  alerts: number;
  by_detector: Record<string, number>;
  first_ts: string | null;
  last_ts: string | null;
  timeseries: TimeSeries;
  top_rules: Array<{ rule_id: string; rule_name: string | null; alerts: number }>;
  incidents: IncidentSummaryRow[];
  incidents_total: number;
}

export interface SearchResult {
  q: string;
  alerts: Array<{ alert_id: string; scenario: string; detector: string; ts: string; rule_name: string | null }>;
  incidents: IncidentSummaryRow[];
  ips: Array<{ value: string; alerts: number }>;
  rules: Array<{ value: string; alerts: number; label: string | null }>;
  text: SearchHit[];
}

export interface Executive {
  scenario: string;
  severity_trend: Array<{ day: string; High: number; Medium: number; Low: number }>;
  top_risks: Array<IncidentSummaryRow & { rule: { row: string; severity: string; rule: string } | null }>;
  coverage: Array<{ tactic: string; name: string; alerts: number; techniques: number }>;
  time_to_review: { reviewed: number; unreviewed: number; median_seconds: number | null; max_seconds: number | null };
  open_approvals: { pending: number; oldest_utc: string | null };
  queue: QueueStatus;
}

export interface Rate {
  covered: number;
  cases: number;
  rate: number | null;
}

export interface ScoreRow {
  coverage?: { event_label?: { reachable?: Rate; all?: Rate }; time_label?: { reachable?: Rate; all?: Rate } };
  citation_precision?: { event_label: number | null; time_label: number | null; cited: number };
  unsupported_claim_rate?: number | null;
  claims?: number;
  alerts_cited?: { total: number; mean_per_case: number | null };
  runs?: { input_tokens: number; output_tokens: number; tool_calls: number; latency_seconds: number; budget_hit: number; status: Record<string, number> };
  base?: string;
  k?: number | null;
}

export interface StudyRun {
  run_id: string;
  scenario: string | null;
  variant: string | null;
  truncation: string | null;
  split: string | null;
  started_utc: string | null;
  model_ids: Record<string, string> | null;
  retrieval_mode: string | null;
  cases: number;
  matched_k: number | null;
  arms: Record<string, ScoreRow>;
  baselines: Record<string, ScoreRow>;
  note: string | null;
  /** pilot | held-out | adhoc, from scores.json (older files have none) */
  study_part?: string | null;
  /** "<single>+<graph>" prompt versions from the run manifest, or "unknown" */
  prompt_revision?: string;
}

export interface StudyResults {
  runs: StudyRun[];
  excluded_fake_runs: number;
  incomplete_runs: number;
  label: string;
}

export interface ExplainAnswer {
  mode: 'explain';
  status: string;
  answer: string[];
  model: string;
  sources: string[];
  note: string;
}

export interface AlertRun {
  first_alert_id: string;
  last_alert_id: string;
  count: number;
  detector: string;
  rule_id: string | null;
  rule_name: string | null;
  severity: number | null;
  host_ip: string | null;
  src_ip: string | null;
  techniques: string[];
  first_ts: string;
  last_ts: string;
}

export interface UserRow {
  username: string;
  role: Role;
  created_utc: string;
  disabled_utc: string | null;
}

export interface RunRow {
  run_id: string;
  scenario?: string;
  status?: string;
  started_utc?: string;
  [k: string]: unknown;
}

// ---- calls --------------------------------------------------------------------------------

export const api = {
  login: (username: string, password: string) =>
    request<{ access_token: string; role: Role }>('POST', '/auth/login', { username, password }),
  health: (signal?: AbortSignal) => request<{ status: string; alerts: number; database: string }>('GET', '/health', undefined, signal),
  scenarios: (signal?: AbortSignal) => request<{ scenarios: ScenarioRow[] }>('GET', '/scenarios', undefined, signal),

  incidents: (scenario: string | null, signal?: AbortSignal) =>
    request<{ incidents: Incident[] }>('GET', `/incidents${qs({ scenario })}`, undefined, signal),
  setIncidentStatus: (id: string, status: string) =>
    request<{ incident_id: string; status: string }>('PATCH', `/incidents/${encodeURIComponent(id)}`, { status }),
  buildIncidents: (scenario: string, gap_seconds: number) =>
    request<Record<string, unknown>>('POST', '/incidents/build', { scenario, gap_seconds }),

  alerts: (
    f: { scenario?: string | null; detector?: string | null; host_ip?: string | null; since?: string | null; until?: string | null; limit: number; offset: number },
    signal?: AbortSignal,
  ) => request<{ alerts: AlertRow[]; count: number; offset: number }>('GET', `/alerts${qs(f)}`, undefined, signal),
  alertStats: (scenario: string | null, signal?: AbortSignal) =>
    request<{ by_detector: Record<string, number> }>('GET', `/alerts/stats${qs({ scenario })}`, undefined, signal),
  searchAlerts: (q: string, scenario: string | null, signal?: AbortSignal) =>
    request<{ hits: SearchHit[] }>('GET', `/alerts/search${qs({ q, scenario, limit: 200 })}`, undefined, signal),
  alert: (id: string, signal?: AbortSignal) => request<AlertRow>('GET', `/alerts/${encodeURIComponent(id)}`, undefined, signal),

  reports: (incident_id: string | null, signal?: AbortSignal) =>
    request<{ reports: Report[] }>('GET', `/reports${qs({ incident_id })}`, undefined, signal),
  createReport: (incident_id: string) => request<{ report_id: string }>('POST', '/reports', { incident_id }),

  approvals: (signal?: AbortSignal) => request<{ approvals: Approval[] }>('GET', '/approvals', undefined, signal),
  requestApproval: (incident_id: string, action: { action_type: string; target?: string; note?: string }) =>
    request<{ id: number; status: string }>('POST', '/approvals', { incident_id, action }),
  decideApproval: (id: number, approved: boolean, reason: string) =>
    request<{ id: number; status: string }>('POST', `/approvals/${id}/decision`, { approved, reason }),
  executeApproval: (id: number) => request<{ executed: boolean; mode: string; note: string }>('POST', `/approvals/${id}/execute`),

  explain: (body: { question: string; screen?: string; context?: string; incident_id?: string | null; glossary: Array<{ term: string; definition: string; why: string }> }) =>
    request<ExplainAnswer>('POST', '/copilot/ask', { mode: 'explain', ...body, incident_id: body.incident_id || undefined }),
  /** cheap model reachability probe (lists models, never generates) */
  copilotStatus: (signal?: AbortSignal) =>
    request<{ state: 'online' | 'offline' | 'busy'; model: string | null; reason?: string; retrieval?: string }>('GET', '/copilot/status', undefined, signal),
  alertRuns: (scenario: string, f: AlertFilter, limit: number, offset: number, signal?: AbortSignal) =>
    request<{ runs: AlertRun[]; total_runs: number; total_alerts: number; offset: number }>('GET', `/alerts/runs${qs({ scenario, ...f, limit, offset })}`, undefined, signal),
  startInvestigation: (incident_id: string, workflow: 'single' | 'graph') =>
    request<{ investigation_id: string; status: string; workflow: string }>(
      'POST', `/incidents/${encodeURIComponent(incident_id)}/investigations`, { workflow }),
  incidentMl: (incident_id: string, signal?: AbortSignal) =>
    request<IncidentMl>('GET', `/incidents/${encodeURIComponent(incident_id)}/ml`, undefined, signal),
  investigations: (incident_id: string, signal?: AbortSignal) =>
    request<{ investigations: InvestigationRow[] }>(
      'GET', `/incidents/${encodeURIComponent(incident_id)}/investigations`, undefined, signal),
  investigation: (id: string, signal?: AbortSignal) =>
    request<Investigation>('GET', `/investigations/${encodeURIComponent(id)}`, undefined, signal),
  ask: (incident_id: string, question: string) => request<CopilotAnswer>('POST', '/copilot/ask', { incident_id, question }),
  audit: (signal?: AbortSignal) => request<{ entries: AuditEntry[] }>('GET', '/audit?limit=1000', undefined, signal),
  overview: (scenario: string, signal?: AbortSignal) => request<Overview>('GET', `/overview${qs({ scenario })}`, undefined, signal),
  queryAlerts: (scenario: string, f: AlertFilter, limit: number, offset: number, signal?: AbortSignal) =>
    request<{ alerts: QueryRow[]; total: number; offset: number }>('GET', `/alerts/query${qs({ scenario, ...f, limit, offset })}`, undefined, signal),
  facets: (scenario: string, f: AlertFilter, signal?: AbortSignal) => request<Facets>('GET', `/alerts/facets${qs({ scenario, ...f })}`, undefined, signal),
  incidentSummaries: (scenario: string, signal?: AbortSignal) =>
    request<{ incidents: IncidentSummaryRow[] }>('GET', `/incidents/summary${qs({ scenario })}`, undefined, signal),
  incident: (id: string, signal?: AbortSignal) => request<Incident>('GET', `/incidents/${encodeURIComponent(id)}`, undefined, signal),
  nodeAlerts: (id: string, node: string, signal?: AbortSignal) =>
    request<{ alert_ids: string[] }>('GET', `/incidents/${encodeURIComponent(id)}/node-alerts${qs({ node })}`, undefined, signal),
  analysis: (id: string, signal?: AbortSignal) => request<IncidentAnalysis>('GET', `/incidents/${encodeURIComponent(id)}/analysis`, undefined, signal),
  entity: (kind: string, value: string, scenario: string, signal?: AbortSignal) =>
    request<EntityView>('GET', `/entities/${encodeURIComponent(kind)}/${encodeURIComponent(value)}${qs({ scenario })}`, undefined, signal),
  search: (q: string, scenario: string | null, signal?: AbortSignal) => request<SearchResult>('GET', `/search${qs({ q, scenario })}`, undefined, signal),
  executive: (scenario: string, signal?: AbortSignal) => request<Executive>('GET', `/executive${qs({ scenario })}`, undefined, signal),
  study: (signal?: AbortSignal) => request<StudyResults>('GET', '/study/results', undefined, signal),
  runs: (signal?: AbortSignal) => request<{ runs: RunRow[] }>('GET', '/runs', undefined, signal),
  users: (signal?: AbortSignal) => request<{ users: UserRow[]; password_source: string; password_source_set: boolean }>('GET', '/users', undefined, signal),
  createUser: (username: string, role: Role) => request<{ username: string; role: Role }>('POST', '/console/users', { username, role }),
  userAction: (username: string, action: 'deactivate' | 'reactivate' | 'reset') =>
    request<Record<string, unknown>>('POST', `/users/${encodeURIComponent(username)}/${action}`),
  report: (id: string, signal?: AbortSignal) => request<Report>('GET', `/reports/${encodeURIComponent(id)}`, undefined, signal),
};

/** CSV of the filtered alert view, fetched with the bearer token and saved by the browser. */
export async function downloadAlertsCsv(scenario: string, f: AlertFilter): Promise<{ rows: number; total: number }> {
  const path = `/alerts/export.csv${qs({ scenario, ...f })}`;
  const res = await fetch(`/api${path}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
  if (!res.ok) throw new ApiError(res.status, path, res.statusText || `HTTP ${res.status}`);
  const rows = Number(res.headers.get('X-Rows') ?? 0);
  const total = Number(res.headers.get('X-Rows-Total') ?? rows);
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement('a');
  a.href = url;
  a.download = `alerts-${scenario}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  return { rows, total };
}

/** Report files need the bearer token, so they are fetched and handed to the browser as a blob. */
export async function downloadReport(reportId: string, format: 'json' | 'csv' | 'pdf'): Promise<void> {
  const path = `/reports/${encodeURIComponent(reportId)}/download?format=${format}`;
  const res = await fetch(`/api${path}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
  if (!res.ok) throw new ApiError(res.status, path, res.statusText || `HTTP ${res.status}`);
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement('a');
  a.href = url;
  a.download = `${reportId}.${format}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
