// Typed client for the SentinelAI API (backend/app/api/app.py), reached through the /api proxy.
// The token lives in memory only (DESIGN.md section 7): a reload asks for sign-in again.

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
  'audit.read': ['manager', 'admin'],
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

  ask: (incident_id: string, question: string) => request<CopilotAnswer>('POST', '/copilot/ask', { incident_id, question }),
  audit: (signal?: AbortSignal) => request<{ entries: AuditEntry[] }>('GET', '/audit?limit=1000', undefined, signal),
};

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
