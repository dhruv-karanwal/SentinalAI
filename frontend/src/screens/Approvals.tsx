// Approvals: requests for state-changing actions. A manager or admin who did not make the
// request decides it with a reason; an approved request is executed once, by a simulated executor.

import { Term } from '../components/Term.tsx';
import { useEffect, useMemo, useState } from 'react';

import { api, ApiError, can, type Approval } from '../api.ts';
import { DataTable, type Column } from '../components/DataTable.tsx';
import { SplitPane } from '../components/SplitPane.tsx';
import { Button, describeError, EmptyState, ErrorNotice, ErrorState, Id, SeverityCell, SkeletonLines, StatusTag, Time } from '../components/ui.tsx';
import { Icon } from '../icons.tsx';
import { fmtInt } from '../lib/format.ts';
import { useApp, useLoad, type Route } from '../hooks.ts';

const stateOf = (a: Approval): string => (a.executed_utc ? 'executed' : a.status);
const ORDER = ['pending', 'approved', 'executed', 'rejected'];

interface Props {
  route: Route & { setParams: (patch: Record<string, string | null>, replace?: boolean) => void };
}

export function ApprovalsScreen({ route }: Props) {
  const { session } = useApp();
  const { data, error, loading, reload } = useLoad((signal) => api.approvals(signal), []);
  const [filter, setFilter] = useState<string>('all');

  const all = useMemo(
    () => [...(data?.approvals ?? [])].sort((a, b) => ORDER.indexOf(stateOf(a)) - ORDER.indexOf(stateOf(b)) || b.id - a.id),
    [data],
  );
  const rows = useMemo(() => (filter === 'all' ? all : all.filter((a) => stateOf(a) === filter)), [all, filter]);
  const selectedId = route.params.id ?? null;
  const selected = all.find((a) => String(a.id) === selectedId) ?? null;

  useEffect(() => {
    if (!selectedId && rows.length > 0) route.setParams({ id: String(rows[0]!.id) });
  }, [selectedId, rows, route]);

  const columns = useMemo<Column<Approval>[]>(
    () => [
      { id: 'status', header: 'Status', width: '82px', sortKey: (a) => ORDER.indexOf(stateOf(a)), render: (a) => <StatusTag value={stateOf(a)} /> },
      { id: 'action', header: 'Action', width: '128px', sortKey: (a) => a.action.action_type, render: (a) => <span className="mono">{a.action.action_type}</span> },
      { id: 'target', header: 'Target', width: 'minmax(0, 1fr)', sortKey: (a) => a.action.target ?? null, render: (a) => <span className="mono">{a.action.target ?? '-'}</span> },
      { id: 'by', header: 'Requested by', width: '104px', sortKey: (a) => a.requested_by, render: (a) => a.requested_by },
      { id: 'at', header: 'Requested (UTC, created)', width: '152px', sortKey: (a) => a.created_utc, render: (a) => <Time ts={a.created_utc} /> },
    ],
    [],
  );

  const count = (s: string) => all.filter((a) => stateOf(a) === s).length;

  const list = (
    <>
      <div className="pane-head">
        <h1>Approvals</h1>
        <span className="spacer" />
        <Button icon="refresh" onClick={reload} disabled={loading}>
          Reload
        </Button>
      </div>
      <div className="filters">
        <div className="group" role="group" aria-label="Status filter">
          <Button aria-pressed={filter === 'all'} onClick={() => setFilter('all')}>
            All <span className="num faint">{all.length}</span>
          </Button>
          {ORDER.map((s) => (
            <Button key={s} aria-pressed={filter === s} onClick={() => setFilter(filter === s ? 'all' : s)}>
              {s} <span className="num faint">{count(s)}</span>
            </Button>
          ))}
        </div>
      </div>
      {error && data && <ErrorNotice what="approvals" error={error} onRetry={reload} />}
      {error && !data ? (
        <ErrorState what="approvals" error={error} onRetry={reload} />
      ) : (
        <DataTable
          label="Approval requests, pending first"
          unit="requests"
          primary
          rows={rows}
          columns={columns}
          rowKey={(a) => String(a.id)}
          selectedKey={selectedId}
          onSelect={(a) => route.setParams({ id: String(a.id) })}
          onOpen={() => document.getElementById('approval-detail-title')?.focus()}
          loading={loading}
          footer={<span>Executor: simulated, no connector is called</span>}
          empty={
            filter !== 'all' ? (
              <EmptyState title={`No ${filter} requests.`}>
                <button type="button" className="linklike" onClick={() => setFilter('all')}>
                  Show all
                </button>
              </EmptyState>
            ) : (
              <EmptyState title="No approval requests.">
                Requests are made from an incident: Incidents, Response, Request approval on a recommended action.
              </EmptyState>
            )
          }
        />
      )}
    </>
  );

  const detail = selected ? (
    <ApprovalDetail key={`${selected.id}-${stateOf(selected)}`} approval={selected} me={session.username} onChanged={reload} />
  ) : (
    <EmptyState title="No request selected." />
  );

  return <SplitPane id="approvals" left={list} right={detail} initial={52} />;
}

function ApprovalDetail({ approval: a, me, onChanged }: { approval: Approval; me: string; onChanged: () => void }) {
  const { session, toast } = useApp();
  const [reason, setReason] = useState('');
  const [reasonError, setReasonError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmExecute, setConfirmExecute] = useState(false);

  const canDecide = can(session.role, 'approval.decide');
  const own = a.requested_by === me;

  const decide = async (approved: boolean) => {
    if (!reason.trim()) {
      setReasonError('Enter a reason. It is stored with the decision and in the audit log.');
      document.getElementById('ap-reason')?.focus();
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.decideApproval(a.id, approved, reason.trim());
      toast(`Request ${a.id} ${approved ? 'approved' : 'rejected'}.`);
      onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? describeError(err) : String(err));
      setBusy(false);
    }
  };

  const execute = async () => {
    setBusy(true);
    setError(null);
    try {
      const res = await api.executeApproval(a.id);
      toast(`Request ${a.id} executed (${res.mode}): ${res.note}.`);
      onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? describeError(err) : String(err));
      setBusy(false);
      setConfirmExecute(false);
    }
  };

  return (
    <>
      <div className="pane-head">
        <h2 id="approval-detail-title" tabIndex={-1}>
          Request <span className="mono num">{a.id}</span>
        </h2>
        <StatusTag value={stateOf(a)} />
      </div>
      <div className="detail-scroll">
        <div className="section">
          <dl className="kv">
            <dt>Action</dt>
            <dd className="mono">{a.action.action_type}</dd>
            <dt>Target</dt>
            <dd>{a.action.target ? <Id value={a.action.target} label="Copy target" /> : <span className="faint">no specific target</span>}</dd>
            <dt>Note</dt>
            <dd>{a.action.note ?? <span className="faint">-</span>}</dd>
            <dt>Incident</dt>
            <dd>
              <a className="mono" href={`#/incidents?id=${encodeURIComponent(a.incident_id)}`}>
                {a.incident_id}
              </a>{' '}
              <span className="faint">open the evidence behind this request</span>
            </dd>
            <dt>Requested</dt>
            <dd>
              {a.requested_by}, <Time ts={a.created_utc} />
            </dd>
            <dt>Decision</dt>
            <dd>
              {a.decided_utc ? (
                <>
                  {a.status} by {a.reviewer}, <Time ts={a.decided_utc} />
                </>
              ) : (
                <span className="faint">not decided</span>
              )}
            </dd>
            {a.reason && (
              <>
                <dt>Reason</dt>
                <dd>{a.reason}</dd>
              </>
            )}
            <dt>Execution</dt>
            <dd>
              {a.executed_utc ? (
                <>
                  simulated, by {a.executed_by}, <Time ts={a.executed_utc} />
                </>
              ) : (
                <span className="faint">not executed</span>
              )}
            </dd>
          </dl>
        </div>

        <div className="section">
          <h3>
            Rules for this request (<Term id="four-eyes">four-eyes approval</Term>)
          </h3>
          <ul className="rules">
            <li data-hit={own || undefined}>
              <Icon name={own ? 'warning' : 'check'} /> Four-eyes: the requester cannot decide.{' '}
              {own ? <strong>You requested this, so you cannot approve or reject it.</strong> : `Requested by ${a.requested_by}.`}
            </li>
            <li>
              <Icon name="check" /> A decision needs a written reason; it is stored with the request and in the audit log.
            </li>
            <li>
              <Icon name="check" /> An approved action runs once, by a manager or admin, and is simulated (no connector is called).
            </li>
          </ul>
        </div>

        <EvidenceSummary incidentId={a.incident_id} />
        <Trail approval={a} />

        {a.status === 'pending' && (
          <div className="section">
            <h3>Decision</h3>
            {!canDecide ? (
              <p className="muted">Your role ({session.role}) cannot decide requests. A manager or admin decides.</p>
            ) : own ? (
              <p className="muted">You made this request. Another manager or admin must decide it (four-eyes rule).</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxWidth: 520 }}>
                <div className="field">
                  <label htmlFor="ap-reason">Reason (required, {reason.trim().length} / 2000)</label>
                  <textarea
                    id="ap-reason"
                    className="textarea"
                    rows={3}
                    maxLength={2000}
                    value={reason}
                    onChange={(e) => (setReason(e.target.value), setReasonError(null))}
                    aria-invalid={reasonError ? true : undefined}
                    aria-describedby={reasonError ? 'ap-reason-err' : undefined}
                  />
                  {reasonError && (
                    <span className="field-error" id="ap-reason-err" role="alert">
                      {reasonError}
                    </span>
                  )}
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <Button kind="primary" onClick={() => void decide(true)} disabled={busy}>
                    Approve
                  </Button>
                  <Button kind="danger" onClick={() => void decide(false)} disabled={busy}>
                    Reject
                  </Button>
                </div>
              </div>
            )}
          </div>
        )}

        {a.status === 'approved' && !a.executed_utc && (
          <div className="section">
            <h3>
              <Term id="simulated">Execution</Term>
            </h3>
            {can(session.role, 'action.execute') ? (
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                {confirmExecute ? (
                  <>
                    <span>
                      Execute <span className="mono">{a.action.action_type}</span> on <span className="mono">{a.action.target ?? 'no target'}</span>? It can run
                      once.
                    </span>
                    <Button kind="primary" onClick={() => void execute()} disabled={busy}>
                      Confirm execute
                    </Button>
                    <Button onClick={() => setConfirmExecute(false)} disabled={busy}>
                      Cancel
                    </Button>
                  </>
                ) : (
                  <Button onClick={() => setConfirmExecute(true)}>Execute (simulated)</Button>
                )}
              </div>
            ) : (
              <p className="muted">Your role ({session.role}) cannot execute actions.</p>
            )}
            <p className="faint" style={{ marginTop: 4 }}>
              Simulated: no connector is called and nothing outside SentinelAI changes.
            </p>
          </div>
        )}

        {error && (
          <div className="section">
            <p className="field-error" role="alert">
              {error}
            </p>
          </div>
        )}
      </div>
    </>
  );
}

/** What the request is about: the incident's severity, triage rule, size and detectors. */
function EvidenceSummary({ incidentId }: { incidentId: string }) {
  const { data, error } = useLoad((signal) => api.analysis(incidentId, signal), [incidentId]);
  return (
    <div className="section">
      <h3>
        <Term id="evidence">Evidence</Term>
      </h3>
      {error && <p className="field-error">The incident could not be loaded: {describeError(error)}</p>}
      {!data && !error && <SkeletonLines lines={2} />}
      {data && (
        <dl className="kv">
          <dt>Incident</dt>
          <dd>
            <SeverityCell value={data.summary.severity} /> <span className="mono">{incidentId}</span>
          </dd>
          <dt>Why</dt>
          <dd>{data.summary.rule ? `${data.summary.rule.severity} because ${data.summary.rule.rule} (rule ${data.summary.rule.row})` : 'no triage rule recorded'}</dd>
          <dt>Alerts</dt>
          <dd className="num">
            {fmtInt(data.summary.alerts)} from {data.summary.detectors_agreeing} detector{data.summary.detectors_agreeing === 1 ? '' : 's'},{' '}
            <Time ts={data.summary.first_ts} /> to <Time ts={data.summary.last_ts} kind="data" />
          </dd>
          <dt>Entities</dt>
          <dd className="mono">
            {data.graph.nodes
              .slice(0, 6)
              .map((n) => n.value)
              .join(', ')}
            {data.graph.nodes_total > 6 ? ` +${data.graph.nodes_total - 6}` : ''}
          </dd>
          <dt>ATT&amp;CK</dt>
          <dd>{data.kill_chain.filter((k) => k.alerts > 0).map((k) => k.name).join(', ') || 'no mapped alert'}</dd>
        </dl>
      )}
      <a href={`#/incidents?id=${encodeURIComponent(incidentId)}`}>Open the incident with its alerts and evidence</a>
    </div>
  );
}

/** The request's history: from the approval record, plus the audit entries for roles that may read them. */
function Trail({ approval: a }: { approval: Approval }) {
  const { session } = useApp();
  const mayAudit = can(session.role, 'audit.read');
  const audit = useLoad((signal) => (mayAudit ? api.audit(signal) : Promise.resolve(null)), [mayAudit, a.id, a.status, a.executed_utc]);
  const entries = (audit.data?.entries ?? []).filter((e) => e.target === `approval:${a.id}`).sort((x, y) => (x.ts < y.ts ? -1 : 1));
  const steps: Array<[string, string | null, string]> = [
    ['requested', a.created_utc, `by ${a.requested_by}`],
    [a.status === 'pending' ? 'decision pending' : a.status, a.decided_utc, a.reviewer ? `by ${a.reviewer}: ${a.reason ?? ''}` : 'waiting for a manager or admin'],
  ];
  if (a.status === 'approved') steps.push([a.executed_utc ? 'executed (simulated)' : 'not executed yet', a.executed_utc, a.executed_by ? `by ${a.executed_by}` : '']);
  return (
    <div className="section">
      <h3>Audit trail</h3>
      <ol className="trail">
        {steps.map(([what, ts, who]) => (
          <li key={what} data-done={ts ? true : undefined}>
            <span className="trail-what">{what}</span> {ts ? <Time ts={ts} /> : <span className="faint">-</span>} <span className="muted">{who}</span>
          </li>
        ))}
      </ol>
      {mayAudit ? (
        entries.length > 0 && (
          <table className="data-table" style={{ marginTop: 'var(--sp-8)' }}>
            <caption className="visually-hidden">Audit log entries for this request</caption>
            <thead>
              <tr>
                <th>Time (UTC)</th>
                <th>User</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.id}>
                  <td>
                    <Time ts={e.ts} />
                  </td>
                  <td>
                    {e.username} <span className="faint">({e.role})</span>
                  </td>
                  <td className="mono">{e.action}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )
      ) : (
        <p className="faint" style={{ fontSize: 'var(--fs-small)' }}>
          The full audit log is visible to managers and admins.
        </p>
      )}
    </div>
  );
}
