// Approvals: requests for state-changing actions. A manager or admin who did not make the
// request decides it with a reason; an approved request is executed once, by a simulated executor.

import { Term } from '../components/Term.tsx';
import { useEffect, useMemo, useState } from 'react';

import { api, ApiError, can, type Approval } from '../api.ts';
import { DataTable, type Column } from '../components/DataTable.tsx';
import { SplitPane } from '../components/SplitPane.tsx';
import { Button, DefGrid, describeError, EmptyState, ErrorNotice, ErrorState, Id, PageHeader, SeverityCell, SkeletonLines, StatusTag, Time } from '../components/ui.tsx';
import { Icon } from '../icons.tsx';
import { fmtInt } from '../lib/format.ts';
import { useApp, useLoad, type Route } from '../hooks.ts';
import { fitColumns, useNarrow } from '../components/narrow.ts';

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

  const narrow = useNarrow();
  const cols = useMemo(() => fitColumns(columns, narrow, ['by', 'at']), [columns, narrow]);
  const count = (s: string) => all.filter((a) => stateOf(a) === s).length;

  const list = (
    <>
      <div className="toolbar">
        <div className="segmented" role="group" aria-label="Status filter">
          <Button aria-pressed={filter === 'all'} onClick={() => setFilter('all')}>
            All <span className="seg-count num">{fmtInt(all.length)}</span>
          </Button>
          {ORDER.map((s) => (
            <Button key={s} aria-pressed={filter === s} onClick={() => setFilter(filter === s ? 'all' : s)}>
              {s.charAt(0).toUpperCase() + s.slice(1)} <span className="seg-count num">{fmtInt(count(s))}</span>
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
          columns={cols}
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
                  Clear filters
                </button>
              </EmptyState>
            ) : (
              <EmptyState title="No approval requests.">Requests are made from an incident: Incidents, Response, Request approval on a recommended action.</EmptyState>
            )
          }
        />
      )}
    </>
  );

  const detail = selected ? (
    <ApprovalDetail key={`${selected.id}-${stateOf(selected)}`} approval={selected} me={session.username} onChanged={reload} />
  ) : loading && !data ? (
    <SkeletonLines lines={5} />
  ) : (
    <EmptyState title="No request selected.">Select a request to read it and decide it.</EmptyState>
  );

  return (
    <div className="work">
      <PageHeader
        bar
        title="Approvals"
        purpose="What is waiting for a second person?"
        actions={
          <Button icon="refresh" onClick={reload} disabled={loading}>
            Reload
          </Button>
        }
      />
      <SplitPane id="approvals" left={list} right={detail} initial={52} />
    </div>
  );
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
      <div className="pane-bar">
        <h2 id="approval-detail-title" tabIndex={-1}>
          Request <span className="mono num">{a.id}</span>
        </h2>
        <StatusTag value={stateOf(a)} />
      </div>
      <div className="detail-scroll">
        <section className="block ap-facts" aria-label="Request">
          <DefGrid
            items={[
              { label: 'Action', value: <span className="mono">{a.action.action_type}</span> },
              { label: 'Target', value: a.action.target ? <Id value={a.action.target} label="Copy target" /> : <span className="faint">no specific target</span> },
              {
                label: 'Requested',
                value: (
                  <>
                    {a.requested_by}, <Time ts={a.created_utc} />
                  </>
                ),
              },
              {
                label: 'Incident',
                value: (
                  <a className="mono" href={`#/incidents?id=${encodeURIComponent(a.incident_id)}`}>
                    {a.incident_id}
                  </a>
                ),
              },
              {
                label: 'Decision',
                value: a.decided_utc ? (
                  <>
                    {a.status} by {a.reviewer}, <Time ts={a.decided_utc} />
                  </>
                ) : (
                  <span className="faint">not decided</span>
                ),
              },
              {
                label: 'Execution',
                value: a.executed_utc ? (
                  <>
                    simulated, by {a.executed_by}, <Time ts={a.executed_utc} />
                  </>
                ) : (
                  <span className="faint">not executed</span>
                ),
              },
              { label: 'Note', value: a.action.note ?? <span className="faint">-</span> },
              ...(a.reason ? [{ label: 'Reason', value: a.reason }] : []),
            ]}
          />
        </section>

        <EvidenceSummary incidentId={a.incident_id} />

        {a.status === 'pending' && (
          <section className="block" aria-labelledby="ap-decision-t">
            <h3 className="block-title" id="ap-decision-t">
              Decision
            </h3>
            <RulesNotice own={own} requestedBy={a.requested_by} />
            {!canDecide ? (
              <p className="muted">Your role ({session.role}) cannot decide requests. A manager or admin decides.</p>
            ) : own ? (
              <p className="muted">You made this request. Another manager or admin must decide it (four-eyes rule).</p>
            ) : (
              <div className="decision-form">
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
                <div className="btn-row">
                  <Button kind="primary" onClick={() => void decide(true)} disabled={busy}>
                    Approve
                  </Button>
                  <Button kind="danger" onClick={() => void decide(false)} disabled={busy}>
                    Reject
                  </Button>
                </div>
              </div>
            )}
          </section>
        )}

        {a.status === 'approved' && !a.executed_utc && (
          <section className="block" aria-labelledby="ap-exec-t">
            <h3 className="block-title" id="ap-exec-t">
              <Term id="simulated">Execution</Term>
            </h3>
            <RulesNotice own={own} requestedBy={a.requested_by} />
            {can(session.role, 'action.execute') ? (
              <div className="btn-row">
                {confirmExecute ? (
                  <>
                    <span>
                      Execute <span className="mono">{a.action.action_type}</span> on <span className="mono">{a.action.target ?? 'no target'}</span>? It can run once.
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
          </section>
        )}

        {a.status !== 'pending' && !(a.status === 'approved' && !a.executed_utc) && (
          <section className="block" aria-label="Rules">
            <RulesNotice own={own} requestedBy={a.requested_by} />
          </section>
        )}

        {error && (
          <section className="block">
            <p className="field-error" role="alert">
              {error}
            </p>
          </section>
        )}

        <Trail approval={a} />
      </div>
    </>
  );
}

/** The rules, stated before the controls they govern. */
function RulesNotice({ own, requestedBy }: { own: boolean; requestedBy: string }) {
  return (
    <ul className="rule-notice" aria-label="Rules for this request">
      <li data-hit={own || undefined}>
        <Icon name={own ? 'warning' : 'check'} />
        <span>
          <Term id="four-eyes">Four-eyes</Term>: the requester cannot decide.{' '}
          {own ? <strong>You requested this, so you cannot approve or reject it.</strong> : `Requested by ${requestedBy}.`}
        </span>
      </li>
      <li>
        <Icon name="check" />
        <span>A decision needs a written reason; it is stored with the request and in the audit log.</span>
      </li>
      <li>
        <Icon name="check" />
        <span>An approved action runs once, by a manager or admin, and is simulated: no connector is called and nothing outside SentinelAI changes.</span>
      </li>
    </ul>
  );
}

/** What the request is about: the incident's severity, triage rule, size and detectors. */
function EvidenceSummary({ incidentId }: { incidentId: string }) {
  const { data, error } = useLoad((signal) => api.analysis(incidentId, signal), [incidentId]);
  return (
    <section className="block ap-facts" aria-labelledby="ap-ev-t">
      <h3 className="block-title" id="ap-ev-t">
        <Term id="evidence">Evidence</Term>
        <a className="meta" href={`#/incidents?id=${encodeURIComponent(incidentId)}`}>
          Open the incident with its alerts
        </a>
      </h3>
      {error && <p className="field-error">The incident could not be loaded: {describeError(error)}</p>}
      {!data && !error && <SkeletonLines lines={2} />}
      {data && (
        <DefGrid
          items={[
            { label: 'Severity', value: <SeverityCell value={data.summary.severity} /> },
            {
              label: 'Alerts',
              value: (
                <span className="num">
                  {fmtInt(data.summary.alerts)} from {data.summary.detectors_agreeing} detector{data.summary.detectors_agreeing === 1 ? '' : 's'}
                </span>
              ),
            },
            {
              label: 'Time (UTC, data date)',
              value: (
                <>
                  <Time ts={data.summary.first_ts} /> to <Time ts={data.summary.last_ts} />
                </>
              ),
            },
            { label: 'Why', value: data.summary.rule ? `${data.summary.rule.severity} because ${data.summary.rule.rule} (rule ${data.summary.rule.row})` : 'no triage rule recorded' },
            {
              label: 'Entities',
              value: (
                <span className="mono">
                  {data.graph.nodes
                    .slice(0, 6)
                    .map((n) => n.value)
                    .join(', ')}
                  {data.graph.nodes_total > 6 ? ` +${data.graph.nodes_total - 6}` : ''}
                </span>
              ),
            },
            { label: 'ATT&CK', value: data.kill_chain.filter((k) => k.alerts > 0).map((k) => k.name).join(', ') || 'no mapped alert' },
          ]}
        />
      )}
    </section>
  );
}

/** The request's history: from the approval record, plus the audit entries for roles that may read them. */
function Trail({ approval: a }: { approval: Approval }) {
  const { session } = useApp();
  const mayAudit = can(session.role, 'audit.read');
  const audit = useLoad((signal) => (mayAudit ? api.audit(signal) : Promise.resolve(null)), [mayAudit, a.id, a.status, a.executed_utc]);
  const entries = (audit.data?.entries ?? []).filter((e) => e.target === `approval:${a.id}`).sort((x, y) => (x.ts < y.ts ? -1 : 1));
  const steps: Array<[string, string | null, string]> = [
    ['Requested', a.created_utc, `by ${a.requested_by}`],
    [a.status === 'pending' ? 'Decision pending' : a.status.charAt(0).toUpperCase() + a.status.slice(1), a.decided_utc, a.reviewer ? `by ${a.reviewer}: ${a.reason ?? ''}` : 'waiting for a manager or admin'],
  ];
  if (a.status === 'approved') steps.push([a.executed_utc ? 'Executed (simulated)' : 'Not executed yet', a.executed_utc, a.executed_by ? `by ${a.executed_by}` : '']);
  return (
    <section className="block" aria-labelledby="ap-trail-t">
      <h3 className="block-title" id="ap-trail-t">
        Audit trail
      </h3>
      <ol className="trail-list">
        {steps.map(([what, ts, who]) => (
          <li key={what} data-done={ts ? true : undefined}>
            <span className="what">{what}</span>
            {ts ? <Time ts={ts} /> : <span className="faint">-</span>}
            <span className="muted">{who}</span>
          </li>
        ))}
        {mayAudit &&
          entries.map((e) => (
            <li key={e.id} data-done>
              <span className="what mono">{e.action}</span>
              <Time ts={e.ts} />
              <span className="muted">
                {e.username} ({e.role}), audit log entry {e.id}
              </span>
            </li>
          ))}
      </ol>
      {mayAudit && audit.error && <p className="field-error">The audit log could not be loaded: {describeError(audit.error)}</p>}
      {!mayAudit && <p className="quiet-note">The full audit log is visible to managers and admins.</p>}
    </section>
  );
}
