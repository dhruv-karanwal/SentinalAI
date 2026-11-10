// Approvals: requests for state-changing actions. A manager or admin who did not make the
// request decides it with a reason; an approved request is executed once, by a simulated executor.

import { useEffect, useMemo, useState } from 'react';

import { api, ApiError, can, type Approval } from '../api.ts';
import { DataTable, type Column } from '../components/DataTable.tsx';
import { SplitPane } from '../components/SplitPane.tsx';
import { Button, describeError, EmptyState, ErrorNotice, ErrorState, Id, StatusTag, Time } from '../components/ui.tsx';
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
      { id: 'at', header: 'Requested (UTC)', width: '152px', sortKey: (a) => a.created_utc, render: (a) => <Time ts={a.created_utc} /> },
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
                  <label htmlFor="ap-reason">Reason (required)</label>
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
            <h3>Execution</h3>
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
