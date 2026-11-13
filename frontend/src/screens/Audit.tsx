// Audit: the API's audit log (every write, every denied request), newest first. Read-only.

import { useMemo, useState } from 'react';

import { api, type AuditEntry } from '../api.ts';
import { ChartFrame } from '../charts/ChartFrame.tsx';
import { TimeBars } from '../charts/TimeBars.tsx';
import { epochSeconds, fmtDuration, fmtInt } from '../lib/format.ts';
import { binByKey } from '../lib/scale.ts';
import { DataTable, type Column } from '../components/DataTable.tsx';
import { SplitPane } from '../components/SplitPane.tsx';
import { Button, EmptyState, ErrorNotice, ErrorState, Time } from '../components/ui.tsx';
import { useLoad, type Route } from '../hooks.ts';
import { Icon } from '../icons.tsx';

interface Props {
  route: Route & { setParams: (patch: Record<string, string | null>, replace?: boolean) => void };
  searchRef: React.RefObject<HTMLInputElement | null>;
}

export function AuditScreen({ route, searchRef }: Props) {
  const { data, error, loading, reload } = useLoad((signal) => api.audit(signal), []);
  const [q, setQ] = useState('');
  const [user, setUser] = useState('');
  const [action, setAction] = useState('');
  const all = useMemo(() => data?.entries ?? [], [data]);
  const users = useMemo(() => [...new Set(all.map((e) => e.username))].sort(), [all]);
  const actions = useMemo(() => [...new Set(all.map((e) => e.action))].sort(), [all]);
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return all.filter(
      (e) => (!user || e.username === user) && (!action || e.action === action) && (!needle || `${e.username} ${e.role} ${e.action} ${e.target ?? ''}`.toLowerCase().includes(needle)),
    );
  }, [all, q, user, action]);
  const activity = useMemo(() => binByKey(rows.map((e) => ({ t: epochSeconds(e.ts), key: family(e.action) }))), [rows]);
  const selectedId = route.params.id ?? null;
  const selected = (data?.entries ?? []).find((e) => String(e.id) === selectedId) ?? null;

  const columns = useMemo<Column<AuditEntry>[]>(
    () => [
      { id: 'ts', header: 'Time (UTC)', width: '152px', sortKey: (e) => e.ts, render: (e) => <Time ts={e.ts} /> },
      { id: 'user', header: 'User', width: '104px', sortKey: (e) => e.username, render: (e) => e.username },
      { id: 'role', header: 'Role', width: '72px', sortKey: (e) => e.role, render: (e) => e.role },
      {
        id: 'action',
        header: 'Action',
        width: '152px',
        sortKey: (e) => e.action,
        render: (e) => (
          <span className="mono" style={e.action === 'denied' || e.action.endsWith('failed') || e.action.endsWith('refused') ? { fontWeight: 600 } : undefined}>
            {e.action}
          </span>
        ),
      },
      { id: 'target', header: 'Target', width: 'minmax(0, 1fr)', sortKey: (e) => e.target, title: (e) => e.target ?? '', render: (e) => <span className="mono">{e.target ?? '-'}</span> },
    ],
    [],
  );

  const list = (
    <>
      <div className="pane-head">
        <h1>Audit</h1>
        <span className="spacer" />
        <Button icon="refresh" onClick={reload} disabled={loading}>
          Reload
        </Button>
      </div>
      <div className="filters" role="search">
        <div className="search">
          <Icon name="search" />
          <label className="visually-hidden" htmlFor="audit-q">
            Filter by user, role, action or target
          </label>
          <input id="audit-q" ref={searchRef} className="input" placeholder="Filter by user, action or target ( / )" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <label className="label" htmlFor="audit-user">
          User
        </label>
        <select id="audit-user" className="select" value={user} onChange={(e) => setUser(e.target.value)}>
          <option value="">all</option>
          {users.map((u) => (
            <option key={u}>{u}</option>
          ))}
        </select>
        <label className="label" htmlFor="audit-action">
          Action
        </label>
        <select id="audit-action" className="select mono" value={action} onChange={(e) => setAction(e.target.value)}>
          <option value="">all</option>
          {actions.map((a) => (
            <option key={a}>{a}</option>
          ))}
        </select>
      </div>
      {activity.bins > 0 && (
        <div style={{ padding: '0 var(--sp-12)' }}>
          <ChartFrame
            className="compact-chart"
            title="Activity over time"
            question="When did people act, and when were requests refused?"
            legend={[
              { key: 'write', label: 'changes', tone: 'ref' },
              { key: 'sign-in', label: 'sign-ins', tone: 'muted' },
              { key: 'refused', label: 'denied, failed or refused', tone: 'high' },
            ]}
            table={{ columns: ['bin start (UTC)', 'changes', 'sign-ins', 'refused'], rows: Array.from({ length: activity.bins }, (_, i) => [new Date((activity.start + i * activity.step) * 1000).toISOString(), activity.series.write?.[i] ?? 0, activity.series['sign-in']?.[i] ?? 0, activity.series.refused?.[i] ?? 0]) }}
            note={`${fmtInt(rows.length)} entries in bins of ${fmtDuration(activity.step)} (the newest 1,000 entries are loaded).`}
          >
            <TimeBars
              series={Object.fromEntries(['write', 'sign-in', 'refused'].filter((k) => activity.series[k]).map((k) => [k, activity.series[k]!]))}
              start={activity.start}
              binSeconds={activity.step}
              height={96}
              label="Audit activity over time"
              tones={{ write: 'ref', 'sign-in': 'muted', refused: 'high' }}
              names={{ write: 'changes', 'sign-in': 'sign-ins', refused: 'refused' }}
            />
          </ChartFrame>
        </div>
      )}
      {error && data && <ErrorNotice what="the audit log" error={error} onRetry={reload} />}
      {error && !data ? (
        <ErrorState what="the audit log" error={error} onRetry={reload} />
      ) : (
        <DataTable
          label="Audit log, newest first"
          unit="entries"
          primary
          rows={rows}
          columns={columns}
          rowKey={(e) => String(e.id)}
          selectedKey={selectedId}
          onSelect={(e) => route.setParams({ id: String(e.id) })}
          loading={loading}
          footer={<span>The newest 1,000 entries are loaded</span>}
          empty={q.trim() ? <EmptyState title={`No audit entry matches "${q.trim()}".`} /> : <EmptyState title="The audit log is empty." />}
        />
      )}
    </>
  );

  const detail = selected ? (
    <>
      <div className="pane-head">
        <h2>
          Entry <span className="mono num">{selected.id}</span>
        </h2>
      </div>
      <div className="detail-scroll">
        <div className="section">
          <dl className="kv">
            <dt>Time (UTC)</dt>
            <dd>
              <Time ts={selected.ts} />
            </dd>
            <dt>User</dt>
            <dd>
              {selected.username} <span className="faint">({selected.role})</span>
            </dd>
            <dt>Action</dt>
            <dd className="mono">{selected.action}</dd>
            <dt>Target</dt>
            <dd className="mono">{selected.target ?? '-'}</dd>
          </dl>
        </div>
        <div className="section">
          <h3>Detail</h3>
          <pre className="raw">{typeof selected.detail === 'string' ? selected.detail : JSON.stringify(selected.detail, null, 2)}</pre>
        </div>
      </div>
    </>
  ) : (
    <EmptyState title="No entry selected.">Select a row to read its detail.</EmptyState>
  );

  return <SplitPane id="audit" left={list} right={detail} initial={62} />;
}

export function family(action: string): 'write' | 'sign-in' | 'refused' {
  if (action === 'denied' || action.endsWith('failed') || action.endsWith('refused')) return 'refused';
  if (action === 'login') return 'sign-in';
  return 'write';
}
