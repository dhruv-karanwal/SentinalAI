// Audit: the API's audit log (every write, every denied request), newest first. Read-only.

import { useMemo, useState } from 'react';

import { api, type AuditEntry } from '../api.ts';
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
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const all = data?.entries ?? [];
    return needle ? all.filter((e) => `${e.username} ${e.role} ${e.action} ${e.target ?? ''}`.toLowerCase().includes(needle)) : all;
  }, [data, q]);
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
      </div>
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
