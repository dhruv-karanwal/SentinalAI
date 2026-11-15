// Ask: questions put to the copilot in this session (kept in memory only), each with its
// verified citations and whatever the verifier dropped.

import { useEffect, useMemo, useState } from 'react';

import { can } from '../api.ts';
import { DataTable, type Column } from '../components/DataTable.tsx';
import { EvidencePane } from '../components/EvidencePane.tsx';
import { AskForm, Finding, type AskEntry, type AskStore } from '../components/Findings.tsx';
import { SplitPane } from '../components/SplitPane.tsx';
import { EmptyState, ModelOffline, PageHeader, Time } from '../components/ui.tsx';
import { useApp, type Route } from '../hooks.ts';
import { Icon } from '../icons.tsx';
import { fitColumns, useNarrow } from '../components/narrow.ts';

interface Props {
  route: Route & { setParams: (patch: Record<string, string | null>, replace?: boolean) => void };
  askStore: AskStore;
}

export function AskScreen({ route, askStore }: Props) {
  const { session } = useApp();
  const [incidentId, setIncidentId] = useState(route.params.incident ?? askStore.entries[0]?.incidentId ?? '');
  const [needles, setNeedles] = useState<string[]>([]);
  const entries = askStore.entries;
  const selectedId = route.params.id ?? null;
  const selected = entries.find((e) => e.id === selectedId) ?? null;
  const ev = route.params.ev ?? null;

  useEffect(() => {
    if (entries.length > 0 && (!selectedId || !entries.some((e) => e.id === selectedId))) route.setParams({ id: entries[0]!.id, ev: null });
  }, [entries, selectedId, route]);

  const columns = useMemo<Column<AskEntry>[]>(
    () => [
      { id: 'at', header: 'Asked (UTC)', width: '152px', sortKey: (e) => e.askedUtc, render: (e) => <Time ts={e.askedUtc} /> },
      { id: 'status', header: 'Run', width: '64px', sortKey: (e) => e.answer.status, render: (e) => e.answer.status },
      {
        id: 'cites',
        header: 'Kept / dropped',
        width: '96px',
        align: 'right',
        render: (e) => `${e.answer.verification.citations_kept} / ${e.answer.verification.citations_dropped}`,
      },
      { id: 'q', header: 'Question', width: 'minmax(0, 1fr)', title: (e) => e.question, render: (e) => e.question },
    ],
    [],
  );

  const narrow = useNarrow();
  const cols = useMemo(() => fitColumns(columns, narrow, ['status']), [columns, narrow]);
  const allowed = can(session.role, 'copilot.ask');

  const list = !allowed ? (
    <div className="state" data-kind="error" role="alert">
      <div className="state-title">
        <Icon name="warning" />
        Not permitted
      </div>
      <p>Your role ({session.role}) cannot ask the copilot.</p>
    </div>
  ) : (
    <>
      <section className="block" aria-label="Ask a question">
        <div className="field">
          <label htmlFor="ask-incident">Incident id (copy it from Incidents with c)</label>
          <input id="ask-incident" className="input mono" value={incidentId} onChange={(e) => setIncidentId(e.target.value.trim())} placeholder="inc-..." spellCheck={false} />
        </div>
        {incidentId ? <AskForm incidentId={incidentId} store={askStore} /> : askStore.modelOffline ? <ModelOffline /> : <p className="quiet-note">Enter an incident id to ask about it.</p>}
      </section>
      <DataTable
        label="Questions asked in this session"
        unit="questions"
        primary
        rows={entries}
        columns={cols}
        rowKey={(e) => e.id}
        selectedKey={selectedId}
        onSelect={(e) => route.setParams({ id: e.id, ev: null })}
        footer={<span>Kept for this session only</span>}
        empty={
          <EmptyState title="No questions asked in this session.">
            Answers use the incident's alerts only. Every citation and claim is checked against the alert records.
          </EmptyState>
        }
      />
    </>
  );

  const detail = selected ? (
    <>
      <div className="pane-bar">
        <h2>Answer</h2>
        <a className="mono" href={`#/incidents?id=${encodeURIComponent(selected.incidentId)}`}>
          {selected.incidentId}
        </a>
      </div>
      <div className="detail-scroll">
        <div className="block">
          <Finding
            entry={selected}
            onOpenEvidence={(id, hl) => {
              setNeedles(hl);
              route.setParams({ ev: id });
            }}
          />
        </div>
      </div>
      {ev && (
        <div className="ev-overlay">
          <EvidencePane alertId={ev} needles={needles} focusKey={ev} onClose={() => route.setParams({ ev: null })} />
        </div>
      )}
    </>
  ) : askStore.modelOffline && allowed ? (
    <ModelOffline />
  ) : (
    <EmptyState title="No answer selected.">Ask a question on the left; its answer, citations and verifier marks appear here.</EmptyState>
  );

  return (
    <div className="work">
      <PageHeader bar title="Ask" purpose="What does the model say, and what did the verifier keep?" />
      <SplitPane id="ask" left={list} right={detail} initial={44} />
    </div>
  );
}
