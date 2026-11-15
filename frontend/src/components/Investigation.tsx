// Investigation workspace (C2, 2026-11-15): start a single-agent or graph investigation of the
// incident and read what each agent did, what it retrieved and what the verifier kept.
// Every value comes from GET /investigations/{id}; model output and log text are text nodes only.

import { useEffect, useRef, useState } from 'react';

import { api, ApiError, can, type Investigation as Inv, type InvestigationResult } from '../api.ts';
import { useApp, useLoad } from '../hooks.ts';
import { fmtInt } from '../lib/format.ts';
import { isTerminal, nodeLabel, pollDelay, statusLine, summarizeStep } from '../lib/investigation.ts';
import { Button, DefGrid, describeError, Disclosure, EmptyState, ErrorNotice, SkeletonLines, StatusTag, Time } from './ui.tsx';

type Workflow = 'graph' | 'single';

const WORKFLOW_TEXT: Record<Workflow, string> = {
  graph: 'Multi-agent graph: a supervisor routes six role agents that share notes; report generation writes the answer.',
  single: 'Single agent: one tool-using loop over the same alerts and the same ATT&CK search.',
};

export function InvestigationPanel({ incidentId, onOpenEvidence }: { incidentId: string; onOpenEvidence: (alertId: string, needles: string[]) => void }) {
  const { session, toast } = useApp();
  const [workflow, setWorkflow] = useState<Workflow>('graph');
  const [selected, setSelected] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<ApiError | null>(null);
  const history = useLoad((signal) => api.investigations(incidentId, signal), [incidentId]);
  const rows = history.data?.investigations ?? [];
  const current = selected ?? rows[0]?.investigation_id ?? null;
  const allowed = can(session.role, 'investigation.run');

  const start = async () => {
    setStarting(true);
    setStartError(null);
    try {
      const r = await api.startInvestigation(incidentId, workflow);
      setSelected(r.investigation_id);
      history.reload();
      toast(`Investigation ${r.investigation_id} started (${workflow}).`);
    } catch (err) {
      setStartError(err instanceof ApiError ? err : new ApiError(0, '', String(err)));
    } finally {
      setStarting(false);
    }
  };

  return (
    <div className="inv">
      <div className="block">
        <div className="block-title">
          Investigate this incident <span className="meta">read-only agents; nothing is executed</span>
        </div>
        {allowed ? (
          <>
            <div className="inv-start">
              <div className="segmented" role="group" aria-label="Workflow">
                <Button aria-pressed={workflow === 'graph'} onClick={() => setWorkflow('graph')}>Multi-agent graph</Button>
                <Button aria-pressed={workflow === 'single'} onClick={() => setWorkflow('single')}>Single agent</Button>
              </div>
              <Button kind="primary" icon="play" disabled={starting} onClick={() => void start()}>
                {starting ? 'Starting...' : 'Start investigation'}
              </Button>
            </div>
            <p className="quiet-note">{WORKFLOW_TEXT[workflow]} Both use the case budgets of the study and the same evidence verifier.</p>
            {startError && (
              <p className="notice" data-kind="error" role="alert">
                {startError.status === 503
                  ? 'No local model is configured or reachable, so no investigation can run. Start Ollama and set SENTINEL_LLM_BASE_URL / SENTINEL_LLM_MODEL for the API.'
                  : startError.status === 429
                    ? 'The local model is busy with another job (help chat or an investigation). Try again when it is free.'
                    : describeError(startError)}
              </p>
            )}
          </>
        ) : (
          <p className="quiet-note">Your role can read investigations but not start them.</p>
        )}
      </div>

      {history.loading && !history.data && (
        <div className="block" aria-busy="true">
          <SkeletonLines lines={3} />
        </div>
      )}
      {history.error && history.error.status === 403 && (
        <div className="block">
          <EmptyState title="Investigations quote raw log lines.">Your role does not see raw records, so investigations are not shown.</EmptyState>
        </div>
      )}
      {history.error && history.error.status !== 403 && (
        <div className="block">
          <ErrorNotice what="investigations" error={history.error} onRetry={history.reload} />
        </div>
      )}
      {history.data && rows.length === 0 && (
        <div className="block">
          <EmptyState title="No investigation of this incident yet.">
            Start one above. The agents read only this incident's alerts; their steps, the ATT&CK techniques they looked up and the verifier's result are stored and shown here.
          </EmptyState>
        </div>
      )}
      {rows.length > 0 && (
        <div className="block">
          <div className="block-title">
            Runs <span className="meta">{fmtInt(rows.length)} for this incident, newest first</span>
          </div>
          <ul className="inv-runs">
            {rows.map((r) => (
              <li key={r.investigation_id}>
                <button type="button" className="inv-run" aria-pressed={r.investigation_id === current} onClick={() => setSelected(r.investigation_id)}>
                  <StatusTag value={r.status} />
                  <span>{r.workflow === 'graph' ? 'Multi-agent graph' : 'Single agent'}</span>
                  <span className="muted">by {r.requested_by}</span>
                  <Time ts={r.started_utc} kind="created" />
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
      {current && <InvestigationView id={current} onFinished={history.reload} onOpenEvidence={onOpenEvidence} />}
    </div>
  );
}

function InvestigationView({ id, onFinished, onOpenEvidence }: { id: string; onFinished: () => void; onOpenEvidence: (alertId: string, needles: string[]) => void }) {
  const [inv, setInv] = useState<Inv | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [now, setNow] = useState(Date.now());
  const finished = useRef(false);

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const ctl = new AbortController();
    const first = Date.now();
    finished.current = false;
    setInv(null);
    const poll = () => {
      api.investigation(id, ctl.signal).then(
        (data) => {
          setInv(data);
          setError(null);
          setNow(Date.now());
          if (!isTerminal(data.status)) {
            timer = setTimeout(poll, pollDelay(Date.now() - first));
          } else if (!finished.current) {
            finished.current = true;
            onFinished();
          }
        },
        (err: unknown) => {
          if (ctl.signal.aborted) return;
          setError(err instanceof ApiError ? err : new ApiError(0, '', String(err)));
          timer = setTimeout(poll, 5_000); // keep the last data, try again
        },
      );
    };
    poll();
    return () => {
      ctl.abort();
      if (timer) clearTimeout(timer);
    };
    // onFinished is a reload callback; re-polling when it changes identity would loop
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  if (!inv) {
    return error ? (
      <div className="block">
        <ErrorNotice what="the investigation" error={error} />
      </div>
    ) : (
      <div className="block" aria-busy="true">
        <SkeletonLines lines={5} />
      </div>
    );
  }
  const res = inv.result;
  return (
    <InvestigationBody inv={inv} res={res} now={now} error={error} onOpenEvidence={onOpenEvidence} />
  );
}

function InvestigationBody({ inv, res, now, error, onOpenEvidence }: { inv: Inv; res: InvestigationResult | null; now: number; error: ApiError | null; onOpenEvidence: (alertId: string, needles: string[]) => void }) {
  const { session, toast } = useApp();
  const [writing, setWriting] = useState(false);
  const writeReport = async () => {
    setWriting(true);
    try {
      const r = await api.createReport(inv.incident_id, inv.investigation_id);
      toast(`Report ${r.report_id} written with this investigation (open it in Reports).`);
    } catch (err) {
      toast(err instanceof ApiError ? describeError(err) : String(err), 'error');
    } finally {
      setWriting(false);
    }
  };
  return (
    <div className="inv-view" aria-live="polite">
      <div className="block">
        <div className="block-title">
          {inv.workflow === 'graph' ? 'Multi-agent graph' : 'Single agent'} <StatusTag value={inv.status} />
          <span className="meta">{inv.investigation_id}</span>
        </div>
        <p>{statusLine(inv, now)}</p>
        {inv.status === 'completed' && can(session.role, 'report.create') && (
          <div>
            <Button icon="reports" disabled={writing} onClick={() => void writeReport()}>
              {writing ? 'Writing report...' : 'Write report with this investigation'}
            </Button>
          </div>
        )}
        {error && <ErrorNotice what="the latest status" error={error} />}
        <DefGrid
          items={[
            { label: 'Started', value: <Time ts={inv.started_utc} kind="created" /> },
            { label: 'Finished', value: inv.completed_utc ? <Time ts={inv.completed_utc} kind="created" /> : 'not yet' },
            { label: 'Model', value: inv.model_id ?? 'none' },
            { label: 'Prompt', value: res?.prompt_version ?? 'n/a' },
            { label: 'Requests / tool calls', value: res ? `${fmtInt(res.usage.requests)} / ${fmtInt(res.usage.tool_calls)}` : 'n/a' },
            { label: 'Tokens in / out', value: res ? `${fmtInt(res.usage.input_tokens)} / ${fmtInt(res.usage.output_tokens)}` : 'n/a' },
            { label: 'ATT&CK search', value: res ? (res.retrieval ? 'on' : 'off (no local index)') : 'n/a' },
          ]}
        />
      </div>
      {res && <Result res={res} onOpenEvidence={onOpenEvidence} />}
    </div>
  );
}

function Result({ res, onOpenEvidence }: { res: InvestigationResult; onOpenEvidence: (alertId: string, needles: string[]) => void }) {
  const v = res.verification;
  return (
    <>
      <div className="block">
        <div className="block-title">
          Conclusion <StatusTag value={res.conclusion.verified ? 'verified' : 'dropped'} />
          <span className="meta">{res.conclusion.note}</span>
        </div>
        <p>
          <span className="muted">Verdict: </span>
          {res.conclusion.verdict ?? 'none (the run did not finish)'}
        </p>
        {res.conclusion.cited_alert_ids.length > 0 && (
          <div className="cite-group">
            <div className="cite-group-head">Evidence kept by the verifier ({fmtInt(res.conclusion.cited_alert_ids.length)})</div>
            <div className="cite-list">
              {res.conclusion.cited_alert_ids.map((a) => (
                <button key={a} type="button" className="cite" onClick={() => onOpenEvidence(a, [])}>
                  <span className="mono">{a.length > 24 ? `${a.slice(0, 24)}...` : a}</span>
                </button>
              ))}
            </div>
          </div>
        )}
        <p className="quiet-note">
          Verifier: {fmtInt(v.citations_kept)} citations kept, {fmtInt(v.citations_dropped)} dropped; {fmtInt(v.claims_kept)} of {fmtInt(v.claims_checked)} claims kept.
        </p>
        {(v.dropped_citations.length > 0 || v.dropped_claims.length > 0) && (
          <Disclosure summary={`What the verifier dropped (${fmtInt(v.dropped_citations.length + v.dropped_claims.length)})`}>
            <ul className="inv-list">
              {v.dropped_citations.map((c) => (
                <li key={`c-${c}`}>
                  <StatusTag value="dropped" /> citation <span className="mono">{c}</span>: not an alert of this incident
                </li>
              ))}
              {v.dropped_claims.map((c, i) => (
                <li key={`k-${i}`}>
                  <StatusTag value="dropped" /> {c.kind} claim on <span className="mono">{c.field ?? 'log line'}</span>: {c.reason}
                </li>
              ))}
            </ul>
          </Disclosure>
        )}
      </div>

      <div className="block">
        <div className="block-title">
          Agent hypotheses <span className="meta">model text, not verified; read it against the evidence</span>
        </div>
        {res.hypotheses.length === 0 ? (
          <p className="muted">No findings in the final answer.</p>
        ) : (
          <ul className="fd-answer">
            {res.hypotheses.map((h, i) => (
              <li key={i}>{h.summary}</li>
            ))}
          </ul>
        )}
      </div>

      <div className="block">
        <div className="block-title">
          Observed facts <span className="meta">claims that match the alert record or its log line exactly</span>
        </div>
        {res.observed.length === 0 ? (
          <p className="muted">No claim survived the verifier.</p>
        ) : (
          <ul className="inv-list">
            {res.observed.map((o, i) => (
              <li key={i}>
                <span className="mono">{o.field}</span> = <span className="mono">{o.value}</span> <span className="muted">on {o.record_id}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="block">
        <div className="block-title">
          Detections behind the evidence <span className="meta">detector, rule and mapped ATT&CK ids of the kept alerts</span>
        </div>
        {res.detections.length === 0 ? (
          <p className="muted">No kept evidence.</p>
        ) : (
          <ul className="inv-list">
            {res.detections.map((d) => (
              <li key={d.alert_id}>
                {d.detector} rule {d.rule_id ?? 'n/a'}
                {d.rule_name ? ` (${d.rule_name})` : ''} {d.techniques.length > 0 ? `· ${d.techniques.join(', ')}` : '· no ATT&CK mapping'}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="block">
        <div className="block-title">
          ATT&CK knowledge retrieved <span className="meta">local ATT&CK v20.1 excerpts the agents looked up; background, not evidence</span>
        </div>
        {res.knowledge.length === 0 ? (
          <p className="muted">{res.retrieval ? 'The agents did not search ATT&CK.' : 'ATT&CK search was off for this run (no local index).'}</p>
        ) : (
          <ul className="inv-list">
            {res.knowledge.map((k) => (
              <li key={k.technique_id}>
                <span className="mono">{k.technique_id}</span> {k.name} <span className="muted">({k.tactics.join(', ') || 'no tactic'}; by {k.retrieved_by.map(nodeLabel).join(', ')})</span>
                {k.excerpt && <div className="quiet-note">{k.excerpt}</div>}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="block">
        <div className="block-title">
          Recommended next steps <span className="meta">playbook rows for the ATT&CK ids of the kept evidence; request them in Response</span>
        </div>
        {res.recommendations.length === 0 ? (
          <p className="muted">None: recommendations are only made from verified evidence.</p>
        ) : (
          <ul className="inv-list">
            {res.recommendations.map((r) => (
              <li key={`${r.action_type}-${r.title}`}>
                {r.title} {r.requires_approval ? <StatusTag value="pending" /> : null}
                <span className="muted">
                  {' '}
                  {r.requires_approval ? 'needs a second person to approve' : 'no state change'}
                  {r.techniques.length > 0 ? ` · ${r.techniques.join(', ')}` : ''}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="block">
        <div className="block-title">
          Agent steps <span className="meta">{fmtInt(res.steps.length)} in order{res.trace.length > 0 ? ` · route: ${res.trace.map(nodeLabel).join(' > ')}` : ''}</span>
        </div>
        <ol className="inv-steps">
          {res.steps.map((s, i) => {
            const sum = summarizeStep(s);
            return (
              <li key={i}>
                <Disclosure
                  summary={
                    <span>
                      {sum.label}
                      <span className="muted">
                        {' '}
                        · {fmtInt(sum.toolCalls)} tool call{sum.toolCalls === 1 ? '' : 's'}
                        {sum.tools.length > 0 ? ` (${sum.tools.join(', ')})` : ''}
                        {sum.routedTo ? ` · routed to ${nodeLabel(sum.routedTo)}` : ''}
                        {sum.ended === 'note' ? ' · wrote a note' : sum.ended === 'final' ? ' · final answer' : sum.ended === 'unparseable' ? ' · unparseable reply' : ''}
                      </span>
                    </span>
                  }
                >
                  <ul className="inv-events">
                    {s.events.map((e, j) => (
                      <li key={j} data-type={e.type}>
                        <span className="muted">{e.type === 'tool_result' ? `tool result (${e.tool})` : e.type === 'reply' ? `model reply${e.action ? `: ${e.action}` : ''}` : 'message'}</span>
                        <pre className="inv-text">{e.text}</pre>
                      </li>
                    ))}
                  </ul>
                </Disclosure>
              </li>
            );
          })}
        </ol>
        {res.notes.length > 0 && (
          <Disclosure summary={`Shared notes (${fmtInt(res.notes.length)})`}>
            <ul className="inv-list">
              {res.notes.map((n) => (
                <li key={n.n}>
                  <span className="muted">{nodeLabel(n.agent)}: </span>
                  {n.text}
                </li>
              ))}
            </ul>
          </Disclosure>
        )}
        <p className="quiet-note">Alert ids inside steps are the opaque ids the agents saw; the evidence links above use the stored ids. {res.note}.</p>
      </div>
    </>
  );
}
