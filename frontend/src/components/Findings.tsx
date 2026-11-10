// Copilot answers for an incident: the answer text, the citations that passed the verifier as
// links into the evidence pane, and everything the verifier dropped, marked and explained.

import { useState } from 'react';

import { api, ApiError, can, type CopilotAnswer } from '../api.ts';
import { useApp } from '../hooks.ts';
import { fmtInt } from '../lib/format.ts';
import { Button, describeError, ModelOffline, Time } from './ui.tsx';

export interface AskEntry {
  id: string;
  incidentId: string;
  question: string;
  askedUtc: string;
  answer: CopilotAnswer;
}

export interface AskStore {
  entries: AskEntry[];
  modelOffline: boolean;
  add: (entry: AskEntry) => void;
  setOffline: () => void;
}

/** Text to highlight in an alert's evidence: the verified quote claims about that alert. */
export function needlesFor(answer: CopilotAnswer, alertId: string): string[] {
  return (answer.claims ?? []).filter((c) => c.record_id === alertId && c.kind === 'quote').map((c) => c.value);
}

export function Finding({ entry, onOpenEvidence }: { entry: AskEntry; onOpenEvidence: (alertId: string, needles: string[]) => void }) {
  const a = entry.answer;
  const v = a.verification;
  const failed = a.status !== 'ok';
  return (
    <article className="finding" aria-label={`Answer to: ${entry.question}`}>
      <div className="meta-row">
        <span>
          <span className="k">Question</span>
          {entry.question}
        </span>
        <Time ts={entry.askedUtc} />
      </div>
      {failed ? (
        <p className="field-error" role="alert">
          The model run did not produce an answer (status {a.status}
          {a.parse_status ? `, ${a.parse_status}` : ''}){a.error ? `: ${a.error}` : '.'}
        </p>
      ) : (
        <>
          {a.verdict && (
            <div>
              <span className="muted">Model verdict: </span>
              <strong>{a.verdict}</strong>
            </div>
          )}
          <ul className="answer">
            {a.answer.map((line, i) => (
              <li key={i}>{line}</li>
            ))}
          </ul>
        </>
      )}

      <div className="cites">
        <span className="muted">Cited alerts ({v.citations_kept} verified):</span>
        {a.cited_alert_ids.length === 0 && <span className="faint">none</span>}
        {a.cited_alert_ids.map((id) => (
          <button key={id} type="button" className="linklike mono" onClick={() => onOpenEvidence(id, needlesFor(a, id))} title="Open the evidence for this alert">
            {id}
          </button>
        ))}
      </div>

      {(a.claims?.length ?? 0) > 0 && (
        <table className="plain-table">
          <caption className="visually-hidden">Claims that passed the verifier</caption>
          <thead>
            <tr>
              <th>Claim</th>
              <th>Alert</th>
              <th>Field</th>
              <th>Value</th>
            </tr>
          </thead>
          <tbody>
            {a.claims?.map((c, i) => (
              <tr key={i}>
                <td>
                  <span className="tag" data-tone="verified">
                    verified
                  </span>
                </td>
                <td>
                  <button type="button" className="linklike mono" onClick={() => onOpenEvidence(c.record_id, c.kind === 'quote' ? [c.value] : [])}>
                    {c.record_id}
                  </button>
                </td>
                <td className="mono">{c.kind === 'quote' ? 'quote' : c.field}</td>
                <td className="mono">{c.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {(v.citations_dropped > 0 || v.claims_dropped > 0) && (
        <div className="dropped" role="group" aria-label="Dropped by the verifier">
          <div>
            <span className="tag" data-tone="dropped">
              dropped by verifier
            </span>{' '}
            {v.citations_dropped} citation{v.citations_dropped === 1 ? '' : 's'}, {v.claims_dropped} of {v.claims_checked} claim
            {v.claims_checked === 1 ? '' : 's'}. These are not supported by the incident's alerts.
          </div>
          {a.dropped_citations?.map((id) => (
            <div key={id}>
              <span className="mono struck">{id}</span> <span className="muted">citation: not an alert of this incident</span>
            </div>
          ))}
          {a.dropped_claims?.map((c, i) => (
            <div key={i}>
              <span className="mono struck">
                {c.kind === 'quote' ? 'quote' : c.field} on {c.record_id}
              </span>{' '}
              <span className="muted">claim: {c.reason}</span>
            </div>
          ))}
          {a.dropped_citations === undefined && a.dropped_claims === undefined && (
            <div className="muted">This API build returns counts only, not the dropped items.</div>
          )}
        </div>
      )}

      <div className="faint num">
        {a.tool_calls} tool call{a.tool_calls === 1 ? '' : 's'} · {fmtInt(a.input_tokens)} input tokens · {fmtInt(a.output_tokens)} output tokens ·
        demo feature, not a study result
      </div>
    </article>
  );
}

export function AskForm({ incidentId, store }: { incidentId: string; store: AskStore }) {
  const { session } = useApp();
  const [question, setQuestion] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  if (!can(session.role, 'copilot.ask')) return <p className="muted">Your role ({session.role}) cannot ask the copilot.</p>;
  if (store.modelOffline) return <ModelOffline />;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const q = question.trim();
    if (!q || busy) return;
    setBusy(true);
    setError(null);
    try {
      const answer = await api.ask(incidentId, q);
      store.add({ id: `${Date.now()}`, incidentId, question: q, askedUtc: new Date().toISOString(), answer });
      setQuestion('');
    } catch (err) {
      const apiErr = err instanceof ApiError ? err : new ApiError(0, '/copilot/ask', String(err));
      if (apiErr.status === 503) store.setOffline();
      else setError(apiErr);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="ask-form" onSubmit={(e) => void submit(e)}>
      <div className="field">
        <label htmlFor={`ask-${incidentId}`}>Question about this incident (answered from its alerts only; citations are verified)</label>
        <input
          id={`ask-${incidentId}`}
          className="input"
          value={question}
          maxLength={2000}
          onChange={(e) => setQuestion(e.target.value)}
          aria-describedby={error ? `ask-err-${incidentId}` : undefined}
          disabled={busy}
        />
        {error && (
          <span className="field-error" id={`ask-err-${incidentId}`} role="alert">
            {describeError(error)}
          </span>
        )}
      </div>
      <Button kind="primary" type="submit" disabled={busy || question.trim().length === 0} aria-busy={busy}>
        {busy ? 'Asking...' : 'Ask'}
      </Button>
    </form>
  );
}
