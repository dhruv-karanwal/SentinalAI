// Help chat: a launcher at the bottom right of every screen and a small panel above it.
// It answers "what is this term / chart / finding?" from the glossary and the current screen:
// - with the local model: POST /copilot/ask in explain mode (same route and model as the copilot,
//   one request at a time, at most ~300 output tokens; the API refuses a second concurrent one);
// - without it (no endpoint, Ollama unreachable, role without copilot.ask, model busy): a
//   deterministic glossary search, labelled "Local model offline: showing glossary answers only".
// It never guesses beyond the glossary and the screen; answers are text nodes only. Esc closes
// and returns focus to the launcher. Nothing leaves the machine: the API and model are local.

import { useEffect, useRef, useState } from 'react';

import { api, ApiError, can } from '../api.ts';
import { SUGGESTED } from '../content/about.ts';
import { getScreenContext, useApp } from '../hooks.ts';
import { Icon } from '../icons.tsx';
import { glossaryAnswer, searchGlossary } from '../lib/explain.ts';

interface Msg {
  id: number;
  who: 'you' | 'help';
  text: string;
  /** who answered: the model id, or 'glossary' */
  by?: string;
  terms?: string[];
  note?: string;
}

type ModelState = 'unknown' | 'online' | 'offline' | 'not-allowed';

/** after an offline answer, the model is asked again only after this long */
const RETRY_MS = 60_000;

export function HelpChat({ path, screenName, incidentId }: { path: string; screenName: string; incidentId: string | null }) {
  const { session } = useApp();
  const allowed = can(session.role, 'copilot.ask');
  const [open, setOpen] = useState(false);
  const [msgs, setMsgs] = useState<Msg[]>([]);
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [model, setModel] = useState<ModelState>(allowed ? 'unknown' : 'not-allowed');
  const offlineAt = useRef(0);
  const launcher = useRef<HTMLButtonElement | null>(null);
  const input = useRef<HTMLTextAreaElement | null>(null);
  const log = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (open) input.current?.focus();
  }, [open]);
  useEffect(() => {
    log.current?.scrollTo({ top: log.current.scrollHeight });
  }, [msgs]);

  const close = () => {
    setOpen(false);
    launcher.current?.focus();
  };

  const ask = async (raw: string) => {
    const question = raw.trim().slice(0, 500);
    if (!question || busy) return;
    setText('');
    const id = Date.now();
    setMsgs((m) => [...m, { id, who: 'you', text: question }]);
    const terms = searchGlossary(question, undefined, 4);
    const fallback = (note: string) => {
      const g = glossaryAnswer(question);
      setMsgs((m) => [...m, { id: id + 1, who: 'help', text: g.text, by: 'glossary', terms: g.terms.map((t) => t.term), note }]);
    };
    if (!allowed) return fallback('Your role cannot ask the local model; showing glossary answers only.');
    if (model === 'offline' && Date.now() - offlineAt.current < RETRY_MS) return fallback('Local model offline: showing glossary answers only.');
    setBusy(true);
    try {
      const r = await api.explain({
        question,
        screen: screenName,
        context: getScreenContext(),
        incident_id: incidentId,
        glossary: terms.map((t) => ({ term: t.term, definition: t.definition, why: t.why })),
      });
      setModel('online');
      setMsgs((m) => [...m, { id: id + 1, who: 'help', text: r.answer.join(' ').trim() || '(empty answer)', by: r.model, terms: terms.map((t) => t.term) }]);
    } catch (err) {
      const status = err instanceof ApiError ? err.status : 0;
      if (status === 429) fallback('The local model is busy with another request; showing the glossary answer instead.');
      else if (status === 503 || status === 0 || status === 502 || status === 504) {
        setModel('offline');
        offlineAt.current = Date.now();
        fallback('Local model offline: showing glossary answers only.');
      } else fallback(`The help request failed (${status || 'no answer'}${err instanceof Error ? `: ${err.message}` : ''}); showing the glossary answer.`);
    } finally {
      setBusy(false);
    }
  };

  const suggestions = SUGGESTED[path] ?? SUGGESTED['/about']!;
  const status =
    model === 'online' ? 'Local model online' : model === 'offline' ? 'Local model offline: showing glossary answers only' : model === 'not-allowed' ? 'Glossary answers only (your role cannot ask the model)' : 'Local model: not asked yet';

  return (
    <>
      <button
        ref={launcher}
        type="button"
        className="chat-launcher"
        aria-expanded={open}
        aria-controls="help-chat"
        onClick={() => (open ? close() : setOpen(true))}
        title="Ask what a term, chart or finding means"
      >
        <Icon name="chat" />
        <span>Explain</span>
      </button>
      {open && (
        <div
          id="help-chat"
          className="chat"
          role="dialog"
          aria-modal="false"
          aria-labelledby="help-chat-t"
          onKeyDown={(e) => {
            if (e.key === 'Escape') {
              close();
              e.stopPropagation();
              e.preventDefault();
            }
          }}
        >
          <div className="chat-head">
            <h2 id="help-chat-t">Explain this screen</h2>
            <span className="faint chat-where">{screenName}{incidentId ? ` · ${incidentId}` : ''}</span>
            <span className="spacer" />
            <button type="button" className="icon-btn" onClick={close} aria-label="Close the help chat (Esc)">
              <Icon name="close" />
            </button>
          </div>
          <div className="chat-status" data-state={model} role="status">
            {status}
          </div>
          <div className="chat-log" ref={log} aria-live="polite">
            {msgs.length === 0 && (
              <p className="faint chat-intro">
                Answers come only from the glossary and what this screen shows. If neither has the answer, it says so instead of guessing. Everything stays on this machine.
              </p>
            )}
            {msgs.map((m) => (
              <div key={m.id} className="chat-msg" data-who={m.who}>
                <div className="chat-who">{m.who === 'you' ? 'You' : 'Help'}</div>
                <div className="chat-text">{m.text}</div>
                {m.who === 'help' && (
                  <div className="chat-by">
                    {m.by === 'glossary' ? 'answered from the glossary (no model)' : `answered by local model ${m.by}`}
                    {m.terms && m.terms.length > 0 && <> · glossary: {m.terms.join(', ')}</>}
                  </div>
                )}
                {m.note && <div className="chat-note">{m.note}</div>}
              </div>
            ))}
            {busy && (
              <div className="chat-msg" data-who="help" aria-busy="true">
                <div className="chat-who">Help</div>
                <div className="chat-text faint">Asking the local model (one short answer)...</div>
              </div>
            )}
          </div>
          <div className="chat-suggest" aria-label="Suggested questions">
            {suggestions.map((s) => (
              <button key={s} type="button" className="chip" onClick={() => void ask(s)} disabled={busy}>
                {s}
              </button>
            ))}
          </div>
          <form
            className="chat-form"
            onSubmit={(e) => {
              e.preventDefault();
              void ask(text);
            }}
          >
            <label htmlFor="help-q" className="visually-hidden">
              Your question
            </label>
            <textarea
              id="help-q"
              ref={input}
              className="input"
              rows={2}
              maxLength={500}
              placeholder="What does this chart show?"
              value={text}
              onChange={(e) => setText(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  void ask(text);
                }
              }}
            />
            <button type="submit" className="btn primary" disabled={busy || !text.trim()} aria-label="Send question">
              <Icon name="send" />
            </button>
          </form>
        </div>
      )}
    </>
  );
}
