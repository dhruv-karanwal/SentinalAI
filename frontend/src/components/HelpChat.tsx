// Floating help chat (DESIGN.md 8): a round button fixed bottom right on every screen (above the
// tour and toasts) with a status dot (green: local model reachable; amber: busy; grey: glossary
// only), and a floating panel (bottom sheet on phone widths).
// - Model status: GET /copilot/status, a probe that lists models and never generates, so the dot is
//   honest without loading the GPU. Polled on mount, on open and every 60 s while the tab is visible.
// - Answers: POST /copilot/ask in explain mode (one request at a time, <= 300 output tokens); on
//   503 / unreachable / 429 / no permission, a deterministic glossary answer with the reason.
// - Keyboard: Esc closes, Tab is trapped inside the panel, focus returns to the button on close.
// - Open state and history are kept per browser session (sessionStorage, try/catch).
// Answers are text nodes only. Nothing leaves the machine: the API and model are local.

import { useCallback, useEffect, useReducer, useRef, useState } from 'react';

import { api, ApiError, can } from '../api.ts';
import { getScreenContext, useApp } from '../hooks.ts';
import { Icon } from '../icons.tsx';
import { chatReducer, errorNote, loadChat, nextFocus, saveChat, sessionStore, suggestionsFor, type ChatMsg } from '../lib/chat.ts';
import { glossaryAnswer, searchGlossary } from '../lib/explain.ts';
import { prefersReducedMotion } from '../lib/motion.ts';

type ModelState = 'unknown' | 'online' | 'offline' | 'busy' | 'not-allowed';

const POLL_MS = 60_000;
const OPEN_EVENT = 'sentinel:chat-open';

/** Opens the help chat from anywhere (command palette). */
export function openHelpChat(): void {
  window.dispatchEvent(new Event(OPEN_EVENT));
}
const FOCUSABLE = 'button:not([disabled]), textarea:not([disabled]), input:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])';

export function HelpChat({ path, screenName, incidentId }: { path: string; screenName: string; incidentId: string | null }) {
  const { session } = useApp();
  const allowed = can(session.role, 'copilot.ask');
  const [state, dispatch] = useReducer(chatReducer, undefined, () => loadChat(sessionStore()));
  const [closing, setClosing] = useState(false);
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [model, setModel] = useState<ModelState>(allowed ? 'unknown' : 'not-allowed');
  const [modelId, setModelId] = useState<string | null>(null);
  const [unread, setUnread] = useState(0);
  const [copied, setCopied] = useState<number | null>(null);
  const fab = useRef<HTMLButtonElement | null>(null);
  const panel = useRef<HTMLDivElement | null>(null);
  const input = useRef<HTMLTextAreaElement | null>(null);
  const log = useRef<HTMLDivElement | null>(null);

  useEffect(() => saveChat(sessionStore(), state), [state]);

  const probe = useCallback(async () => {
    if (!allowed) return;
    try {
      const r = await api.copilotStatus();
      setModel(r.state);
      setModelId(r.model);
    } catch {
      setModel('offline');
    }
  }, [allowed]);

  useEffect(() => {
    void probe();
    const t = window.setInterval(() => document.visibilityState === 'visible' && void probe(), POLL_MS);
    return () => window.clearInterval(t);
  }, [probe]);

  useEffect(() => {
    if (state.open && !state.minimised) {
      input.current?.focus();
      setUnread(0);
    }
  }, [state.open, state.minimised]);
  useEffect(() => {
    if (state.returnFocus) {
      fab.current?.focus();
      dispatch({ type: 'focused' });
    }
  }, [state.returnFocus]);
  useEffect(() => {
    log.current?.scrollTo({ top: log.current.scrollHeight, behavior: prefersReducedMotion() ? 'auto' : 'smooth' });
  }, [state.msgs, busy]);

  const open = useCallback(() => {
    dispatch({ type: 'open' });
    void probe();
  }, [probe]);
  // the command palette's "Open help chat" action
  useEffect(() => {
    window.addEventListener(OPEN_EVENT, open);
    return () => window.removeEventListener(OPEN_EVENT, open);
  }, [open]);
  const close = () => {
    if (prefersReducedMotion()) return dispatch({ type: 'close' });
    setClosing(true);
    window.setTimeout(() => {
      setClosing(false);
      dispatch({ type: 'close' });
    }, 140);
  };

  const push = (msg: ChatMsg) => {
    dispatch({ type: 'push', msg });
    if (msg.who === 'help' && (!state.open || state.minimised)) setUnread((n) => n + 1);
  };

  const ask = async (raw: string) => {
    const question = raw.trim().slice(0, 500);
    if (!question || busy) return;
    setText('');
    const id = Date.now();
    push({ id, who: 'you', text: question });
    const terms = searchGlossary(question, undefined, 4);
    const fallback = (note: string) => {
      const g = glossaryAnswer(question);
      push({ id: id + 1, who: 'help', text: g.text, by: 'glossary', terms: g.terms.map((t) => t.term), note });
    };
    if (!allowed) return fallback('Your role cannot ask the local model; showing glossary answers only.');
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
      setModelId(r.model);
      push({ id: id + 1, who: 'help', text: r.answer.join(' ').trim() || '(empty answer)', by: r.model, terms: terms.map((t) => t.term) });
    } catch (err) {
      const status = err instanceof ApiError ? err.status : 0;
      const n = errorNote(status, err instanceof Error ? err.message : '');
      if (status === 429) setModel('busy');
      else if (n.offline) setModel('offline');
      fallback(n.note);
    } finally {
      setBusy(false);
    }
  };

  const copy = async (m: ChatMsg) => {
    try {
      await navigator.clipboard.writeText(m.text);
      setCopied(m.id);
      window.setTimeout(() => setCopied((c) => (c === m.id ? null : c)), 1500);
    } catch {
      // clipboard blocked: nothing to do, the text stays selectable
    }
  };

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.stopPropagation();
      e.preventDefault();
      close();
      return;
    }
    if (e.key !== 'Tab' || !panel.current) return;
    const items = Array.from(panel.current.querySelectorAll<HTMLElement>(FOCUSABLE));
    const idx = nextFocus(items.length, items.indexOf(document.activeElement as HTMLElement), e.shiftKey);
    if (idx !== null) {
      e.preventDefault();
      items[idx]?.focus();
    }
  };

  const suggestions = suggestionsFor(path);
  const dot = model === 'online' ? 'online' : model === 'busy' ? 'busy' : 'offline';
  const status =
    model === 'online'
      ? `Local model online${modelId ? `: ${modelId}` : ''}`
      : model === 'busy'
        ? 'Local model busy: answers may come from the glossary'
        : model === 'not-allowed'
          ? 'Glossary only (your role cannot ask the model)'
          : model === 'unknown'
            ? 'Checking the local model...'
            : 'Local model offline: glossary answers only';

  return (
    <>
      <button
        ref={fab}
        type="button"
        className="fab no-print"
        aria-expanded={state.open}
        aria-controls="help-chat"
        aria-label={`${state.open ? 'Close' : 'Open'} the help chat. ${status}${unread ? `. ${unread} new answer${unread === 1 ? '' : 's'}` : ''}`}
        title={`Ask what a term, chart or finding means (${status})`}
        onClick={() => (state.open ? close() : open())}
      >
        <Icon name="chat" />
        <span className="fab-dot" data-state={dot} aria-hidden="true" />
        {unread > 0 && (
          <span className="fab-badge" aria-hidden="true">
            {unread}
          </span>
        )}
      </button>
      {state.open && (
        <div
          id="help-chat"
          ref={panel}
          className="fab-panel no-print"
          role="dialog"
          aria-modal="false"
          aria-labelledby="help-chat-t"
          data-wide={state.wide ? '' : undefined}
          data-min={state.minimised ? '' : undefined}
          data-closing={closing ? '' : undefined}
          onKeyDown={onKey}
        >
          <div className="fab-head">
            <div className="fab-title">
              <h2 id="help-chat-t">Explain this screen</h2>
              <span className="fab-status" data-state={dot} role="status">
                <i aria-hidden="true" />
                {status}
              </span>
            </div>
            <span className="spacer" />
            <button type="button" className="btn ghost icon-only" onClick={() => dispatch({ type: 'clear' })} aria-label="Clear the conversation" title="Clear" disabled={state.msgs.length === 0}>
              <Icon name="trash" />
            </button>
            <button type="button" className="btn ghost icon-only" onClick={() => dispatch({ type: 'wide' })} aria-label={state.wide ? 'Make the panel smaller' : 'Make the panel larger'} aria-pressed={state.wide} title="Resize">
              <Icon name="expand" />
            </button>
            <button type="button" className="btn ghost icon-only" onClick={() => dispatch({ type: 'minimise' })} aria-label={state.minimised ? 'Restore the panel' : 'Minimise the panel'} aria-pressed={state.minimised} title="Minimise">
              <Icon name="minimise" />
            </button>
            <button type="button" className="btn ghost icon-only" onClick={close} aria-label="Close the help chat (Esc)" title="Close (Esc)">
              <Icon name="close" />
            </button>
          </div>
          {!state.minimised && (
            <>
              <div className="fab-log" ref={log} aria-live="polite">
                <p className="fab-intro">
                  On <strong>{screenName}</strong>
                  {incidentId ? ` · ${incidentId}` : ''}. Answers come only from the glossary and what this screen shows; if neither has the answer it says so. Everything stays on this machine.
                </p>
                {state.msgs.map((m) => (
                  <div key={m.id} className="fab-msg" data-who={m.who}>
                    <div className="fab-text">{m.text}</div>
                    {m.who === 'help' && (
                      <div className="fab-meta">
                        <span>
                          {m.by === 'glossary' ? 'from the glossary (no model)' : `local model ${m.by}`}
                          {m.terms && m.terms.length > 0 && <> · {m.terms.join(', ')}</>}
                        </span>
                        <span className="spacer" />
                        <button type="button" className="btn ghost icon-only" onClick={() => void copy(m)} aria-label="Copy this answer" title="Copy">
                          <Icon name={copied === m.id ? 'check' : 'copy'} />
                        </button>
                      </div>
                    )}
                    {m.note && <div className="fab-note">{m.note}</div>}
                  </div>
                ))}
                {busy && (
                  <div className="fab-msg" data-who="help" aria-busy="true" aria-label="The local model is answering">
                    <span className="fab-typing">Answering...</span>
                  </div>
                )}
              </div>
              <div className="fab-suggest" aria-label="Suggested questions">
                {suggestions.map((s) => (
                  <button key={s} type="button" className="chip" onClick={() => void ask(s)} disabled={busy}>
                    {s}
                  </button>
                ))}
              </div>
              <form
                className="fab-form"
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
            </>
          )}
        </div>
      )}
    </>
  );
}
