// Notification centre: approvals waiting for this user's decision, decisions on this user's own
// requests, and failed runs. Derived from GET /approvals and GET /runs (polled every 60 s); "read"
// is remembered for this page only.

import { useEffect, useMemo, useRef, useState } from 'react';

import { api, can, type Approval, type RunRow } from '../api.ts';
import { buildHash, useApp, useLoad } from '../hooks.ts';
import { Icon } from '../icons.tsx';
import { relTime } from '../lib/format.ts';

interface Note {
  id: string;
  href: string;
  title: string;
  sub: string;
  ts: string;
}

export function notesFor(user: string, mayDecide: boolean, approvals: readonly Approval[], runs: readonly RunRow[]): Note[] {
  const out: Note[] = [];
  for (const a of approvals) {
    if (a.status === 'pending' && mayDecide && a.requested_by !== user)
      out.push({ id: `p${a.id}`, href: buildHash('/approvals', { id: String(a.id) }), title: `Approval #${a.id} waits for a decision`, sub: `${a.action.action_type} on ${a.incident_id}, requested by ${a.requested_by}`, ts: a.created_utc });
    if (a.status !== 'pending' && a.requested_by === user && a.decided_utc)
      out.push({ id: `d${a.id}:${a.status}`, href: buildHash('/approvals', { id: String(a.id) }), title: `Your request #${a.id} was ${a.status}`, sub: `by ${a.reviewer ?? 'unknown'}: ${a.reason ?? ''}`, ts: a.decided_utc });
  }
  for (const r of runs) {
    const status = String(r.status ?? '');
    if (status === 'failed' || status === 'error')
      out.push({ id: `r${r.run_id}`, href: buildHash('/study', {}), title: `Run ${r.run_id} failed`, sub: String(r.scenario ?? ''), ts: String(r.started_utc ?? '') });
  }
  return out.sort((a, b) => (a.ts < b.ts ? 1 : -1));
}

export function Notifications() {
  const { session } = useApp();
  const [tick, setTick] = useState(0);
  const [open, setOpen] = useState(false);
  const [seen, setSeen] = useState<Set<string>>(() => new Set());
  const box = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const t = window.setInterval(() => setTick((x) => x + 1), 60_000);
    return () => window.clearInterval(t);
  }, []);
  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, []);
  const approvals = useLoad((signal) => api.approvals(signal), [tick]);
  const runs = useLoad((signal) => api.runs(signal).catch(() => ({ runs: [] })), [tick]);
  const notes = useMemo(
    () => notesFor(session.username, can(session.role, 'approval.decide'), approvals.data?.approvals ?? [], runs.data?.runs ?? []),
    [session, approvals.data, runs.data],
  );
  const unseen = notes.filter((n) => !seen.has(n.id)).length;
  return (
    <div className="bell" ref={box}>
      <button
        type="button"
        className="btn ghost"
        aria-expanded={open}
        aria-controls="notes"
        aria-label={`Notifications: ${unseen} unread`}
        onClick={() => {
          setOpen(!open);
          if (!open) window.setTimeout(() => setSeen(new Set(notes.map((n) => n.id))), 1500);
        }}
        onKeyDown={(e) => e.key === 'Escape' && setOpen(false)}
      >
        <Icon name="bell" />
        {unseen > 0 && <span className="badge">{unseen}</span>}
      </button>
      {open && (
        <div className="popover" id="notes" style={{ right: 0 }} onKeyDown={(e) => e.key === 'Escape' && setOpen(false)}>
          <h2>Notifications</h2>
          {approvals.error && <div className="empty field-error">Approvals could not be loaded ({approvals.error.status || 'no answer'}).</div>}
          {notes.length === 0 && !approvals.error && <div className="empty">Nothing waiting: no pending approvals for you, no decisions on your requests, no failed runs.</div>}
          <ul>
            {notes.map((n) => (
              <li key={n.id}>
                <a href={n.href} onClick={() => setOpen(false)} style={{ flexDirection: 'column', alignItems: 'flex-start', gap: 0 }}>
                  <span style={{ fontWeight: seen.has(n.id) ? 400 : 600 }}>{n.title}</span>
                  <span className="faint">
                    {n.sub} · {relTime(n.ts)}
                  </span>
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
