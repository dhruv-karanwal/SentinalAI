// Sign in (DESIGN.md 11.2): brand, one line about the product, the environment badge, the form
// (show / hide password, caps-lock warning, role hint, announced errors, session-expired banner)
// and a schematic of the real pipeline with the component names used in the code.

import { useState, type KeyboardEvent } from 'react';

import { api, ApiError, setToken, type Session } from '../api.ts';
import { Button } from '../components/ui.tsx';
import { BrandMark, Icon } from '../icons.tsx';

export function SignIn({ onSignedIn, expired }: { onSignedIn: (session: Session) => void; expired: boolean }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [show, setShow] = useState(false);
  const [caps, setCaps] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ field: 'user' | 'pass' | 'form'; text: string } | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim()) return setError({ field: 'user', text: 'Enter your username.' });
    if (!password) return setError({ field: 'pass', text: 'Enter your password.' });
    setBusy(true);
    setError(null);
    try {
      const res = await api.login(username.trim(), password);
      setToken(res.access_token);
      onSignedIn({ username: username.trim(), role: res.role });
    } catch (err) {
      const apiErr = err instanceof ApiError ? err : null;
      let text: string;
      if (apiErr?.status === 401) text = apiErr.message === 'account deactivated' ? 'This account is deactivated. Ask an admin to reactivate it.' : 'Username or password is not correct.';
      else if (apiErr?.status === 0) text = 'The API did not answer. Is `app.main serve` running on 127.0.0.1:8000?';
      else if (apiErr) text = `Sign-in failed: ${apiErr.status} ${apiErr.message}`;
      else text = String(err);
      setError({ field: 'form', text });
      setBusy(false);
    }
  };
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => setCaps(e.getModifierState?.('CapsLock') ?? false);

  return (
    <main className="login">
      <section className="login-form" aria-labelledby="login-title">
        <div className="brand" style={{ fontSize: 'var(--fs-heading)' }}>
          <BrandMark size={40} />
        </div>
        <div>
          <h1 id="login-title">SentinelAI</h1>
          <p className="lede">Security operations console for the AIT-ADS alert replay.</p>
        </div>
        <span className="env-badge" style={{ alignSelf: 'flex-start' }}>
          Dataset replay: demo data
        </span>
        {expired && (
          <div className="notice" role="status">
            <Icon name="warning" />
            <span>Session expired. Sign in again; you will return to the page you were on.</span>
          </div>
        )}
        <form onSubmit={(e) => void submit(e)} noValidate style={{ display: 'grid', gap: 'var(--sp-12)' }}>
          <div className="field">
            <label htmlFor="si-user">Username</label>
            <input
              id="si-user"
              className="input"
              autoComplete="username"
              autoFocus
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              aria-invalid={error?.field === 'user' || undefined}
              aria-describedby={error?.field === 'user' ? 'si-err-user' : undefined}
            />
            {error?.field === 'user' && (
              <span className="field-error" id="si-err-user" role="alert">
                {error.text}
              </span>
            )}
          </div>
          <div className="field">
            <label htmlFor="si-pass">Password</label>
            <div className="pw">
              <input
                id="si-pass"
                className="input"
                type={show ? 'text' : 'password'}
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={onKey}
                onKeyUp={onKey}
                onBlur={() => setCaps(false)}
                aria-invalid={error?.field === 'pass' || undefined}
                aria-describedby={[error?.field === 'pass' ? 'si-err-pass' : '', caps ? 'si-caps' : ''].filter(Boolean).join(' ') || undefined}
              />
              <Button aria-pressed={show} aria-controls="si-pass" onClick={() => setShow(!show)}>
                {show ? 'Hide' : 'Show'}
              </Button>
            </div>
            {caps && (
              <span className="warn" id="si-caps" role="status">
                <Icon name="warning" /> Caps Lock is on.
              </span>
            )}
            {error?.field === 'pass' && (
              <span className="field-error" id="si-err-pass" role="alert">
                {error.text}
              </span>
            )}
          </div>
          <p className="hint">Your role comes from your account: analyst, manager, admin or executive. The screens you see depend on it.</p>
          <Button kind="primary" type="submit" disabled={busy}>
            {busy ? 'Signing in...' : 'Sign in'}
          </Button>
          {error?.field === 'form' && (
            <p className="field-error" role="alert" style={{ margin: 0 }}>
              {error.text}
            </p>
          )}
        </form>
        <p className="hint">
          Accounts are created by an admin (Users) or on the API host with <span className="mono">app.main create-user</span>. The session is kept in memory and ends
          when the page is reloaded.
        </p>
      </section>
      <section className="login-art" aria-labelledby="pipe-title">
        <h2 id="pipe-title">How alerts move through the platform</h2>
        <Pipeline />
      </section>
    </main>
  );
}

const STAGES: Array<[string, string, string]> = [
  ['Ingest', 'replay collector', 'stream (memory / Kafka)'],
  ['Normalize', 'alert normalizer', 'enrichment'],
  ['Detect', 'Wazuh, Suricata, AMiner', 'Sigma engine, triage'],
  ['Investigate', 'agent, LangGraph graph', 'evidence verifier'],
  ['Report', 'JSON, CSV, PDF', 'playbook suggestions'],
  ['Review', 'four-eyes approvals', 'audit log'],
];

/** Schematic of the real pipeline: stage boxes, arrows, component names, the shared stores. */
function Pipeline() {
  const W = 146;
  const G = 16;
  const H = 86;
  const total = STAGES.length * W + (STAGES.length - 1) * G;
  return (
    <svg className="pipeline-svg" viewBox={`0 0 ${total + 2} 190`} width="100%" role="img" aria-labelledby="pipe-desc">
      <desc id="pipe-desc">
        {STAGES.map(([s, a, b]) => `${s}: ${a}; ${b}`).join('. ')}. All stages read and write the stores: SQLite or PostgreSQL, FTS5 or OpenSearch, local
        files or MinIO.
      </desc>
      <defs>
        <marker id="arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="8" markerHeight="8" orient="auto">
          <path d="M0 0 8 4 0 8z" fill="var(--text-faint)" />
        </marker>
      </defs>
      {STAGES.map(([stage, a, b], i) => {
        const x = 1 + i * (W + G);
        return (
          <g key={stage}>
            <rect x={x} y={1} width={W} height={H} rx={4} fill="var(--surface)" stroke="var(--border-strong)" />
            <text x={x + 10} y={20} className="num-label">
              {i + 1}
            </text>
            <text x={x + 10} y={40} className="stage">
              {stage}
            </text>
            <text x={x + 10} y={60} className="comp">
              {a}
            </text>
            <text x={x + 10} y={76} className="comp">
              {b}
            </text>
            {i < STAGES.length - 1 && <line x1={x + W + 2} y1={H / 2} x2={x + W + G - 3} y2={H / 2} stroke="var(--text-faint)" strokeWidth={1.5} markerEnd="url(#arrow)" />}
            <line x1={x + W / 2} y1={H + 1} x2={x + W / 2} y2={128} stroke="var(--border-strong)" strokeDasharray="2 3" />
          </g>
        );
      })}
      <rect x={1} y={128} width={total} height={40} rx={4} fill="none" stroke="var(--border-strong)" />
      <text x={12} y={146} className="stage" style={{ fontSize: 12 }}>
        Stores
      </text>
      <text x={12} y={161} className="comp">
        SQLite or PostgreSQL (alerts, incidents, approvals, audit) · FTS5 or OpenSearch (search) · local files or MinIO (report files) · truth area kept separate
      </text>
    </svg>
  );
}
