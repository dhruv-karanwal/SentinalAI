// Sign in (DESIGN.md 5): brand, one line about the product, the data source as quiet text, the form
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
        <div className="login-brand">
          <BrandMark size={24} />
          <span>SentinelAI</span>
        </div>
        <div className="login-head">
          <h1 id="login-title">Sign in</h1>
          <p className="login-lede">Security operations console for the AIT-ADS alert replay.</p>
          <p className="login-src" title="Alerts are replayed from the AIT-ADS dataset (dev scenarios). Nothing here is live traffic.">
            Dataset replay: demo data, no live traffic
          </p>
        </div>
        {expired && (
          <div className="notice" role="status">
            <Icon name="warning" />
            <span>Session expired. Sign in again; you will return to the page you were on.</span>
          </div>
        )}
        <form className="login-fields" onSubmit={(e) => void submit(e)} noValidate>
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
              <Button className="lg" aria-pressed={show} aria-controls="si-pass" onClick={() => setShow(!show)}>
                {show ? 'Hide' : 'Show'}
              </Button>
            </div>
            {caps && (
              <span className="login-warn" id="si-caps" role="status">
                <Icon name="warning" /> Caps Lock is on.
              </span>
            )}
            {error?.field === 'pass' && (
              <span className="field-error" id="si-err-pass" role="alert">
                {error.text}
              </span>
            )}
          </div>
          <p className="login-hint">Your role comes from your account: analyst, manager, admin or executive. The screens you see depend on it.</p>
          <Button kind="primary" className="lg" type="submit" disabled={busy}>
            {busy ? 'Signing in...' : 'Sign in'}
          </Button>
          {error?.field === 'form' && (
            <p className="field-error" role="alert">
              {error.text}
            </p>
          )}
        </form>
        <p className="login-hint">
          Accounts are created by an admin (Users) or on the API host with <span className="mono">app.main create-user</span>. The session is kept in memory and ends
          when the page is reloaded.
        </p>
      </section>
      <section className="login-art" aria-labelledby="pipe-title">
        <h2 id="pipe-title">From a replayed alert to a reviewed response</h2>
        <p className="login-art-lede">Six stages, each one a part of the code. Findings cite the alerts they come from, and a second person approves every response action.</p>
        <Pipeline />
      </section>
    </main>
  );
}

const STAGES: Array<[string, string]> = [
  ['Ingest', 'replay collector, stream (memory / Kafka)'],
  ['Normalize', 'alert normalizer, enrichment'],
  ['Detect', 'Wazuh, Suricata, AMiner; Sigma engine, triage'],
  ['Investigate', 'agent, LangGraph graph, evidence verifier'],
  ['Report', 'JSON, CSV, PDF; playbook suggestions'],
  ['Review', 'four-eyes approvals, audit log'],
];

/** Schematic of the real pipeline as a hairline flow: stage, its components, the shared stores. */
function Pipeline() {
  return (
    <div className="login-flow">
      <ol aria-label="Pipeline stages">
        {STAGES.map(([stage, comps], i) => (
          <li key={stage}>
            <span className="flow-n" aria-hidden="true">
              {i + 1}
            </span>
            <span className="flow-stage">{stage}</span>
            <span className="flow-comp">{comps}</span>
          </li>
        ))}
      </ol>
      <p className="flow-stores">
        <span className="flow-stage">Stores</span>
        <span className="flow-comp">SQLite or PostgreSQL (alerts, incidents, approvals, audit) · FTS5 or OpenSearch (search) · local files or MinIO (report files) · truth area kept separate</span>
      </p>
    </div>
  );
}
