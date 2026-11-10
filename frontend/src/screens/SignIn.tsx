import { useState } from 'react';

import { api, ApiError, setToken, type Session } from '../api.ts';
import { Button, describeError } from '../components/ui.tsx';

export function SignIn({ onSignedIn, expired }: { onSignedIn: (session: Session) => void; expired: boolean }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setError('Enter a username and a password.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const res = await api.login(username.trim(), password);
      setToken(res.access_token);
      onSignedIn({ username: username.trim(), role: res.role });
    } catch (err) {
      const apiErr = err instanceof ApiError ? err : null;
      setError(apiErr?.status === 401 ? 'Username or password is not correct.' : apiErr ? describeError(apiErr) : String(err));
      setBusy(false);
    }
  };

  return (
    <main className="signin">
      <h1>SentinelAI console</h1>
      {expired && (
        <p className="muted" role="status">
          Session expired. Sign in again.
        </p>
      )}
      <form onSubmit={(e) => void submit(e)} style={{ display: 'flex', flexDirection: 'column', gap: 12 }} noValidate>
        <div className="field">
          <label htmlFor="si-user">Username</label>
          <input id="si-user" className="input" autoComplete="username" autoFocus value={username} onChange={(e) => setUsername(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="si-pass">Password</label>
          <input
            id="si-pass"
            className="input"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            aria-describedby={error ? 'si-err' : undefined}
            aria-invalid={error ? true : undefined}
          />
          {error && (
            <span className="field-error" id="si-err" role="alert">
              {error}
            </span>
          )}
        </div>
        <Button kind="primary" type="submit" disabled={busy}>
          {busy ? 'Signing in...' : 'Sign in'}
        </Button>
      </form>
      <p className="faint" style={{ fontSize: 'var(--fs-12)' }}>
        Accounts are created on the API host with <span className="mono">app.main create-user</span>. The session is kept in memory and ends when the page is
        reloaded.
      </p>
    </main>
  );
}
