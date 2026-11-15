// Users (admin): accounts and roles. Create, deactivate, reactivate and reset. Passwords never go
// through the browser: the API sets them from SENTINEL_NEW_USER_PASSWORD on its own host.

import { useState } from 'react';

import { api, ApiError, type Role } from '../api.ts';
import { Button, Dialog, EmptyState, ErrorState, Page, PageHeader, Section, SkeletonLines, Time, describeError } from '../components/ui.tsx';
import { useApp, useLoad } from '../hooks.ts';
import { Icon } from '../icons.tsx';

const ROLES: Role[] = ['analyst', 'manager', 'admin', 'executive'];

export function UsersScreen() {
  const { session, toast } = useApp();
  const { data, error, loading, reload } = useLoad((signal) => api.users(signal), []);
  const [name, setName] = useState('');
  const [role, setRole] = useState<Role>('analyst');
  const [formError, setFormError] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<{ user: string; action: 'deactivate' | 'reactivate' | 'reset' } | null>(null);
  const [busy, setBusy] = useState(false);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!/^[A-Za-z0-9_.-]{1,64}$/.test(name)) return setFormError('Use 1-64 letters, digits, dot, dash or underscore.');
    setBusy(true);
    setFormError(null);
    try {
      await api.createUser(name, role);
      toast(`Created ${name} (${role}) with the environment-supplied password.`);
      setName('');
      reload();
    } catch (err) {
      setFormError(err instanceof ApiError ? describeError(err) : String(err));
    } finally {
      setBusy(false);
    }
  };
  const act = async () => {
    if (!confirm) return;
    setBusy(true);
    try {
      await api.userAction(confirm.user, confirm.action);
      toast(`${confirm.action === 'reset' ? 'Reset the password of' : confirm.action === 'deactivate' ? 'Deactivated' : 'Reactivated'} ${confirm.user}.`);
      reload();
    } catch (err) {
      toast(err instanceof ApiError ? describeError(err) : String(err), 'error');
    } finally {
      setBusy(false);
      setConfirm(null);
    }
  };

  return (
    <Page label="Users">
      <PageHeader
        title="Users"
        purpose="Who can sign in, and with which role? Admin only; every change is written to the audit log."
        actions={
          <Button icon="refresh" onClick={reload} disabled={loading}>
            Reload
          </Button>
        }
      />

      <Section id="us-new" title="New account" description="The password comes from the API host, never from this browser.">
        <div className="form-rows">
          {data && (
            <div className="status-line" data-kind={data.password_source_set ? undefined : 'error'} role="status">
              <Icon name={data.password_source_set ? 'check' : 'warning'} />
              <span>
                Passwords for new and reset accounts come from <span className="mono">{data.password_source}</span> on the API host
                {data.password_source_set ? ' (set).' : ' (not set: create and reset will be refused until it is set, at least 8 characters).'} They are never typed or
                shown here.
              </span>
            </div>
          )}
          <form className="inline-form"onSubmit={(e) => void create(e)} noValidate>
            <div className="field">
              <label htmlFor="nu-name">Username</label>
              <input id="nu-name" className="input mono" value={name} onChange={(e) => setName(e.target.value)} aria-invalid={formError ? true : undefined} aria-describedby={formError ? 'nu-err' : 'nu-help'} />
            </div>
            <div className="field">
              <label htmlFor="nu-role">Role</label>
              <select id="nu-role" className="select" value={role} onChange={(e) => setRole(e.target.value as Role)}>
                {ROLES.map((r) => (
                  <option key={r}>{r}</option>
                ))}
              </select>
            </div>
            <Button kind="primary" type="submit" disabled={busy}>
              Create account
            </Button>
            {formError ? (
              <span className="field-error" id="nu-err" role="alert">
                {formError}
              </span>
            ) : (
              <span className="form-help" id="nu-help">
                1-64 letters, digits, dot, dash or underscore.
              </span>
            )}
          </form>
        </div>
      </Section>

      <Section id="us-list" title="Accounts" description={data ? `${data.users.length} account${data.users.length === 1 ? '' : 's'}.` : undefined}>
        {error && !data ? (
          <ErrorState what="users" error={error} onRetry={reload} />
        ) : !data ? (
          <SkeletonLines />
        ) : data.users.length === 0 ? (
          <EmptyState title="No accounts">Create one above or with app.main create-user on the API host.</EmptyState>
        ) : (
          <div className="card table-scroll">
            <table className="plain-table">
              <caption className="visually-hidden">Accounts</caption>
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Role</th>
                  <th>State</th>
                  <th>Created (UTC)</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.users.map((u) => {
                  const self = u.username === session.username;
                  return (
                    <tr key={u.username}>
                      <td className="mono nowrap">{u.username}</td>
                      <td className="nowrap">{u.role}</td>
                      <td>
                        <span className="tag" data-tone={u.disabled_utc ? 'rejected' : 'approved'}>
                          {u.disabled_utc ? 'deactivated' : 'active'}
                        </span>
                      </td>
                      <td className="nowrap">
                        <Time ts={u.created_utc} />
                      </td>
                      <td className="nowrap">
                        {self ? (
                          <span className="faint">your account</span>
                        ) : (
                          <div className="btn-row">
                            <Button onClick={() => setConfirm({ user: u.username, action: u.disabled_utc ? 'reactivate' : 'deactivate' })}>{u.disabled_utc ? 'Reactivate' : 'Deactivate'}</Button>
                            <Button onClick={() => setConfirm({ user: u.username, action: 'reset' })}>Reset password</Button>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      {confirm && (
        <Dialog
          title={`${confirm.action === 'reset' ? 'Reset password' : confirm.action === 'deactivate' ? 'Deactivate' : 'Reactivate'}: ${confirm.user}`}
          onClose={() => setConfirm(null)}
          footer={
            <>
              <Button onClick={() => setConfirm(null)}>Cancel</Button>
              <Button kind={confirm.action === 'deactivate' ? 'danger' : 'primary'} onClick={() => void act()} disabled={busy}>
                Confirm
              </Button>
            </>
          }
        >
          <p>
            {confirm.action === 'deactivate'
              ? 'The account can no longer sign in, and its current session token stops working on the next request.'
              : confirm.action === 'reactivate'
                ? 'The account can sign in again with its current password.'
                : 'The password is replaced with the value of SENTINEL_NEW_USER_PASSWORD on the API host. Tell the user out of band.'}
          </p>
        </Dialog>
      )}
    </Page>
  );
}
