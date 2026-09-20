import { useEffect, useState, type FormEvent } from 'react'
import { api, errorMessage } from '../../api/client'
import { fmtTime } from '../../api/format'
import type { Group, GroupMember, Role, User } from '../../api/types'
import { useAuth } from '../../auth/AuthContext'
import { Alert, Badge, Confirm, Empty, Field, Modal, PageHead } from '../../components/ui'
import { useList } from './lib'

const roles: Role[] = ['admin', 'auditor', 'user']

export function UsersGroups() {
  const [tab, setTab] = useState<'users' | 'groups'>('users')
  return (
    <>
      <PageHead title="Users & groups" lead="People sign in to Zanskar as users; policies grant access to groups. Roles: admin configures, auditor reviews, user connects." />
      <div className="tabs">
        <button className={tab === 'users' ? 'active' : ''} onClick={() => setTab('users')}>Users</button>
        <button className={tab === 'groups' ? 'active' : ''} onClick={() => setTab('groups')}>Groups</button>
      </div>
      {tab === 'users' ? <Users /> : <Groups />}
    </>
  )
}

type UserAction = 'roles' | 'password' | 'sessions' | 'mfa' | 'status' | 'delete'

function Users() {
  const me = useAuth().user
  const { items, err, setErr, reload } = useList<User>('/users')
  const [adding, setAdding] = useState(false)
  const [action, setAction] = useState<{ u: User; a: UserAction } | null>(null)
  const [notice, setNotice] = useState('')

  return (
    <>
      {err && <Alert tone="danger">{err}</Alert>}
      {notice && <Alert tone="ok">{notice}</Alert>}
      <div className="actions" style={{ marginBottom: 12 }}>
        <button className="btn primary" onClick={() => setAdding(true)}>Add user</button>
      </div>
      <div className="card table-wrap">
        {items === null ? (
          <Empty>Loading…</Empty>
        ) : items.length === 0 ? (
          <Empty>No users.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Username</th>
                <th>Name</th>
                <th>Roles</th>
                <th>Status</th>
                <th>Last login</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {items.map((u) => {
                const self = u.id === me?.id
                return (
                  <tr key={u.id}>
                    <td className="mono">{u.username}{self && <span className="muted"> (you)</span>}</td>
                    <td>
                      {u.display_name}
                      {u.email && <div className="muted">{u.email}</div>}
                    </td>
                    <td>{u.roles.map((r) => <Badge key={r} tone={r === 'admin' ? 'accent' : undefined}>{r}</Badge>)}</td>
                    <td>{u.status === 'active' ? <Badge tone="ok">active</Badge> : <Badge tone="warn">{u.status}</Badge>}</td>
                    <td className="muted">{u.last_login_at ? fmtTime(u.last_login_at) : 'never'}</td>
                    <td>
                      <select id={`u-action-${u.id}`} value="" onChange={(e) => e.target.value && setAction({ u, a: e.target.value as UserAction })} aria-label={`actions for ${u.username}`}>
                        <option value="">Actions…</option>
                        <option value="roles">Edit roles</option>
                        <option value="password">Reset password</option>
                        <option value="sessions">Revoke sessions</option>
                        <option value="mfa">Reset authenticator</option>
                        {!self && <option value="status">{u.status === 'active' ? 'Disable' : 'Enable'}</option>}
                        {!self && <option value="delete">Delete</option>}
                      </select>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
      {adding && (
        <UserForm
          onClose={() => setAdding(false)}
          onSaved={() => {
            setAdding(false)
            void reload()
          }}
        />
      )}
      {action?.a === 'roles' && (
        <RolesForm
          user={action.u}
          onClose={() => setAction(null)}
          onSaved={() => {
            setAction(null)
            void reload()
          }}
        />
      )}
      {action?.a === 'password' && (
        <PasswordForm
          user={action.u}
          onClose={() => setAction(null)}
          onSaved={() => {
            setAction(null)
            setNotice(`Password for ${action.u.username} replaced; their sessions were signed out.`)
          }}
        />
      )}
      {action?.a === 'sessions' && (
        <Confirm
          title={`Sign ${action.u.username} out everywhere?`}
          body="Every browser session for this account ends now. Live terminal sessions continue until they end on their own or are terminated."
          confirmLabel="Revoke sessions"
          onClose={() => setAction(null)}
          onConfirm={async () => {
            const r = await api.del<{ sessions_revoked: number }>(`/users/${action.u.id}/sessions`)
            setNotice(`Revoked ${r?.sessions_revoked ?? 0} session(s) for ${action.u.username}.`)
          }}
        />
      )}
      {action?.a === 'mfa' && (
        <Confirm
          title={`Reset ${action.u.username}'s authenticator?`}
          body="Their TOTP secret and recovery codes are deleted and their sessions signed out. They will enroll a new authenticator at next sign-in."
          confirmLabel="Reset authenticator"
          danger
          onClose={() => setAction(null)}
          onConfirm={async () => {
            await api.del(`/users/${action.u.id}/mfa`)
            setNotice(`Authenticator reset for ${action.u.username}.`)
          }}
        />
      )}
      {action?.a === 'status' && (
        <Confirm
          title={`${action.u.status === 'active' ? 'Disable' : 'Enable'} ${action.u.username}?`}
          body={action.u.status === 'active' ? 'They are signed out and cannot sign in until re-enabled.' : 'They can sign in again.'}
          confirmLabel={action.u.status === 'active' ? 'Disable' : 'Enable'}
          danger={action.u.status === 'active'}
          onClose={() => setAction(null)}
          onConfirm={async () => {
            try {
              await api.put(`/users/${action.u.id}`, { display_name: action.u.display_name, email: action.u.email ?? '', status: action.u.status === 'active' ? 'disabled' : 'active' })
              void reload()
            } catch (e) {
              setErr(errorMessage(e))
              throw e
            }
          }}
        />
      )}
      {action?.a === 'delete' && (
        <Confirm
          title={`Delete ${action.u.username}?`}
          body="The account is removed. Audit entries keep the user id so history stays intact."
          confirmLabel="Delete"
          danger
          onClose={() => setAction(null)}
          onConfirm={async () => {
            try {
              await api.del(`/users/${action.u.id}`)
              void reload()
            } catch (e) {
              setErr(errorMessage(e))
              throw e
            }
          }}
        />
      )}
    </>
  )
}

function RoleChecks({ value, onChange, prefix }: { value: Role[]; onChange: (r: Role[]) => void; prefix: string }) {
  return (
    <Field label="Roles">
      <div className="actions">
        {roles.map((r) => (
          <span key={r} className="field inline" style={{ margin: 0 }}>
            <input id={`${prefix}-role-${r}`} type="checkbox" checked={value.includes(r)} onChange={(e) => onChange(e.target.checked ? [...value, r] : value.filter((x) => x !== r))} />
            <label htmlFor={`${prefix}-role-${r}`}>{r}</label>
          </span>
        ))}
      </div>
    </Field>
  )
}

function UserForm({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [f, setF] = useState({ username: '', display_name: '', email: '', password: '' })
  const [r, setR] = useState<Role[]>(['user'])
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value })
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      const body: Record<string, unknown> = { username: f.username.trim(), display_name: f.display_name.trim(), email: f.email.trim(), roles: r }
      if (f.password) body.password = f.password
      await api.post('/users', body)
      onSaved()
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal title="Add user" onClose={onClose}>
      {err && <Alert tone="danger">{err}</Alert>}
      <form onSubmit={submit}>
        <Field label="Username" hint="2-64 characters: letters, digits, . _ -"><input id="nu-username" value={f.username} onChange={set('username')} required autoFocus /></Field>
        <Field label="Display name"><input id="nu-name" value={f.display_name} onChange={set('display_name')} required /></Field>
        <Field label="Email (optional)"><input id="nu-email" type="email" value={f.email} onChange={set('email')} /></Field>
        <Field label="Initial password" hint="At least 12 characters. Leave blank for accounts that sign in through an identity provider. Shown nowhere after this."><input id="nu-password" type="password" autoComplete="new-password" value={f.password} onChange={set('password')} /></Field>
        <RoleChecks value={r} onChange={setR} prefix="nu" />
        <div className="actions">
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button className="btn primary" disabled={busy}>Create</button>
        </div>
      </form>
    </Modal>
  )
}

function RolesForm({ user, onClose, onSaved }: { user: User; onClose: () => void; onSaved: () => void }) {
  const [r, setR] = useState<Role[]>(user.roles)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  return (
    <Modal title={`Roles for ${user.username}`} onClose={onClose}>
      {err && <Alert tone="danger">{err}</Alert>}
      <form
        onSubmit={async (e) => {
          e.preventDefault()
          setBusy(true)
          setErr('')
          try {
            await api.put(`/users/${user.id}/roles`, { roles: r })
            onSaved()
          } catch (e2) {
            setErr(errorMessage(e2))
          } finally {
            setBusy(false)
          }
        }}
      >
        <RoleChecks value={r} onChange={setR} prefix={`er-${user.id}`} />
        <p className="muted">Granting admin or auditor is recorded in the audit log.</p>
        <div className="actions">
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button className="btn primary" disabled={busy}>Save</button>
        </div>
      </form>
    </Modal>
  )
}

function PasswordForm({ user, onClose, onSaved }: { user: User; onClose: () => void; onSaved: () => void }) {
  const [pw, setPw] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  return (
    <Modal title={`Reset password for ${user.username}`} onClose={onClose}>
      {err && <Alert tone="danger">{err}</Alert>}
      <form
        onSubmit={async (e) => {
          e.preventDefault()
          setBusy(true)
          setErr('')
          try {
            await api.put(`/users/${user.id}/password`, { password: pw })
            onSaved()
          } catch (e2) {
            setErr(errorMessage(e2))
          } finally {
            setBusy(false)
          }
        }}
      >
        <Field label="New password" hint="At least 12 characters. Their existing sessions are signed out."><input id={`pw-${user.id}`} type="password" autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} required autoFocus /></Field>
        <div className="actions">
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button className="btn primary" disabled={busy}>Set password</button>
        </div>
      </form>
    </Modal>
  )
}

function Groups() {
  const { items, err, setErr, reload } = useList<Group>('/groups')
  const [adding, setAdding] = useState(false)
  const [members, setMembers] = useState<Group | null>(null)
  const [deleting, setDeleting] = useState<Group | null>(null)
  return (
    <>
      {err && <Alert tone="danger">{err}</Alert>}
      <div className="actions" style={{ marginBottom: 12 }}>
        <button className="btn primary" onClick={() => setAdding(true)}>Add group</button>
      </div>
      <div className="card table-wrap">
        {items === null ? (
          <Empty>Loading…</Empty>
        ) : items.length === 0 ? (
          <Empty>No groups. Policies attach to groups, so create one first.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Description</th>
                <th>Members</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {items.map((g) => (
                <tr key={g.id}>
                  <td><strong>{g.name}</strong></td>
                  <td className="muted">{g.description}</td>
                  <td>{g.member_count ?? 0}</td>
                  <td className="actions">
                    <button className="btn sm" onClick={() => setMembers(g)}>Members</button>
                    <button className="btn sm danger" onClick={() => setDeleting(g)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {adding && (
        <GroupForm
          onClose={() => setAdding(false)}
          onSaved={() => {
            setAdding(false)
            void reload()
          }}
        />
      )}
      {members && (
        <MembersForm
          group={members}
          onClose={() => setMembers(null)}
          onSaved={() => {
            setMembers(null)
            void reload()
          }}
        />
      )}
      {deleting && (
        <Confirm
          title={`Delete group ${deleting.name}?`}
          body="Policies attached to this group are deleted with it."
          confirmLabel="Delete"
          danger
          onClose={() => setDeleting(null)}
          onConfirm={async () => {
            try {
              await api.del(`/groups/${deleting.id}`)
              void reload()
            } catch (e) {
              setErr(errorMessage(e))
              throw e
            }
          }}
        />
      )}
    </>
  )
}

function GroupForm({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [f, setF] = useState({ name: '', description: '' })
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  return (
    <Modal title="Add group" onClose={onClose}>
      {err && <Alert tone="danger">{err}</Alert>}
      <form
        onSubmit={async (e) => {
          e.preventDefault()
          setBusy(true)
          setErr('')
          try {
            await api.post('/groups', { name: f.name.trim(), description: f.description })
            onSaved()
          } catch (e2) {
            setErr(errorMessage(e2))
          } finally {
            setBusy(false)
          }
        }}
      >
        <Field label="Name"><input id="g-name" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} required autoFocus /></Field>
        <Field label="Description"><input id="g-desc" value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
        <div className="actions">
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button className="btn primary" disabled={busy}>Create</button>
        </div>
      </form>
    </Modal>
  )
}

function MembersForm({ group, onClose, onSaved }: { group: Group; onClose: () => void; onSaved: () => void }) {
  const users = useList<User>('/users')
  const [selected, setSelected] = useState<string[] | null>(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    api
      .get<{ items: GroupMember[] }>(`/groups/${group.id}/members`)
      .then((r) => setSelected(r.items.map((m) => m.user_id)))
      .catch((e) => setErr(errorMessage(e)))
  }, [group.id])
  return (
    <Modal title={`Members of ${group.name}`} onClose={onClose}>
      {err && <Alert tone="danger">{err}</Alert>}
      {selected === null || users.items === null ? (
        <Empty>Loading…</Empty>
      ) : (
        <div style={{ maxHeight: 320, overflowY: 'auto' }}>
          {users.items.map((u) => (
            <div key={u.id} className="field inline" style={{ margin: '4px 0' }}>
              <input id={`m-${group.id}-${u.id}`} type="checkbox" checked={selected.includes(u.id)} onChange={(e) => setSelected(e.target.checked ? [...selected, u.id] : selected.filter((x) => x !== u.id))} />
              <label htmlFor={`m-${group.id}-${u.id}`}>
                {u.display_name} <span className="mono muted">{u.username}</span>
              </label>
            </div>
          ))}
        </div>
      )}
      <div className="actions">
        <button type="button" className="btn" onClick={onClose}>Cancel</button>
        <button
          className="btn primary"
          disabled={busy || selected === null}
          onClick={async () => {
            setBusy(true)
            setErr('')
            try {
              await api.put(`/groups/${group.id}/members`, { user_ids: selected })
              onSaved()
            } catch (e) {
              setErr(errorMessage(e))
            } finally {
              setBusy(false)
            }
          }}
        >
          Save members
        </button>
      </div>
    </Modal>
  )
}
