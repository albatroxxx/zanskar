import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, errorMessage } from '../../api/client'
import { fmtTime } from '../../api/format'
import { capitalised, stateLabel } from '../../api/states'
import type { Group, GroupMember, Role, User } from '../../api/types'
import { useAuth } from '../../auth/AuthContext'
import { FilterChips } from '../../components/FilterChips'
import { PickList } from '../../components/PickList'
import { RolePicker } from '../../components/RolePicker'
import { normalizeRoles } from '../../api/roles'
import { useSubmit } from '../../components/submit'
import { Alert, Badge, Confirm, Empty, Field, FormModal, Loading, Modal, PageHead, Tabs } from '../../components/ui'
import { useDebounced, useList } from './lib'
import { StateIcon } from '../../components/icons'


export function UsersGroups() {
  const [tab, setTab] = useState<'users' | 'groups'>('users')
  // The page's one action sits at its top right, as on every other page;
  // it sat under the tabs (live, 2026-11-11). It adds to the tab shown.
  const [adding, setAdding] = useState(false)
  const switchTab = (t: 'users' | 'groups') => {
    setAdding(false)
    setTab(t)
  }
  return (
    <>
      <PageHead title="Users & groups">
        <button className="btn primary" onClick={() => setAdding(true)}>{tab === 'users' ? 'Add user' : 'Add group'}</button>
      </PageHead>
      <Tabs label="Users and groups" value={tab} onChange={switchTab} tabs={[{ key: 'users', label: 'Users' }, { key: 'groups', label: 'Groups' }]} />
      {tab === 'users' ? <Users adding={adding} setAdding={setAdding} /> : <Groups adding={adding} setAdding={setAdding} />}
    </>
  )
}

/** Adding is the page's: its Add button opens the tab's form. */
interface AddingProps { adding: boolean; setAdding: (open: boolean) => void }

type UserAction = 'roles' | 'password' | 'sessions' | 'mfa' | 'status' | 'delete'

type Providers = Map<string, { name: string; type: string; holds: boolean }>

/** useProviders names the identity providers by id, for the Source column,
 *  and says which still decide who their people are: enabled, and listing
 *  them or having them pushed (idp.Repo.Holds on the server). */
function useProviders(): Providers {
  const { items } = useList<{ id: string; name: string; type: string; enabled?: boolean; config?: { sync_users?: boolean; scim?: boolean } }>('/identity-providers')
  return new Map((items ?? []).map((p) => [p.id, { name: p.name, type: p.type, holds: !!p.enabled && !!(p.config?.sync_users || p.config?.scim) }]))
}

/** tookAway names the provider that disabled an account because its person
 *  left, while that provider still decides (2026-10-31): the account comes
 *  back when the person does, and is not an administrator's to enable. */
function tookAway(u: User, providers: Providers): string | undefined {
  if (!u.directory_removed_at || !u.idp_id) return undefined
  const p = providers.get(u.idp_id)
  return p?.holds ? p.name : undefined
}

/**
 * Source says where an account or a group comes from (2026-10-31: the list
 * did not tell an identity provider's people from Zanskar's own): the
 * provider by name, outlined so it never reads as a role; "Single sign-on"
 * for an account made here to sign in through a provider and not yet
 * linked; "Zanskar" for one with its own password, or a group made here.
 */
function Source({ idp, providerSignIn, providers, group }: { idp?: string; providerSignIn?: boolean; providers: Providers; group?: boolean }) {
  if (idp) {
    const p = providers.get(idp)
    const name = p?.name ?? 'Identity provider'
    const how = p ? ` (${p.type.toUpperCase()})` : ''
    return (
      <span className="badge source-idp" title={group ? `Members come from ${name}${how}` : `Signs in through ${name}${how}`}>
        {name}
      </span>
    )
  }
  if (providerSignIn) {
    return (
      <span className="badge source-idp" title="Signs in through an identity provider">
        Single sign-on
      </span>
    )
  }
  return (
    <span className="badge" title={group ? 'Made in Zanskar' : 'Made in Zanskar, with its own password'}>
      Zanskar
    </span>
  )
}

/** The dashboard's posture tiles, by the name the users list filters them
 *  under (2026-11-04: a tile opened the whole list); the label is the tile's. */
const postureLabels: Record<string, string> = { admins: 'Administrators', not_enrolled: 'No authenticator yet', dormant: 'Dormant (90 days)' }

function Users({ adding, setAdding }: AddingProps) {
  const me = useAuth().user
  const [sp, setSp] = useSearchParams()
  const posture = postureLabels[sp.get('posture') ?? ''] ? sp.get('posture')! : ''
  // A word finds an account by part of its username, name or email, the
  // closest match first (2026-11-04); the server ranks, so the list is shown
  // in the order it comes. Debounced so a fetch fires once typing pauses.
  const [q, setQ] = useState('')
  const dq = useDebounced(q.trim())
  const { items, err, setErr, reload } = useList<User>('/users', { posture: posture || undefined, q: dq || undefined })
  const providers = useProviders()
  const [showOnce, setShowOnce] = useState<{ username: string; password: string } | null>(null)
  const [action, setAction] = useState<{ u: User; a: UserAction } | null>(null)
  const [notice, setNotice] = useState('')

  return (
    <>
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      {notice && <Alert tone="ok" onDismiss={() => setNotice('')}>{notice}</Alert>}
      <FilterChips chips={posture ? [{ label: postureLabels[posture], onClear: () => setSp({}, { replace: true }) }] : []} />
      <div className="card table-wrap">
        <div className="list-search">
          <input type="search" placeholder="Search users by name or email" aria-label="Search users" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        {items === null ? (
          err ? null : <Loading />
        ) : items.length === 0 ? (
          <Empty>{posture || dq ? 'No users match.' : 'No users.'}</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Username</th>
                <th>Name</th>
                <th>Source</th>
                <th>Roles</th>
                <th>Status</th>
                <th>Last login</th>
                <th><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {items.map((u) => {
                const self = u.id === me?.id
                const leftFor = tookAway(u, providers)
                return (
                  <tr key={u.id}>
                    <td className="mono">{u.username}{self && <span className="muted"> (you)</span>}</td>
                    <td>
                      {u.display_name}
                      {u.email && <div className="muted">{u.email}</div>}
                    </td>
                    <td>
                      <Source idp={u.idp_id} providerSignIn={u.provider_sign_in} providers={providers} />
                    </td>
                    <td>{normalizeRoles(u.roles).map((r) => <Badge key={r} tone={r === 'admin' ? 'accent' : undefined}>{r}</Badge>)}</td>
                    <td>
                      <StateIcon
                        state={u.state === 'active' ? 'ok' : 'warn'}
                        label={
                          u.state === 'disabled' && leftFor
                            ? `Disabled: ${leftFor} no longer has this person`
                            : u.state === 'locked_out' && u.locked_until
                              ? `Locked out until ${fmtTime(u.locked_until)}`
                              : capitalised(stateLabel('user', u.state).label)
                        }
                      />
                      {u.must_change_password && (
                        <>
                          {' '}
                          <Badge>password change due</Badge>
                        </>
                      )}
                    </td>
                    <td className="muted">{u.last_login_at ? fmtTime(u.last_login_at) : 'never'}</td>
                    <td>
                      <select id={`u-action-${u.id}`} value="" onChange={(e) => e.target.value && setAction({ u, a: e.target.value as UserAction })} aria-label={`actions for ${u.username}`}>
                        <option value="">Actions…</option>
                        <option value="roles">Edit roles</option>
                        <option value="password">Reset password</option>
                        <option value="sessions">Revoke sessions</option>
                        <option value="mfa">Reset authenticator</option>
                        {!self && (
                          <option value="status" disabled={!!leftFor} title={leftFor ? `${leftFor} no longer has this person` : undefined}>
                            {u.status === 'active' ? 'Disable' : 'Enable'}
                          </option>
                        )}
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
          onSaved={(oneTime) => {
            setAdding(false)
            if (oneTime) setShowOnce(oneTime)
            void reload()
          }}
        />
      )}
      {showOnce && <OneTimePassword username={showOnce.username} password={showOnce.password} onClose={() => setShowOnce(null)} />}
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
          onSaved={(oneTime) => {
            setAction(null)
            if (oneTime) setShowOnce(oneTime)
            else setNotice(`Password for ${action.u.username} reset.`)
            void reload()
          }}
        />
      )}
      {action?.a === 'sessions' && (
        <Confirm
          title={`Sign ${action.u.username} out everywhere?`}
          body="Ends every sign-in and live session of this account."
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
          body="They are signed out and enrol again at their next sign-in."
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
          body={action.u.status === 'active' ? 'They are signed out and their live sessions end.' : null}
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
          body="Their sign-ins and live sessions end."
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
      <RolePicker value={value} onChange={onChange} idPrefix={prefix} />
    </Field>
  )
}

/**
 * OneTimePassword shows a generated password exactly once, for the admin
 * to pass on. The user replaces it at their first sign-in (QA finding R25).
 */
function OneTimePassword({ username, password, onClose }: { username: string; password: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  return (
    <Modal title={`One-time password for ${username}`} onClose={onClose}>
      <p>Shown once.</p>
      <p className="mono" style={{ fontSize: '1.2rem', letterSpacing: 1, wordBreak: 'break-all', padding: '10px 12px', background: 'var(--bg-sunken)', borderRadius: 6 }}>{password}</p>
      <div className="actions">
        <button className="btn" onClick={() => void navigator.clipboard?.writeText(password).then(() => setCopied(true)).catch(() => {})}>{copied ? 'Copied' : 'Copy'}</button>
        <button className="btn primary" onClick={onClose}>Done</button>
      </div>
    </Modal>
  )
}

function UserForm({ onClose, onSaved }: { onClose: () => void; onSaved: (oneTime?: { username: string; password: string }) => void }) {
  const [f, setF] = useState({ username: '', display_name: '', email: '', password: '' })
  const [r, setR] = useState<Role[]>(['user'])
  // Groups can be picked as the user is made (2026-10-30, as AWS Identity
  // Center does); the server adds them in the same transaction.
  const groups = useList<Group>('/groups')
  const [groupIDs, setGroupIDs] = useState<string[]>([])
  const { busy, err, submit } = useSubmit()
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value })
  const save = () =>
    submit(async () => {
      const body: Record<string, unknown> = { username: f.username.trim(), display_name: f.display_name.trim(), email: f.email.trim(), roles: r }
      if (groupIDs.length) body.group_ids = groupIDs
      if (f.password) body.password = f.password
      const created = await api.post<User & { initial_password?: string }>('/users', body)
      onSaved(created.initial_password ? { username: created.username, password: created.initial_password } : undefined)
    })
  return (
    <FormModal title="Add user" err={err} busy={busy} submitLabel="Create" onSubmit={save} onClose={onClose}>
      <Field label="Username" hint="letters, digits, . _ - (2-64), or an email address"><input id="nu-username" value={f.username} onChange={set('username')} required autoFocus /></Field>
      <Field label="Display name"><input id="nu-name" value={f.display_name} onChange={set('display_name')} required /></Field>
      <Field label="Email (optional)"><input id="nu-email" type="email" value={f.email} onChange={set('email')} /></Field>
      <Field label="Initial password"><input id="nu-password" type="password" autoComplete="new-password" value={f.password} onChange={set('password')} minLength={12} placeholder="A one-time password is generated" /></Field>
      {/* Zanskar adds its own accounts only; a person who signs in through an
          identity provider comes from it (2026-11-02, ADR 0035 amended). */}
      <RoleChecks value={r} onChange={setR} prefix="nu" />
      {(groups.items?.length ?? 0) > 0 && (
        <Field label="Groups (optional)">
          <PickList
            label="groups"
            idPrefix="nu-g"
            selected={groupIDs}
            onToggle={(id) => setGroupIDs((g) => (g.includes(id) ? g.filter((x) => x !== id) : [...g, id]))}
            onSelect={(ids, on) => setGroupIDs((g) => (on ? [...new Set([...g, ...ids])] : g.filter((x) => !ids.includes(x))))}
            options={(groups.items ?? []).map((g) => ({ id: g.id, label: g.name, locked: g.idp_id ? 'Members come from the provider' : undefined }))}
          />
        </Field>
      )}
    </FormModal>
  )
}

function RolesForm({ user, onClose, onSaved }: { user: User; onClose: () => void; onSaved: () => void }) {
  const [r, setR] = useState<Role[]>(normalizeRoles(user.roles))
  const { busy, err, submit } = useSubmit()
  const save = () =>
    submit(async () => {
      await api.put(`/users/${user.id}/roles`, { roles: r })
      onSaved()
    })
  return (
    <FormModal title={`Roles for ${user.username}`} err={err} busy={busy} submitLabel="Save" onSubmit={save} onClose={onClose}>
      <RoleChecks value={r} onChange={setR} prefix={`er-${user.id}`} />
      <p className="muted">Auditor alone is review-only.</p>
    </FormModal>
  )
}

function PasswordForm({ user, onClose, onSaved }: { user: User; onClose: () => void; onSaved: (oneTime?: { username: string; password: string }) => void }) {
  const [pw, setPw] = useState('')
  const [generate, setGenerate] = useState(true)
  const { busy, err, submit } = useSubmit()
  const save = () =>
    submit(async () => {
      const res = await api.put<{ initial_password?: string }>(`/users/${user.id}/password`, generate ? { generate: true } : { password: pw })
      onSaved(res.initial_password ? { username: user.username, password: res.initial_password } : undefined)
    })
  return (
    <FormModal title={`Reset password for ${user.username}`} err={err} busy={busy} submitLabel={generate ? 'Generate' : 'Set password'} onSubmit={save} onClose={onClose}>
      <div className="field inline">
        <input id={`pw-gen-${user.id}`} type="checkbox" checked={generate} onChange={(e) => setGenerate(e.target.checked)} />
        <label htmlFor={`pw-gen-${user.id}`}>Generate a one-time password and show it once</label>
      </div>
      {!generate && (
        <Field label="New password" hint="At least 12 characters."><input id={`pw-${user.id}`} type="password" autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} required autoFocus minLength={12} /></Field>
      )}
      <p className="muted">They are signed out and replace it at their next sign-in.</p>
    </FormModal>
  )
}

function Groups({ adding, setAdding }: AddingProps) {
  const { items, err, setErr, reload } = useList<Group>('/groups')
  const providers = useProviders()
  const [members, setMembers] = useState<Group | null>(null)
  const [deleting, setDeleting] = useState<Group | null>(null)
  return (
    <>
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      <div className="card table-wrap">
        {items === null ? (
          err ? null : <Loading />
        ) : items.length === 0 ? (
          <Empty>No groups.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Description</th>
                <th>Source</th>
                <th>Members</th>
                <th><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {items.map((g) => (
                <tr key={g.id}>
                  <td><strong>{g.name}</strong></td>
                  <td className="muted">{g.description}</td>
                  <td>
                    <Source idp={g.idp_id} providers={providers} group />
                  </td>
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
          body="It leaves its policies. Sessions it alone allowed end."
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
  // Members can be picked as the group is made (2026-10-30).
  const users = useList<User>('/users')
  const [userIDs, setUserIDs] = useState<string[]>([])
  const { busy, err, submit } = useSubmit()
  const save = () =>
    submit(async () => {
      await api.post('/groups', { name: f.name.trim(), description: f.description, ...(userIDs.length ? { user_ids: userIDs } : {}) })
      onSaved()
    })
  return (
    <FormModal title="Add group" err={err} busy={busy} submitLabel="Create" onSubmit={save} onClose={onClose}>
      <Field label="Name"><input id="g-name" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} required autoFocus /></Field>
      <Field label="Description"><input id="g-desc" value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
      {(users.items?.length ?? 0) > 0 && (
        <Field label="Members (optional)">
          <PickList
            label="users"
            idPrefix="g-u"
            selected={userIDs}
            onToggle={(id) => setUserIDs((u) => (u.includes(id) ? u.filter((x) => x !== id) : [...u, id]))}
            onSelect={(ids, on) => setUserIDs((u) => (on ? [...new Set([...u, ...ids])] : u.filter((x) => !ids.includes(x))))}
            options={(users.items ?? []).map((u) => ({ id: u.id, label: u.username, detail: u.display_name && u.display_name !== u.username ? u.display_name : undefined, detailTitle: 'Display name' }))}
          />
        </Field>
      )}
    </FormModal>
  )
}

function MembersForm({ group, onClose, onSaved }: { group: Group; onClose: () => void; onSaved: () => void }) {
  const users = useList<User>('/users')
  const [selected, setSelected] = useState<string[] | null>(null)
  const { busy, err, setErr, submit } = useSubmit()
  useEffect(() => {
    api
      .get<{ items: GroupMember[] }>(`/groups/${group.id}/members`)
      .then((r) => setSelected(r.items.map((m) => m.user_id)))
      .catch((e) => setErr(errorMessage(e)))
  }, [group.id, setErr])
  return (
    <Modal title={`Members of ${group.name}`} onClose={onClose}>
      {err && <Alert tone="danger">{err}</Alert>}
      {selected === null || users.items === null ? (
        <Loading />
      ) : (
        <div style={{ maxHeight: 320, overflowY: 'auto' }}>
          {users.items.map((u) => (
            <div key={u.id} className="field inline" style={{ margin: '4px 0' }}>
              <input id={`m-${group.id}-${u.id}`} type="checkbox" checked={selected.includes(u.id)} onChange={(e) => setSelected(e.target.checked ? [...selected, u.id] : selected.filter((x) => x !== u.id))} />
              <label htmlFor={`m-${group.id}-${u.id}`}>
                {u.username}
                {u.display_name && u.display_name !== u.username && (
                  <>
                    {' '}
                    <span className="pick-detail" title="Display name">
                      {u.display_name}
                    </span>
                  </>
                )}
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
          onClick={() =>
            void submit(async () => {
              await api.put(`/groups/${group.id}/members`, { user_ids: selected })
              onSaved()
            })
          }
        >
          Save members
        </button>
      </div>
    </Modal>
  )
}
