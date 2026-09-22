import { useState, type FormEvent } from 'react'
import { api, errorMessage } from '../../api/client'
import type { Group, Policy, Protocol, Target, TimeWindow, AutoscalingGroup, User } from '../../api/types'
import { Alert, Badge, Confirm, Empty, Field, Modal, PageHead } from '../../components/ui'
import { formatTags, parseTags, protocols, useList } from './lib'

const days = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']

function selectorSummary(p: Policy, targets: Target[], asgs: AutoscalingGroup[]) {
  const parts: string[] = []
  const tags = Object.entries(p.target_selector.tags ?? {})
  if (tags.length) parts.push(tags.map(([k, v]) => `${k}=${v}`).join(', '))
  const ids = p.target_selector.targets ?? []
  if (ids.length) parts.push(ids.map((id) => targets.find((t) => t.id === id)?.name ?? id.slice(0, 8)).join(', '))
  if (p.target_selector.asgs?.length) parts.push(p.target_selector.asgs.map((id) => 'ASG ' + (asgs.find((g) => g.id === id)?.name ?? id.slice(0, 8))).join(', '))
  return parts.join(' · ') || '—'
}

export function Policies() {
  const { items, err, setErr, reload } = useList<Policy>('/access-policies')
  const groups = useList<Group>('/groups')
  const users = useList<User>('/users')
  const targets = useList<Target>('/targets')
  const asgs = useList<AutoscalingGroup>('/autoscaling-groups')
  const [editing, setEditing] = useState<Policy | 'new' | null>(null)
  const [deleting, setDeleting] = useState<Policy | null>(null)
  const groupName = (id: string) => groups.items?.find((g) => g.id === id)?.name ?? id.slice(0, 8)
  const userName = (id: string) => users.items?.find((u) => u.id === id)?.username ?? id.slice(0, 8)

  return (
    <>
      <PageHead title="Access policies" lead="A policy lets a group, or a single user, reach a set of targets over chosen protocols, inside optional time windows, with session limits. A user's access is the union of their own policies and their groups' policies; when policies overlap, the shortest idle timeout wins.">
        <button className="btn primary" onClick={() => setEditing('new')}>Add policy</button>
      </PageHead>
      {err && <Alert tone="danger">{err}</Alert>}
      <div className="card table-wrap">
        {items === null ? (
          <Empty>Loading…</Empty>
        ) : items.length === 0 ? (
          <Empty>No policies yet. Nobody can connect until a policy grants access.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Applies to</th>
                <th>Protocols</th>
                <th>Targets</th>
                <th>Windows</th>
                <th>Idle / max</th>
                <th>Enabled</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {items.map((p) => (
                <tr key={p.id}>
                  <td>
                    <strong>{p.name}</strong>
                    {p.description && <div className="muted">{p.description}</div>}
                  </td>
                  <td>
                    {p.user_id ? (
                      <>
                        <strong>{userName(p.user_id)}</strong> <Badge>user</Badge>
                      </>
                    ) : (
                      <>
                        {groupName(p.group_id ?? '')} <Badge>group</Badge>
                      </>
                    )}
                  </td>
                  <td>{p.protocols.map((x) => <Badge key={x} tone="accent">{x}</Badge>)}</td>
                  <td>{selectorSummary(p, targets.items ?? [], asgs.items ?? [])}</td>
                  <td>{p.time_windows.length === 0 ? <span className="muted">always</span> : p.time_windows.length}</td>
                  <td>{p.idle_timeout_minutes} m / {p.max_session_minutes ? `${p.max_session_minutes} m` : '∞'}</td>
                  <td>{p.enabled ? <Badge tone="ok">on</Badge> : <Badge>off</Badge>}</td>
                  <td className="actions">
                    <button className="btn sm" onClick={() => setEditing(p)}>Edit</button>
                    <button className="btn sm danger" onClick={() => setDeleting(p)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {editing && (
        <PolicyForm
          initial={editing === 'new' ? undefined : editing}
          groups={groups.items ?? []}
          users={users.items ?? []}
          targets={targets.items ?? []}
          asgs={asgs.items ?? []}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null)
            void reload()
          }}
        />
      )}
      {deleting && (
        <Confirm
          title={`Delete policy ${deleting.name}?`}
          body={deleting.user_id ? `${userName(deleting.user_id)} loses the access it granted. Live sessions are not cut off by deletion.` : 'Users in its group lose the access it granted. Live sessions are not cut off by deletion.'}
          confirmLabel="Delete"
          danger
          onClose={() => setDeleting(null)}
          onConfirm={async () => {
            try {
              await api.del(`/access-policies/${deleting.id}`)
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

type Subject = 'group' | 'user'

interface FormState {
  name: string
  description: string
  enabled: boolean
  subject: Subject
  group_id: string
  user_id: string
  tags: string
  targets: string[]
  asgs: string[]
  protocols: Protocol[]
  windows: TimeWindow[]
  idle: string
  max: string
  allow_clipboard: boolean
  allow_file_transfer: boolean
  require_mfa: boolean
}

function PolicyForm({ initial, groups, users, targets, asgs, onClose, onSaved }: { initial?: Policy; groups: Group[]; users: User[]; targets: Target[]; asgs: AutoscalingGroup[]; onClose: () => void; onSaved: () => void }) {
  const [f, setF] = useState<FormState>({
    name: initial?.name ?? '',
    description: initial?.description ?? '',
    enabled: initial?.enabled ?? true,
    subject: initial?.user_id ? 'user' : 'group',
    group_id: initial?.group_id ?? groups[0]?.id ?? '',
    user_id: initial?.user_id ?? users[0]?.id ?? '',
    tags: formatTags(initial?.target_selector.tags),
    targets: initial?.target_selector.targets ?? [],
    asgs: initial?.target_selector.asgs ?? [],
    protocols: initial?.protocols ?? ['ssh'],
    windows: initial?.time_windows ?? [],
    idle: String(initial?.idle_timeout_minutes ?? 15),
    max: initial?.max_session_minutes ? String(initial.max_session_minutes) : '',
    allow_clipboard: initial?.allow_clipboard ?? false,
    allow_file_transfer: initial?.allow_file_transfer ?? false,
    require_mfa: initial?.require_mfa ?? true,
  })
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const up = (patch: Partial<FormState>) => setF({ ...f, ...patch })
  const toggleProto = (p: Protocol) => up({ protocols: f.protocols.includes(p) ? f.protocols.filter((x) => x !== p) : [...f.protocols, p] })
  const toggleTarget = (id: string) => up({ targets: f.targets.includes(id) ? f.targets.filter((x) => x !== id) : [...f.targets, id] })
  const toggleAsg = (id: string) => up({ asgs: f.asgs.includes(id) ? f.asgs.filter((x) => x !== id) : [...f.asgs, id] })
  const setWindow = (i: number, patch: Partial<TimeWindow>) => up({ windows: f.windows.map((w, j) => (j === i ? { ...w, ...patch } : w)) })

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    const { tags, error } = parseTags(f.tags)
    if (error) return setErr(error)
    if (f.subject === 'group' && !f.group_id) return setErr('choose a group')
    if (f.subject === 'user' && !f.user_id) return setErr('choose a user')
    if (f.protocols.length === 0) return setErr('choose at least one protocol')
    if (Object.keys(tags).length === 0 && f.targets.length === 0 && f.asgs.length === 0) return setErr('select targets by tag, by name, or an autoscaling group')
    const idle = Number(f.idle)
    if (!Number.isInteger(idle) || idle < 1) return setErr('idle timeout must be a whole number of minutes')
    const max = f.max.trim() ? Number(f.max) : null
    if (max !== null && (!Number.isInteger(max) || max < 1)) return setErr('max session must be a whole number of minutes')
    setBusy(true)
    setErr('')
    try {
      const body = {
        name: f.name.trim(),
        description: f.description,
        enabled: f.enabled,
        ...(f.subject === 'group' ? { group_id: f.group_id } : { user_id: f.user_id }),
        target_selector: { ...(Object.keys(tags).length ? { tags } : {}), ...(f.targets.length ? { targets: f.targets } : {}), ...(f.asgs.length ? { asgs: f.asgs } : {}) },
        protocols: f.protocols,
        time_windows: f.windows.map((w) => ({ ...w, tz: w.tz || 'UTC' })),
        idle_timeout_minutes: idle,
        max_session_minutes: max,
        allow_clipboard: f.allow_clipboard,
        allow_file_transfer: f.allow_file_transfer,
        require_mfa: f.require_mfa,
      }
      if (initial) await api.put(`/access-policies/${initial.id}`, body)
      else await api.post('/access-policies', body)
      onSaved()
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal title={initial ? `Edit ${initial.name}` : 'Add policy'} onClose={onClose} width={720}>
      {err && <Alert tone="danger">{err}</Alert>}
      <form onSubmit={submit}>
        <div className="form-grid">
          <Field label="Name">
            <input id="p-name" value={f.name} onChange={(e) => up({ name: e.target.value })} required autoFocus />
          </Field>
          <Field label="Description">
            <input id="p-desc" value={f.description} onChange={(e) => up({ description: e.target.value })} />
          </Field>
        </div>
        <Field label="Applies to" hint="A group policy reaches every member. A user policy reaches one person and leaves their groups untouched.">
          <div className="actions" role="radiogroup" aria-label="Applies to">
            <span className="field inline" style={{ margin: 0 }}>
              <input id="p-subject-group" type="radio" name="p-subject" checked={f.subject === 'group'} onChange={() => up({ subject: 'group' })} />
              <label htmlFor="p-subject-group">A group</label>
            </span>
            <span className="field inline" style={{ margin: 0 }}>
              <input id="p-subject-user" type="radio" name="p-subject" checked={f.subject === 'user'} onChange={() => up({ subject: 'user' })} />
              <label htmlFor="p-subject-user">One user</label>
            </span>
          </div>
        </Field>
        {f.subject === 'group' ? (
          <Field label="Group">
            <select id="p-group" value={f.group_id} onChange={(e) => up({ group_id: e.target.value })} required>
              {groups.length === 0 && <option value="">no groups yet</option>}
              {groups.map((g) => (
                <option key={g.id} value={g.id}>{g.name}</option>
              ))}
            </select>
          </Field>
        ) : (
          <Field label="User">
            <select id="p-user" value={f.user_id} onChange={(e) => up({ user_id: e.target.value })} required>
              {users.length === 0 && <option value="">no users yet</option>}
              {users.map((u) => (
                <option key={u.id} value={u.id}>{u.username}{u.display_name && u.display_name !== u.username ? ` (${u.display_name})` : ''}</option>
              ))}
            </select>
          </Field>
        )}
        <h2>Targets</h2>
        <div className="form-grid">
          <Field label="By tag" hint="key=value per line; all must match">
            <textarea id="p-tags" value={f.tags} onChange={(e) => up({ tags: e.target.value })} placeholder="env=prod" />
          </Field>
          <Field label="By name">
            <div style={{ maxHeight: 120, overflowY: 'auto', border: '1px solid var(--line)', borderRadius: 6, padding: 6 }}>
              {targets.length === 0 && <span className="muted">no targets defined</span>}
              {targets.map((t) => (
                <div key={t.id} className="field inline" style={{ margin: '2px 0' }}>
                  <input id={`p-target-${t.id}`} type="checkbox" checked={f.targets.includes(t.id)} onChange={() => toggleTarget(t.id)} />
                  <label htmlFor={`p-target-${t.id}`}>{t.name}</label>
                </div>
              ))}
            </div>
          </Field>
          <Field label="Autoscaling groups" hint="Every healthy instance of a selected group">
            <div style={{ maxHeight: 120, overflowY: 'auto', border: '1px solid var(--line)', borderRadius: 6, padding: 6 }}>
              {asgs.length === 0 && <span className="muted">no autoscaling groups enrolled</span>}
              {asgs.map((g) => (
                <div key={g.id} className="field inline" style={{ margin: '2px 0' }}>
                  <input id={`p-asg-${g.id}`} type="checkbox" checked={f.asgs.includes(g.id)} onChange={() => toggleAsg(g.id)} />
                  <label htmlFor={`p-asg-${g.id}`}>{g.name}</label>
                </div>
              ))}
            </div>
          </Field>
        </div>
        <Field label="Protocols">
          <div className="actions">
            {protocols.map((p) => (
              <span key={p} className="field inline" style={{ margin: 0 }}>
                <input id={`p-proto-${p}`} type="checkbox" checked={f.protocols.includes(p)} onChange={() => toggleProto(p)} />
                <label htmlFor={`p-proto-${p}`}>{p.toUpperCase()}</label>
              </span>
            ))}
          </div>
        </Field>
        <h2>Time windows <span className="muted" style={{ fontWeight: 400, fontSize: '0.85rem' }}>(none = always)</span></h2>
        {f.windows.map((w, i) => (
          <div key={i} className="card" style={{ padding: 12, marginBottom: 8 }}>
            <div className="actions" style={{ marginBottom: 8 }}>
              {days.map((d) => (
                <span key={d} className="field inline" style={{ margin: 0 }}>
                  <input id={`p-w${i}-${d}`} type="checkbox" checked={w.days.includes(d)} onChange={() => setWindow(i, { days: w.days.includes(d) ? w.days.filter((x) => x !== d) : [...w.days, d] })} />
                  <label htmlFor={`p-w${i}-${d}`}>{d}</label>
                </span>
              ))}
            </div>
            <div className="form-grid">
              <Field label="From (HH:MM)"><input id={`p-w${i}-from`} value={w.from} onChange={(e) => setWindow(i, { from: e.target.value })} placeholder="09:00" required /></Field>
              <Field label="To (HH:MM)"><input id={`p-w${i}-to`} value={w.to} onChange={(e) => setWindow(i, { to: e.target.value })} placeholder="18:00" required /></Field>
              <Field label="Time zone"><input id={`p-w${i}-tz`} value={w.tz} onChange={(e) => setWindow(i, { tz: e.target.value })} placeholder="UTC" /></Field>
            </div>
            <button type="button" className="btn sm" onClick={() => up({ windows: f.windows.filter((_, j) => j !== i) })}>Remove window</button>
          </div>
        ))}
        <button type="button" className="btn sm" onClick={() => up({ windows: [...f.windows, { days: ['mon', 'tue', 'wed', 'thu', 'fri'], from: '09:00', to: '18:00', tz: 'UTC' }] })}>Add window</button>
        <h2 style={{ marginTop: 16 }}>Limits</h2>
        <div className="form-grid">
          <Field label="Idle timeout (minutes)"><input id="p-idle" inputMode="numeric" value={f.idle} onChange={(e) => up({ idle: e.target.value })} required /></Field>
          <Field label="Max session (minutes, blank = none)"><input id="p-max" inputMode="numeric" value={f.max} onChange={(e) => up({ max: e.target.value })} /></Field>
        </div>
        <div className="actions">
          {(
            [
              ['allow_clipboard', 'Allow clipboard'],
              ['allow_file_transfer', 'Allow file transfer'],
              ['require_mfa', 'Require an enrolled authenticator'],
              ['enabled', 'Enabled'],
            ] as const
          ).map(([k, label]) => (
            <span key={k} className="field inline" style={{ margin: 0 }}>
              <input id={`p-${k}`} type="checkbox" checked={f[k]} onChange={(e) => up({ [k]: e.target.checked } as Partial<FormState>)} />
              <label htmlFor={`p-${k}`}>{label}</label>
            </span>
          ))}
        </div>
        <div className="actions">
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button className="btn primary" disabled={busy}>{initial ? 'Save' : 'Create'}</button>
        </div>
      </form>
    </Modal>
  )
}
