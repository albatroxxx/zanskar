import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { protocolName } from '../../api/format'
import { api, errorMessage } from '../../api/client'
import type { AutoscalingGroup, Group, Policy, PolicyGrant, PolicySubject, Protocol, Target, TargetKind, TimeWindow, User } from '../../api/types'
import { canConnect } from '../../auth/home'
import { PickList } from '../../components/PickList'
import { TagEditor } from '../../components/TagEditor'
import { tagSuggestions } from '../../components/tags'
import { Alert, Empty, Field, PageHead, RemoveButton } from '../../components/ui'
import { useList } from './lib'
import { chipsFor, fromDraft, grantSummary, kindOf, kinds, newGrant, toDraft, unfound, type GrantDraft } from './policyModel'

const days = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']

function toggle<T>(list: T[], v: T): T[] {
  return list.includes(v) ? list.filter((x) => x !== v) : [...list, v]
}

/** pickMany adds ids to list, or takes them out. */
/** personOption is a user as the audience picker lists them: the display
 *  name beside the username, and a disabled account (one its identity
 *  provider removed, say) marked and left out of Select all, the way a
 *  disabled target is. Unmarked, it read as someone the policy would reach
 *  (the live console, 2026-11-01). */
function personOption(u: User) {
  const named = u.display_name && u.display_name !== u.username ? u.display_name : undefined
  const off = u.status === 'disabled'
  return { id: u.id, label: u.username, detail: off ? [named, 'disabled'].filter(Boolean).join(' · ') : named, detailTitle: off ? undefined : 'Display name', inactive: off }
}

function pickMany(list: string[], ids: string[], on: boolean): string[] {
  return on ? [...new Set([...list, ...ids])] : list.filter((x) => !ids.includes(x))
}

/**
 * PolicyEditor adds or edits an access policy on a page of its own (ADR
 * 0036): the policy, who it applies to, and its grants, each a card that
 * picks a kind first, then targets with a protocol each or tags, then the
 * conditions its sessions open and run under.
 */
export function PolicyEditor() {
  const { id } = useParams()
  const nav = useNavigate()
  const groups = useList<Group>('/groups')
  const users = useList<User>('/users')
  const targets = useList<Target>('/targets', { limit: 500 })
  const asgs = useList<AutoscalingGroup>('/autoscaling-groups')
  const [loaded, setLoaded] = useState<Policy | null>(null)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [enabled, setEnabled] = useState(true)
  const [groupIDs, setGroupIDs] = useState<string[]>([])
  const [userIDs, setUserIDs] = useState<string[]>([])
  const [grants, setGrants] = useState<GrantDraft[]>([toDraft(newGrant())])
  const [open, setOpen] = useState<number[]>([0])
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!id) return
    api.get<Policy>(`/access-policies/${id}`).then((p) => {
      setLoaded(p)
      setName(p.name)
      setDescription(p.description)
      setEnabled(p.enabled)
      setGroupIDs(p.subjects.filter((s) => s.kind === 'group').map((s) => s.id))
      setUserIDs(p.subjects.filter((s) => s.kind === 'user').map((s) => s.id))
      setGrants(p.grants.map(toDraft))
      setOpen(p.grants.length === 1 ? [0] : [])
    }).catch((e) => setErr(errorMessage(e)))
  }, [id])

  const nameOf = (tid: string) => targets.items?.find((t) => t.id === tid)?.name ?? asgs.items?.find((g) => g.id === tid)?.name ?? tid.slice(0, 8)
  const setGrant = (i: number, d: GrantDraft) => setGrants(grants.map((g, j) => (j === i ? d : g)))

  const save = async () => {
    setErr('')
    if (!name.trim()) return fail('Name the policy')
    // A policy left with no one (its last group deleted) may be saved as it is;
    // a new one needs someone.
    if (!id && groupIDs.length + userIDs.length === 0) return fail('Choose at least one group or user')
    if (grants.length === 0) return fail('Add a grant')
    const out: PolicyGrant[] = []
    for (const [i, d] of grants.entries()) {
      const { grant, error } = fromDraft(d, nameOf)
      if (error || !grant) {
        setOpen((o) => (o.includes(i) ? o : [...o, i]))
        return fail(`Grant ${i + 1}: ${error}`)
      }
      out.push(grant)
    }
    const subjects: PolicySubject[] = [...groupIDs.map((gid) => ({ kind: 'group' as const, id: gid })), ...userIDs.map((uid) => ({ kind: 'user' as const, id: uid }))]
    const body = { name: name.trim(), description, enabled, subjects, grants: out }
    setBusy(true)
    try {
      if (id) await api.put(`/access-policies/${id}`, body)
      else await api.post('/access-policies', body)
      nav('/admin/policies')
    } catch (e) {
      fail(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }
  const fail = (msg: string) => {
    setErr(msg)
    window.scrollTo?.({ top: 0 })
  }

  if (id && !loaded && !err) return <Empty>Loading…</Empty>
  const people = (users.items ?? []).filter(canConnect)
  return (
    <div className="policy-editor">
      <PageHead title={id ? `Edit ${loaded?.name ?? 'policy'}` : 'New policy'}>
        <Link className="btn" to="/admin/policies">Back to policies</Link>
      </PageHead>
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      <div className="card">
        <h2>Policy</h2>
        <div className="form-grid">
          <Field label="Name"><input id="pe-name" value={name} onChange={(e) => setName(e.target.value)} required autoFocus={!id} /></Field>
          <Field label="Description"><input id="pe-desc" value={description} onChange={(e) => setDescription(e.target.value)} /></Field>
        </div>
        <div className="field inline">
          <input id="pe-enabled" type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          <label htmlFor="pe-enabled">Enabled</label>
        </div>
      </div>
      <div className="card">
        <h2>Who</h2>
        <div className="form-grid">
          <Field label="Groups">
            <PickList label="groups" idPrefix="pe-group" selected={groupIDs} onToggle={(gid) => setGroupIDs(toggle(groupIDs, gid))} onSelect={(ids, on) => setGroupIDs(pickMany(groupIDs, ids, on))}
              options={(groups.items ?? []).map((g) => ({ id: g.id, label: g.name, detail: g.member_count !== undefined ? `${g.member_count} ${g.member_count === 1 ? 'member' : 'members'}` : undefined }))} />
          </Field>
          <Field label="Users" hint="Review-only accounts are not offered">
            <PickList label="users" idPrefix="pe-user" selected={userIDs} onToggle={(uid) => setUserIDs(toggle(userIDs, uid))} onSelect={(ids, on) => setUserIDs(pickMany(userIDs, ids, on))}
              options={people.map(personOption)} />
          </Field>
        </div>
      </div>
      <h2 className="section-title">Grants</h2>
      {grants.map((d, i) => (
        <GrantCard
          key={i}
          index={i}
          draft={d}
          open={open.includes(i)}
          onToggleOpen={() => setOpen(toggle(open, i))}
          onChange={(nd) => setGrant(i, nd)}
          onRemove={() => {
            setGrants(grants.filter((_, j) => j !== i))
            setOpen(open.filter((j) => j !== i).map((j) => (j > i ? j - 1 : j)))
          }}
          onDuplicate={() => {
            setGrants([...grants.slice(0, i + 1), { ...structuredClone(d), id: undefined }, ...grants.slice(i + 1)])
            setOpen([...open.map((j) => (j > i ? j + 1 : j)), i + 1])
          }}
          targets={targets.items ?? []}
          asgs={asgs.items ?? []}
          nameOf={nameOf}
        />
      ))}
      <div className="actions">
        <button type="button" className="btn" onClick={() => { setGrants([...grants, toDraft(newGrant())]); setOpen([...open, grants.length]) }}>Add grant</button>
        {grants.length > 0 && (
          <button type="button" className="btn" onClick={() => {
            const last = fromDraft(grants[grants.length - 1], nameOf).grant
            setGrants([...grants, toDraft(newGrant(grants[grants.length - 1].kind, last))])
            setOpen([...open, grants.length])
          }}>Add grant, same conditions</button>
        )}
      </div>
      <div className="editor-footer">
        <Link className="btn" to="/admin/policies">Cancel</Link>
        <button type="button" className="btn primary" disabled={busy} onClick={() => void save()}>{busy ? 'Saving…' : id ? 'Save' : 'Create'}</button>
      </div>
    </div>
  )
}

/** GrantCard edits one grant: kind, what it covers, and its conditions. */
function GrantCard({ index, draft: d, open, onToggleOpen, onChange, onRemove, onDuplicate, targets, asgs, nameOf }: {
  index: number
  draft: GrantDraft
  open: boolean
  onToggleOpen: () => void
  onChange: (d: GrantDraft) => void
  onRemove: () => void
  onDuplicate: () => void
  targets: Target[]
  asgs: AutoscalingGroup[]
  nameOf: (id: string) => string
}) {
  const p = `pe-g${index}`
  const up = (patch: Partial<GrantDraft>) => onChange({ ...d, ...patch })
  const implicit = d.kind === 'database' || d.kind === 'application'
  const ofKind = useMemo(
    () => (d.kind === 'autoscaling' ? [] : targets.filter((t) => kindOf(t) === d.kind)),
    [targets, d.kind],
  )
  const listed = d.kind === 'autoscaling'
    ? asgs.map((g) => ({ id: g.id, label: g.name, detail: g.status === 'disabled' ? `${g.os_family} · disabled` : g.os_family, inactive: g.status === 'disabled' }))
    : ofKind.map((t) => {
      const what = d.kind === 'database' ? t.engine : d.kind === 'host' ? t.os_family : undefined
      return { id: t.id, label: t.name, detail: t.status === 'disabled' ? [what, 'disabled'].filter(Boolean).join(' · ') : what, inactive: t.status === 'disabled' }
    })
  // A target the grant names that the lists do not hold (retired since, or
  // beyond the first page) stays visible, so it can be seen and removed
  // rather than kept in silence.
  const options = [...listed, ...Object.keys(d.targets).filter((tid) => !listed.some((o) => o.id === tid)).map((tid) => ({ id: tid, label: nameOf(tid), detail: 'not found', inactive: true }))]
  const chips = (tid: string): Protocol[] => {
    if (d.kind === 'autoscaling') {
      const g = asgs.find((x) => x.id === tid)
      return g ? chipsFor('autoscaling', g) : []
    }
    const t = ofKind.find((x) => x.id === tid)
    return t ? chipsFor(d.kind, t) : []
  }
  // Picking a target picks its one protocol for the admin; with several, none.
  const firstPick = (tid: string): Protocol[] => {
    const c = chips(tid)
    return c.length === 1 ? [...c] : []
  }
  const chosenIDs = Object.keys(d.targets)
  // The protocols any chosen target serves, for setting them on all at once.
  const bulk = implicit || chosenIDs.length < 2 ? [] : [...new Set(chosenIDs.flatMap((tid) => chips(tid)))]
  const suggest = tagSuggestions(d.kind === 'autoscaling' ? asgs : ofKind)
  const summary = fromDraft(d, nameOf).grant
  const setWindow = (i: number, patch: Partial<TimeWindow>) => up({ windows: d.windows.map((w, j) => (j === i ? { ...w, ...patch } : w)) })

  return (
    <section className="card grant-card" aria-labelledby={`${p}-title`}>
      <div className="grant-head">
        <h3 id={`${p}-title`}>Grant {index + 1}</h3>
        {!open && <span className="muted grant-summary">{summary ? grantSummary(summary, nameOf) : 'incomplete'}</span>}
        <span className="grow" />
        <button type="button" className="btn sm" onClick={onDuplicate}>Duplicate</button>
        <button type="button" className="btn sm" onClick={onRemove}>Remove</button>
        <button type="button" className="btn sm" aria-expanded={open} aria-label={open ? `Done with grant ${index + 1}` : `Edit grant ${index + 1}`} onClick={onToggleOpen}>{open ? 'Done' : 'Edit'}</button>
      </div>
      {open && (
        <>
          <div className="seg" role="radiogroup" aria-label={`Grant ${index + 1} type`}>
            {kinds.map((k) => (
              <span key={k.kind} className="field inline">
                <input id={`${p}-kind-${k.kind}`} type="radio" name={`${p}-kind`} checked={d.kind === k.kind}
                  onChange={() => onChange({ ...d, kind: k.kind as TargetKind, targets: {}, tagProtocols: k.kind === 'database' ? ['database'] : k.kind === 'application' ? ['http'] : ['ssh'], sign_in: k.kind === 'application' ? 'target' : d.sign_in })} />
                <label htmlFor={`${p}-kind-${k.kind}`}>{k.label}</label>
              </span>
            ))}
          </div>
          <div className="form-grid">
            <Field label="Targets">
              <PickList label={d.kind === 'autoscaling' ? 'groups' : `${kinds.find((k) => k.kind === d.kind)?.label.toLowerCase()}s`} idPrefix={`${p}-t`}
                options={options} selected={Object.keys(d.targets)}
                onToggle={(tid) => {
                  const next = { ...d.targets }
                  if (tid in next) delete next[tid]
                  else next[tid] = firstPick(tid)
                  up({ targets: next })
                }}
                onSelect={(ids, on) => {
                  const next = { ...d.targets }
                  for (const tid of ids) {
                    if (!on) delete next[tid]
                    else if (!(tid in next)) next[tid] = firstPick(tid)
                  }
                  up({ targets: next })
                }}
                extra={implicit ? undefined : (tid) => {
                  const chosen = d.targets[tid] ?? []
                  const host = d.kind === 'host' ? ofKind.find((x) => x.id === tid) : undefined
                  const { missing, stale } = host ? unfound(host, chosen) : { missing: [], stale: [] }
                  return (
                    <span className="chips">
                      {[...chips(tid), ...stale].map((proto) => {
                        const off = stale.includes(proto)
                        return (
                          <span key={proto} className={'chip-toggle' + (off ? ' stale' : '')} title={off ? 'Not found by the last probe' : undefined}>
                            <input id={`${p}-t-${tid}-${proto}`} type="checkbox" checked={chosen.includes(proto)}
                              onChange={() => up({ targets: { ...d.targets, [tid]: toggle(chosen, proto) } })}
                              aria-label={`${protocolName(proto)} on ${nameOf(tid)}${off ? ', not found by the last probe' : ''}`} />
                            <label htmlFor={`${p}-t-${tid}-${proto}`} aria-hidden="true">{protocolName(proto)}</label>
                          </span>
                        )
                      })}
                      {missing.map((proto) => (
                        <span key={proto} className="chip-toggle unfound" title="Not found by the last probe; probe again">
                          <input id={`${p}-t-${tid}-${proto}`} type="checkbox" checked={false} disabled
                            aria-label={`${protocolName(proto)} on ${nameOf(tid)}, not found by the last probe; probe again`} />
                          <label htmlFor={`${p}-t-${tid}-${proto}`} aria-hidden="true">{protocolName(proto)}</label>
                        </span>
                      ))}
                    </span>
                  )
                }} />
              {bulk.length > 0 && (
                <div className="chips bulk-chips" role="group" aria-label={`Grant ${index + 1} protocols for every chosen target`}>
                  <span className="muted">All chosen</span>
                  {bulk.map((proto) => {
                    const serving = chosenIDs.filter((tid) => chips(tid).includes(proto))
                    const on = serving.every((tid) => (d.targets[tid] ?? []).includes(proto))
                    return (
                      <span key={proto} className="chip-toggle">
                        <input id={`${p}-bulk-${proto}`} type="checkbox" checked={on}
                          onChange={() => {
                            const next = { ...d.targets }
                            for (const tid of serving) next[tid] = on ? (next[tid] ?? []).filter((x) => x !== proto) : [...new Set([...(next[tid] ?? []), proto])]
                            up({ targets: next })
                          }} />
                        <label htmlFor={`${p}-bulk-${proto}`}>{protocolName(proto)}</label>
                      </span>
                    )
                  })}
                </div>
              )}
            </Field>
            <Field label="Tags" hint="Every key must match; a repeated key matches any of its values">
              <>
                <TagEditor idPrefix={`${p}-tag`} rows={d.tagRows} onChange={(tagRows) => up({ tagRows })} suggest={suggest} valuePlaceholder="value" />
                {!implicit && d.tagRows.length > 0 && (
                  <div className="chips" role="group" aria-label={`Grant ${index + 1} protocols for tagged targets`}>
                    {(['ssh', 'rdp', 'vnc', 'winrm'] as Protocol[]).map((proto) => (
                      <span key={proto} className="chip-toggle">
                        <input id={`${p}-tagproto-${proto}`} type="checkbox" checked={d.tagProtocols.includes(proto)} onChange={() => up({ tagProtocols: toggle(d.tagProtocols, proto) })} />
                        <label htmlFor={`${p}-tagproto-${proto}`}>{protocolName(proto)}</label>
                      </span>
                    ))}
                  </div>
                )}
              </>
            </Field>
          </div>
          <h4>Conditions</h4>
          <div className="conditions">
            <div className="form-grid">
              <Field label="Access">
                <div className="seg" role="radiogroup" aria-label={`Grant ${index + 1} access`}>
                  {(['standing', 'approval'] as const).map((a) => (
                    <span key={a} className="field inline">
                      <input id={`${p}-access-${a}`} type="radio" name={`${p}-access`} checked={d.access === a} onChange={() => up({ access: a })} />
                      <label htmlFor={`${p}-access-${a}`}>{a === 'standing' ? 'Standing' : 'Approval (just-in-time)'}</label>
                    </span>
                  ))}
                </div>
              </Field>
              {d.kind !== 'application' && (
                <Field label="Sign in with">
                  <div className="seg" role="radiogroup" aria-label={`Grant ${index + 1} sign-in`}>
                    {(['target', 'own'] as const).map((s) => (
                      <span key={s} className="field inline">
                        <input id={`${p}-signin-${s}`} type="radio" name={`${p}-signin`} checked={d.sign_in === s} onChange={() => up({ sign_in: s })} />
                        <label htmlFor={`${p}-signin-${s}`}>{s === 'target' ? "The target's credential" : 'Their own login'}</label>
                      </span>
                    ))}
                  </div>
                </Field>
              )}
            </div>
            <div className="actions">
              {([
                ['require_mfa', 'Authenticator'],
                ['allow_clipboard', 'Clipboard'],
                ['allow_file_transfer', 'File transfer'],
                // Developer tools exist only in an application's browser (ADR 0037).
                ...(d.kind === 'application' ? ([['allow_devtools', 'Developer tools']] as const) : []),
              ] as const).map(([k, label]) => (
                <span key={k} className="field inline">
                  <input id={`${p}-${k}`} type="checkbox" checked={d[k]} onChange={(e) => up({ [k]: e.target.checked } as Partial<GrantDraft>)} />
                  <label htmlFor={`${p}-${k}`}>{label}</label>
                </span>
              ))}
            </div>
            <div className="form-grid">
              <Field label="Idle (minutes)"><input id={`${p}-idle`} inputMode="numeric" value={d.idle} onChange={(e) => up({ idle: e.target.value })} /></Field>
              <Field label="Maximum (minutes)"><input id={`${p}-max`} inputMode="numeric" value={d.max} onChange={(e) => up({ max: e.target.value })} placeholder="No limit" /></Field>
              <Field label="Recording retention (days)" info="A target's own value comes first; this grant's next; left empty, the global retention."><input id={`${p}-retention`} inputMode="numeric" value={d.retention} onChange={(e) => up({ retention: e.target.value })} placeholder="Global" /></Field>
            </div>
            <Field label="Time windows" hint="None = always">
              <div className="windows">
                {d.windows.map((w, i) => (
                  <div key={i} className="window-row">
                    <span className="days" role="group" aria-label={`Window ${i + 1} days`}>
                      {days.map((day) => (
                        <span key={day} className="chip-toggle">
                          <input id={`${p}-w${i}-${day}`} type="checkbox" checked={w.days.includes(day)} onChange={() => setWindow(i, { days: toggle(w.days, day) })} />
                          <label htmlFor={`${p}-w${i}-${day}`}>{day}</label>
                        </span>
                      ))}
                    </span>
                    <input aria-label={`Window ${i + 1} from`} className="time" value={w.from} onChange={(e) => setWindow(i, { from: e.target.value })} placeholder="09:00" />
                    <input aria-label={`Window ${i + 1} to`} className="time" value={w.to} onChange={(e) => setWindow(i, { to: e.target.value })} placeholder="18:00" />
                    <input aria-label={`Window ${i + 1} time zone`} className="tz" value={w.tz} onChange={(e) => setWindow(i, { tz: e.target.value })} placeholder="UTC" />
                    <RemoveButton label={`Remove window ${i + 1}`} onClick={() => up({ windows: d.windows.filter((_, j) => j !== i) })} />
                  </div>
                ))}
                <div>
                  <button type="button" className="btn sm" onClick={() => up({ windows: [...d.windows, { days: ['mon', 'tue', 'wed', 'thu', 'fri'], from: '09:00', to: '18:00', tz: 'UTC' }] })}>Add window</button>
                </div>
              </div>
            </Field>
          </div>
        </>
      )}
    </section>
  )
}
