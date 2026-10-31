import { useEffect, useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, ApiError, errorMessage } from '../../api/client'
import { accessDrill, expiresSoon } from '../../api/drilldown'
import type { AccessRequest, ConnectResponse, Page, Protocol, ReachableInstance, ReachableTarget, Session } from '../../api/types'
import { DatabaseIcon, OSIcon, StateIcon } from '../../components/icons'
import { Alert, Badge, Empty, Field, Modal, PageHead, StatTile, Tabs, Tags } from '../../components/ui'
import { badgesChanged } from '../../components/badges'
import { engineName, protocolName } from '../../api/format'
import { fmtAgo } from './Failover'

const terminalProtocols: Protocol[] = ['ssh', 'winrm']
const desktopProtocols: Protocol[] = ['rdp', 'vnc']
const databaseProtocols: Protocol[] = ['database']

function pick(t: ReachableTarget, family: Protocol[]): Protocol | null {
  // database is brokered, never probed, so it is not a capability.
  for (const p of family) if (t.allowed_protocols.includes(p) && (p === 'database' || t.capabilities.length === 0 || t.capabilities.includes(p))) return p
  return null
}

/** Body of POST /connect: exactly one of target_id, asg_id, asg_instance_id. */
interface ConnectBody {
  target_id?: string
  asg_id?: string
  asg_instance_id?: string
  protocol: Protocol
  /** The user's own login, for a slot that asks for it: a password, or over
   *  SSH their own private key with its passphrase when it has one. */
  credential?: { username: string; password?: string; private_key?: string; private_key_passphrase?: string }
}

/** The largest key file the prompt reads; the gateway refuses more. */
const maxKeyBytes = 16 << 10

const noCred = { username: '', password: '', method: 'password' as 'password' | 'key', key: '', passphrase: '' }

export function Targets() {
  const nav = useNavigate()
  const [items, setItems] = useState<ReachableTarget[] | null>(null)
  const [err, setErr] = useState('')
  const [notice, setNotice] = useState('')
  const [tab, setTab] = useState<'static' | 'database' | 'application' | 'asg'>('static')
  const [prompt, setPrompt] = useState<{ target: ReachableTarget; protocol: Protocol; body: ConnectBody } | null>(null)
  const [chooser, setChooser] = useState<{ group: ReachableTarget; protocol: Protocol; instances: ReachableInstance[] | null } | null>(null)
  const [cred, setCred] = useState(noCred)
  const [promptErr, setPromptErr] = useState('')
  // Closing the prompt forgets what was typed in it, the username excepted.
  const closePrompt = () => {
    setPrompt(null)
    setPromptErr('')
    setCred((c) => ({ ...noCred, username: c.username, method: c.method }))
  }
  const readKeyFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    if (file.size > maxKeyBytes) {
      setPromptErr('that file is too large to be a private key')
      return
    }
    void file.text().then((key) => setCred((c) => ({ ...c, key })))
  }
  // Active grants, as a set of "targetId:protocol", so a gated protocol the user
  // already holds a grant for shows Connect rather than Request.
  const [grants, setGrants] = useState<Set<string>>(new Set())
  const [reqModal, setReqModal] = useState<{ target: ReachableTarget; protocol: Protocol } | null>(null)
  const [reqForm, setReqForm] = useState({ reason: '', minutes: 60 })
  const [busy, setBusy] = useState('')
  // Live filter over the already-loaded reachable list: matching is instant, no
  // refetch. Only name and the private IP are searchable because the portal is
  // the only place a public address is deliberately withheld (see
  // ReachableTarget.private_ip); searching cannot reveal what the list hides.
  const [search, setSearch] = useState('')

  // The overview strip (ADR 0029): the three things worth a glance before the
  // list — a session left open, a request still waiting, a grant about to run
  // out. All scoped to the account; it fails silently because the page's real
  // content reports its own errors.
  const [strip, setStrip] = useState({ open: 0, pending: 0, expiring: 0 })

  const loadGrants = () =>
    api
      .get<Page<AccessRequest>>('/me/access')
      .then((p) => {
        setGrants(new Set(p.items.map((g) => `${g.target_id ?? g.asg_id}:${g.protocol}`)))
        setStrip((s) => ({ ...s, expiring: p.items.filter((g) => expiresSoon(g.expires_at)).length }))
      })
      .catch(() => {})

  useEffect(() => {
    api
      .get<Page<ReachableTarget>>('/me/targets')
      .then((p) => {
        setItems(p.items)
        // Land on a tab that has something in it. Opening on an empty Hosts
        // tab while Databases holds entries reads as "you have no access"
        // (manual QA finding 2).
        const kind = (t: ReachableTarget) => (t.kind === 'asg' ? 'asg' : t.kind === 'application' ? 'application' : t.engine ? 'database' : 'static')
        if (!p.items.some((t) => kind(t) === 'static')) {
          const first = (['database', 'application', 'asg'] as const).find((k) => p.items.some((t) => kind(t) === k))
          if (first) setTab(first)
        }
      })
      .catch((e) => setErr(errorMessage(e)))
    void loadGrants()
    api
      .get<Page<Session>>('/me/sessions?open=true&limit=50')
      .then((p) => setStrip((s) => ({ ...s, open: p.items.length })))
      .catch(() => {})
    api
      .get<Page<AccessRequest>>('/me/access-requests')
      .then((p) => setStrip((s) => ({ ...s, pending: p.items.filter((r) => r.status === 'pending').length })))
      .catch(() => {})
  }, [])

  // A protocol is gated when the policy requires approval and the user holds no
  // active grant for it yet.
  const gated = (t: ReachableTarget, p: Protocol) => (t.requires_approval ?? []).includes(p) && !grants.has(`${t.id}:${p}`)

  const connect = async (target: ReachableTarget, body: ConnectBody) => {
    setBusy(target.id + body.protocol)
    setErr('')
    try {
      const res = await api.post<ConnectResponse>('/connect', body)
      closePrompt()
      setChooser(null)
      nav(res.ws_path === '/ws/desktop' ? '/desktop' : '/terminal', {
        state: {
          ticket: res.ticket,
          ws_path: res.ws_path,
          target: target.name,
          protocol: body.protocol,
          asg_id: res.asg_id,
          asg_instance_id: res.asg_instance_id,
          instance_label: res.instance_label,
        },
      })
    } catch (e) {
      if (prompt && e instanceof ApiError && (e.code === 'credential_required' || e.code === 'credential_invalid')) {
        // Said inside the open prompt, where the user is looking.
        setPromptErr(e.message)
      } else if (e instanceof ApiError && e.code === 'credential_required') {
        setPromptErr('')
        setPrompt({ target, protocol: body.protocol, body })
      } else if (e instanceof ApiError && e.code === 'approval_required') {
        // The grant lapsed between listing and connecting; fall back to a request.
        void loadGrants()
        setReqModal({ target, protocol: body.protocol })
      } else if (e instanceof ApiError && (e.code === 'no_healthy_instances' || e.code === 'instance_unhealthy')) {
        setErr(e.message)
        if (chooser) void loadInstances(chooser.group, chooser.protocol)
      } else {
        setErr(errorMessage(e))
      }
    } finally {
      setBusy('')
    }
  }

  const submitRequest = async (e: FormEvent) => {
    e.preventDefault()
    if (!reqModal) return
    setBusy('request')
    setErr('')
    try {
      await api.post<AccessRequest>('/me/access-requests', {
        ...(reqModal.target.kind === 'asg' ? { asg_id: reqModal.target.id } : { target_id: reqModal.target.id }),
        protocol: reqModal.protocol,
        reason: reqForm.reason,
        minutes: Number(reqForm.minutes),
      })
      badgesChanged()
      setNotice(`Requested ${protocolName(reqModal.protocol)} access to ${reqModal.target.name}. An administrator must approve it — track it under Access.`)
      setReqModal(null)
      setReqForm({ reason: '', minutes: 60 })
      void loadGrants()
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy('')
    }
  }

  const loadInstances = async (group: ReachableTarget, protocol: Protocol) => {
    setChooser({ group, protocol, instances: null })
    try {
      const p = await api.get<Page<ReachableInstance>>(`/me/autoscaling-groups/${encodeURIComponent(group.id)}/instances`)
      setChooser({ group, protocol, instances: p.items })
    } catch (e) {
      setErr(errorMessage(e))
      setChooser({ group, protocol, instances: [] })
    }
  }

  const kindOf = (t: ReachableTarget) => (t.kind === 'asg' ? 'asg' : t.kind === 'application' ? 'application' : t.engine ? 'database' : 'target')
  const term = search.trim().toLowerCase()
  const matches = (t: ReachableTarget) => term === '' || t.name.toLowerCase().includes(term) || (t.private_ip?.toLowerCase().includes(term) ?? false)
  const shown = items?.filter(matches) ?? null
  const statics = shown?.filter((t) => kindOf(t) === 'target') ?? null
  const databases = shown?.filter((t) => kindOf(t) === 'database') ?? null
  const applications = shown?.filter((t) => kindOf(t) === 'application') ?? null
  const groups = shown?.filter((t) => kindOf(t) === 'asg') ?? null
  // Every tab says how many it holds, the same way, once there are any; a
  // search narrows the counts with the lists.
  const counted = (label: string, list: ReachableTarget[] | null) => (list && list.length > 0 ? `${label} (${list.length})` : label)
  // Empty-state text for a tab: the search message while filtering, else the tab's own "nothing assigned" line.
  const emptyFor = (noun: string, assigned: string) => (term ? `No ${noun} match ‘${search.trim()}’.` : assigned)

  // protoButtons renders one cell per protocol family. onRequest, when given,
  // turns a gated protocol into a Request button; onOwn, when given, adds
  // "as me" where a grant lets the user sign in with their own login
  // instead of the target's (ADR 0036).
  const protoButtons = (t: ReachableTarget, onPick: (p: Protocol) => void, onRequest?: (p: Protocol) => void, onOwn?: (p: Protocol) => void) => {
    const term = pick(t, terminalProtocols)
    const desk = pick(t, desktopProtocols)
    const notReady = !t.host_key_ready && term === 'ssh'
    const cell = (p: Protocol | null, colorClass: string, label: string, blocked: boolean) => {
      if (p && onRequest && gated(t, p)) {
        return (
          <button className="btn sm" onClick={() => onRequest(p)} title={`request ${label.toLowerCase()} access`}>
            Request
          </button>
        )
      }
      const main = (
        <button className={'btn sm' + (p ? colorClass : '')} disabled={!p || blocked || busy === t.id + p} onClick={() => p && onPick(p)} title={p ? label : 'not allowed'}>
          {p ? label : '—'}
        </button>
      )
      if (!p || !onOwn || !(t.own_login ?? []).includes(p)) return main
      return (
        <span className="actions">
          {main}
          <button className="btn sm ghost" disabled={blocked} onClick={() => onOwn(p)} aria-label={`${label} with my own login`} title="with my own login">as me</button>
        </span>
      )
    }
    return (
      <>
        <td>{cell(term, ' proto-terminal', term ? protocolName(term) : '', notReady)}</td>
        <td>{cell(desk, ' proto-desktop', desk ? protocolName(desk) : '', false)}</td>
      </>
    )
  }

  return (
    <>
      <PageHead title="Targets" />
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      {items && items.length > 0 && (
        <div className="list-search">
          <input
            type="search"
            placeholder="Search by name or IP"
            aria-label="Search targets by name or IP"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      )}
      {notice && <Alert tone="ok" onDismiss={() => setNotice('')}>{notice}</Alert>}
      {(strip.open > 0 || strip.pending > 0 || strip.expiring > 0) && (
        <div className="stat-grid" style={{ marginBottom: 16 }}>
          {strip.open > 0 && <StatTile value={strip.open} label="Open sessions" to={accessDrill.openSessions} />}
          {strip.pending > 0 && <StatTile value={strip.pending} label="Pending requests" to={accessDrill.pendingRequests} />}
          {strip.expiring > 0 && <StatTile value={strip.expiring} label="Grants expiring soon" to={accessDrill.expiringGrants} tone="warn" />}
        </div>
      )}
      <Tabs
        label="Kinds of target"
        value={tab}
        onChange={setTab}
        tabs={[
          { key: 'static', label: counted('Hosts', statics) },
          { key: 'database', label: counted('Databases', databases) },
          { key: 'application', label: counted('Applications', applications) },
          { key: 'asg', label: counted('Autoscaling', groups) },
        ]}
      />

      {tab === 'application' && (
        <div className="card table-wrap">
          {applications === null ? (
            <Empty>Loading…</Empty>
          ) : applications.length === 0 ? (
            <Empty>{emptyFor('applications', 'No applications are assigned to you. Ask an administrator for access.')}</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Tags</th>
                  <th>Open</th>
                </tr>
              </thead>
              <tbody>
                {applications.map((t) => (
                  <tr key={t.id}>
                    <td><strong>{t.name}</strong></td>
                    <td><Tags tags={t.tags} /></td>
                    <td>
                      {gated(t, 'http') ? (
                        <button className="btn sm" onClick={() => setReqModal({ target: t, protocol: 'http' })} title="request access to this application">Request</button>
                      ) : (
                        // The application opens in an isolated browser beside
                        // the gateway, streamed like a desktop (ADR 0034): the
                        // ticket comes from /connect and the page is Desktop.
                        <button className="btn sm proto-app" disabled={busy === t.id + 'http'} onClick={() => void connect(t, { target_id: t.id, protocol: 'http' })} title="open in an isolated browser">Open</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === 'database' && (
        <div className="card table-wrap">
          {databases === null ? (
            <Empty>Loading…</Empty>
          ) : databases.length === 0 ? (
            <Empty>{emptyFor('databases', 'No databases are assigned to you. Ask an administrator for access.')}</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Engine</th>
                  <th>Tags</th>
                  <th>Connect</th>
                </tr>
              </thead>
              <tbody>
                {databases.map((t) => {
                  const p = pick(t, databaseProtocols)
                  return (
                    <tr key={t.id}>
                      <td><strong>{t.name}</strong></td>
                      <td><DatabaseIcon label={engineName(t.engine)} /> {engineName(t.engine)}</td>
                      <td><Tags tags={t.tags} /></td>
                      <td>
                        {p && gated(t, p) ? (
                          <button className="btn sm" onClick={() => setReqModal({ target: t, protocol: p })} title="request database access">Request</button>
                        ) : (
                          <button className={'btn sm' + (p ? ' proto-database' : '')} disabled={!p || busy === t.id + p} onClick={() => p && void connect(t, { target_id: t.id, protocol: p })} title={p ? 'open the SQL client' : 'not allowed'}>
                            {p ? 'SQL client' : '—'}
                          </button>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === 'static' && (
        <div className="card table-wrap">
          {statics === null ? (
            <Empty>Loading…</Empty>
          ) : statics.length === 0 ? (
            <Empty>{emptyFor('hosts', 'No hosts are assigned to you yet. Ask an administrator for access.')}</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>OS</th>
                  <th>IP</th>
                  <th>Tags</th>
                  <th>Terminal</th>
                  <th>Desktop</th>
                </tr>
              </thead>
              <tbody>
                {statics.map((t) => {
                  const notReady = !t.host_key_ready && pick(t, terminalProtocols) === 'ssh'
                  return (
                    <tr key={t.id}>
                      <td>
                        <strong>{t.name}</strong>
                        {notReady && (
                          <>
                            {' '}
                            <StateIcon state="warn" label="Awaiting host key trust — an administrator must trust this machine's key first" />
                          </>
                        )}
                      </td>
                      <td><OSIcon os={t.os_family} /></td>
                      <td className="mono">{t.private_ip ?? '—'}</td>
                      <td><Tags tags={t.tags} /></td>
                      {protoButtons(t, (p) => void connect(t, { target_id: t.id, protocol: p }), (p) => setReqModal({ target: t, protocol: p }),
                        (p) => { setPromptErr(''); setPrompt({ target: t, protocol: p, body: { target_id: t.id, protocol: p } }) })}
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === 'asg' && (
        <div className="card table-wrap">
          {groups === null ? (
            <Empty>Loading…</Empty>
          ) : groups.length === 0 ? (
            <Empty>{emptyFor('autoscaling groups', 'No autoscaling groups are assigned to you. Ask an administrator for access.')}</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Group</th>
                  <th>OS</th>
                  <th>Tags</th>
                  <th>Healthy</th>
                  <th>Terminal</th>
                  <th>Desktop</th>
                </tr>
              </thead>
              <tbody>
                {groups.map((g) => {
                  const healthy = g.healthy_count ?? 0
                  const total = g.instance_count ?? 0
                  return (
                    <tr key={g.id}>
                      <td><strong>{g.name}</strong></td>
                      <td><OSIcon os={g.os_family} /></td>
                      <td><Tags tags={g.tags} /></td>
                      <td>
                        <Badge tone={healthy === 0 ? 'danger' : 'ok'}>{healthy} / {total}</Badge>
                      </td>
                      {protoButtons(g, (p) => void loadInstances(g, p), (p) => setReqModal({ target: g, protocol: p }))}
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {chooser && (
        <Modal title={`Connect to ${chooser.group.name}`} onClose={() => setChooser(null)} width={560}>
          <p className="muted">Newest healthy instance, or pick one.</p>
          {chooser.instances === null && <p className="muted">Loading healthy instances…</p>}
          {chooser.instances !== null && chooser.instances.length === 0 && (
            <Alert tone="warn">This group has no healthy instance right now.</Alert>
          )}
          {chooser.instances && chooser.instances.length > 0 && (
            <div className="failover-list">
              {chooser.instances.map((i) => (
                <div key={i.id} className="failover-row">
                  <div>
                    <span className="mono">{i.instance_id}</span>
                    <span className="muted"> · {i.availability_zone} · launched {fmtAgo(i.launched_at)}</span>
                  </div>
                  <button id={`pick-${i.id}`} className="btn sm" disabled={busy !== ''} onClick={() => void connect(chooser.group, { asg_instance_id: i.id, protocol: chooser.protocol })}>
                    Connect
                  </button>
                </div>
              ))}
            </div>
          )}
          <div className="actions" style={{ justifyContent: 'space-between' }}>
            <a href="#refresh" className="muted" onClick={(e) => { e.preventDefault(); void loadInstances(chooser.group, chooser.protocol) }}>Refresh</a>
            <span>
              <button className="btn" onClick={() => setChooser(null)}>Cancel</button>
              <button
                id="connect-newest"
                className="btn primary"
                style={{ marginLeft: 8 }}
                disabled={busy !== '' || !chooser.instances || chooser.instances.length === 0}
                onClick={() => void connect(chooser.group, { asg_id: chooser.group.id, protocol: chooser.protocol })}
              >
                Connect to newest healthy
              </button>
            </span>
          </div>
        </Modal>
      )}

      {reqModal && (
        <Modal title={`Request access to ${reqModal.target.name}`} onClose={() => setReqModal(null)}>
          <p className="muted">{reqModal.target.kind === 'asg' ? 'This autoscaling group' : reqModal.target.kind === 'application' ? 'This application' : 'This machine'} requires approval for {protocolName(reqModal.protocol)}. Say why and for how long; an administrator approves before you can {reqModal.target.kind === 'application' ? 'open it' : 'connect'}.</p>
          <form onSubmit={(e) => void submitRequest(e)}>
            <Field label="Reason">
              <textarea id="req-reason" autoFocus value={reqForm.reason} onChange={(e) => setReqForm({ ...reqForm, reason: e.target.value })} required placeholder="What you need to do" />
            </Field>
            <Field label="Duration (minutes)" hint="Capped by the policy">
              <input id="req-minutes" type="number" min={1} value={reqForm.minutes} onChange={(e) => setReqForm({ ...reqForm, minutes: Number(e.target.value) })} required />
            </Field>
            <div className="actions">
              <button type="button" className="btn" onClick={() => setReqModal(null)}>Cancel</button>
              <button type="submit" className="btn primary" disabled={busy === 'request'}>Request access</button>
            </div>
          </form>
        </Modal>
      )}

      {prompt && (
        <Modal title={`Credentials for ${prompt.target.name}`} onClose={closePrompt}>
          <p className="muted">Sent to the machine; not stored.</p>
          {promptErr && <Alert tone="danger" onDismiss={() => setPromptErr('')}>{promptErr}</Alert>}
          <form
            onSubmit={(e) => {
              e.preventDefault()
              const withKey = prompt.protocol === 'ssh' && cred.method === 'key'
              void connect(prompt.target, {
                ...prompt.body,
                credential: withKey
                  ? { username: cred.username, private_key: cred.key, ...(cred.passphrase ? { private_key_passphrase: cred.passphrase } : {}) }
                  : { username: cred.username, password: cred.password },
              })
            }}
          >
            <Field label="Username">
              <input id="cred-user" autoFocus value={cred.username} onChange={(e) => setCred({ ...cred, username: e.target.value })} required />
            </Field>
            {prompt.protocol === 'ssh' && (
              <div className="actions" role="radiogroup" aria-label="Sign in with" style={{ marginBottom: 8 }}>
                {(
                  [
                    ['password', 'Password'],
                    ['key', 'Private key'],
                  ] as const
                ).map(([m, label]) => (
                  <span key={m} className="field inline" style={{ margin: 0 }}>
                    <input id={`cred-method-${m}`} type="radio" name="cred-method" checked={cred.method === m} onChange={() => setCred({ ...cred, method: m })} />
                    <label htmlFor={`cred-method-${m}`}>{label}</label>
                  </span>
                ))}
              </div>
            )}
            {prompt.protocol === 'ssh' && cred.method === 'key' ? (
              <>
                <Field label="Private key" hint="OpenSSH, PKCS#8 or PKCS#1">
                  <textarea id="cred-key" className="mono" value={cred.key} onChange={(e) => setCred({ ...cred, key: e.target.value })} required spellCheck={false} autoComplete="off" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" />
                </Field>
                <div className="actions" style={{ marginTop: -6, marginBottom: 10 }}>
                  <input id="cred-key-file" type="file" hidden onChange={readKeyFile} />
                  <button type="button" className="btn sm" onClick={() => document.getElementById('cred-key-file')?.click()}>Choose key file…</button>
                </div>
                <Field label="Passphrase" hint="If the key has one">
                  <input id="cred-passphrase" type="password" autoComplete="off" value={cred.passphrase} onChange={(e) => setCred({ ...cred, passphrase: e.target.value })} />
                </Field>
              </>
            ) : (
              <Field label="Password">
                <input id="cred-pass" type="password" value={cred.password} onChange={(e) => setCred({ ...cred, password: e.target.value })} required />
              </Field>
            )}
            <div className="actions">
              <button type="button" className="btn" onClick={closePrompt}>Cancel</button>
              <button type="submit" className="btn primary" disabled={busy !== ''}>Connect</button>
            </div>
          </form>
        </Modal>
      )}
    </>
  )
}
