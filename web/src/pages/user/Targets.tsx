import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, ApiError, errorMessage } from '../../api/client'
import type { ConnectResponse, Page, Protocol, ReachableInstance, ReachableTarget } from '../../api/types'
import { Alert, Badge, Empty, Field, Modal, PageHead, Tags } from '../../components/ui'
import { fmtAgo } from './Failover'

const terminalProtocols: Protocol[] = ['ssh', 'winrm']
const desktopProtocols: Protocol[] = ['rdp', 'vnc']
const databaseProtocols: Protocol[] = ['database']

function pick(t: ReachableTarget, family: Protocol[]): Protocol | null {
  for (const p of family) if (t.allowed_protocols.includes(p) && (t.capabilities.length === 0 || t.capabilities.includes(p))) return p
  return null
}

/** Body of POST /connect: exactly one of target_id, asg_id, asg_instance_id. */
interface ConnectBody {
  target_id?: string
  asg_id?: string
  asg_instance_id?: string
  protocol: Protocol
  credential?: { username: string; password: string }
}

export function Targets() {
  const nav = useNavigate()
  const [items, setItems] = useState<ReachableTarget[] | null>(null)
  const [err, setErr] = useState('')
  const [tab, setTab] = useState<'static' | 'asg'>('static')
  const [prompt, setPrompt] = useState<{ target: ReachableTarget; protocol: Protocol; body: ConnectBody } | null>(null)
  const [chooser, setChooser] = useState<{ group: ReachableTarget; protocol: Protocol; instances: ReachableInstance[] | null } | null>(null)
  const [cred, setCred] = useState({ username: '', password: '' })
  const [busy, setBusy] = useState('')

  useEffect(() => {
    api
      .get<Page<ReachableTarget>>('/me/targets')
      .then((p) => setItems(p.items))
      .catch((e) => setErr(errorMessage(e)))
  }, [])

  const connect = async (target: ReachableTarget, body: ConnectBody) => {
    setBusy(target.id + body.protocol)
    setErr('')
    try {
      const res = await api.post<ConnectResponse>('/connect', body)
      setPrompt(null)
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
      if (e instanceof ApiError && e.code === 'credential_required') {
        setPrompt({ target, protocol: body.protocol, body })
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

  const kindOf = (t: ReachableTarget) => t.kind ?? 'target'
  const statics = items?.filter((t) => kindOf(t) === 'target') ?? null
  const groups = items?.filter((t) => kindOf(t) === 'asg') ?? null

  const protoButtons = (t: ReachableTarget, onPick: (p: Protocol) => void) => {
    const term = pick(t, terminalProtocols)
    const desk = pick(t, desktopProtocols)
    const db = pick(t, databaseProtocols)
    const notReady = !t.host_key_ready && term === 'ssh'
    return (
      <>
        <td>
          <button className="btn sm primary" disabled={!term || notReady || busy === t.id + term} onClick={() => term && onPick(term)} title={term ? term.toUpperCase() : 'no terminal protocol allowed'}>
            {term ? term.toUpperCase() : '—'}
          </button>
        </td>
        <td>
          <button className="btn sm proto-desktop" disabled={!desk || busy === t.id + desk} onClick={() => desk && onPick(desk)} title={desk ? desk.toUpperCase() : 'no desktop protocol allowed'}>
            {desk ? desk.toUpperCase() : '—'}
          </button>
        </td>
        <td>
          <button className="btn sm proto-database" disabled={!db || busy === t.id + db} onClick={() => db && onPick(db)} title={db ? (t.engine ? t.engine + ' database' : 'database') : 'no database access allowed'}>
            {db ? (t.engine || 'database').toUpperCase() : '—'}
          </button>
        </td>
      </>
    )
  }

  return (
    <>
      <PageHead title="Targets" lead="Machines your access policies let you reach. Terminal opens SSH or PowerShell; Desktop opens RDP or VNC when the machine offers it." />
      {err && <Alert tone="danger">{err}</Alert>}
      <div className="tabs">
        <button className={tab === 'static' ? 'active' : ''} onClick={() => setTab('static')}>Static</button>
        <button className={tab === 'asg' ? 'active' : ''} onClick={() => setTab('asg')}>Autoscaling</button>
      </div>

      {tab === 'static' && (
        <div className="card table-wrap">
          {statics === null ? (
            <Empty>Loading…</Empty>
          ) : statics.length === 0 ? (
            <Empty>No targets are assigned to you yet. Ask an administrator for access.</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>OS</th>
                  <th>Tags</th>
                  <th>Terminal</th>
                  <th>Desktop</th>
                  <th>Database</th>
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
                            <Badge tone="warn">awaiting host key trust</Badge>
                          </>
                        )}
                      </td>
                      <td>{t.os_family}</td>
                      <td><Tags tags={t.tags} /></td>
                      {protoButtons(t, (p) => void connect(t, { target_id: t.id, protocol: p }))}
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
            <Empty>No autoscaling groups are assigned to you. Ask an administrator for access.</Empty>
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
                  <th>Database</th>
                </tr>
              </thead>
              <tbody>
                {groups.map((g) => {
                  const healthy = g.healthy_count ?? 0
                  const total = g.instance_count ?? 0
                  return (
                    <tr key={g.id}>
                      <td><strong>{g.name}</strong></td>
                      <td>{g.os_family}</td>
                      <td><Tags tags={g.tags} /></td>
                      <td>
                        <Badge tone={healthy === 0 ? 'danger' : 'ok'}>{healthy} / {total}</Badge>
                      </td>
                      {protoButtons(g, (p) => void loadInstances(g, p))}
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
          <p className="muted">Instances come and go with scaling. Connect to the newest healthy one, or pick a specific instance.</p>
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

      {prompt && (
        <Modal title={`Credentials for ${prompt.target.name}`} onClose={() => setPrompt(null)}>
          <p className="muted">This target uses your own account. Zanskar forwards these to the machine and does not store them.</p>
          <form
            onSubmit={(e) => {
              e.preventDefault()
              void connect(prompt.target, { ...prompt.body, credential: cred })
            }}
          >
            <Field label="Username">
              <input id="cred-user" autoFocus value={cred.username} onChange={(e) => setCred({ ...cred, username: e.target.value })} required />
            </Field>
            <Field label="Password">
              <input id="cred-pass" type="password" value={cred.password} onChange={(e) => setCred({ ...cred, password: e.target.value })} required />
            </Field>
            <div className="actions">
              <button type="button" className="btn" onClick={() => setPrompt(null)}>Cancel</button>
              <button className="btn primary" disabled={busy !== ''}>Connect</button>
            </div>
          </form>
        </Modal>
      )}
    </>
  )
}
