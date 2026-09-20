import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, ApiError, errorMessage } from '../../api/client'
import type { ConnectResponse, Page, Protocol, ReachableTarget } from '../../api/types'
import { Alert, Badge, Empty, Field, Modal, PageHead, Tags } from '../../components/ui'

const terminalProtocols: Protocol[] = ['ssh', 'winrm']
const desktopProtocols: Protocol[] = ['rdp', 'vnc']

function pick(t: ReachableTarget, family: Protocol[]): Protocol | null {
  for (const p of family) if (t.allowed_protocols.includes(p) && (t.capabilities.length === 0 || t.capabilities.includes(p))) return p
  return null
}

export function Targets() {
  const nav = useNavigate()
  const [items, setItems] = useState<ReachableTarget[] | null>(null)
  const [err, setErr] = useState('')
  const [tab, setTab] = useState<'static' | 'asg'>('static')
  const [prompt, setPrompt] = useState<{ target: ReachableTarget; protocol: Protocol } | null>(null)
  const [cred, setCred] = useState({ username: '', password: '' })
  const [busy, setBusy] = useState('')

  useEffect(() => {
    api
      .get<Page<ReachableTarget>>('/me/targets')
      .then((p) => setItems(p.items))
      .catch((e) => setErr(errorMessage(e)))
  }, [])

  const connect = async (target: ReachableTarget, protocol: Protocol, credential?: { username: string; password: string }) => {
    setBusy(target.id + protocol)
    setErr('')
    try {
      const res = await api.post<ConnectResponse>('/connect', { target_id: target.id, protocol, ...(credential ? { credential } : {}) })
      setPrompt(null)
      nav(res.ws_path === '/ws/desktop' ? '/desktop' : '/terminal', { state: { ticket: res.ticket, ws_path: res.ws_path, target: target.name, protocol } })
    } catch (e) {
      if (e instanceof ApiError && e.code === 'credential_required') {
        setPrompt({ target, protocol })
      } else {
        setErr(errorMessage(e))
      }
    } finally {
      setBusy('')
    }
  }

  return (
    <>
      <PageHead title="Targets" lead="Machines your access policies let you reach. Terminal opens SSH or PowerShell; Desktop opens RDP or VNC when the machine offers it." />
      {err && <Alert tone="danger">{err}</Alert>}
      <div className="tabs">
        <button className={tab === 'static' ? 'active' : ''} onClick={() => setTab('static')}>Static</button>
        <button className={tab === 'asg' ? 'active' : ''} onClick={() => setTab('asg')}>Autoscaling</button>
      </div>
      {tab === 'asg' && <Empty>Autoscaling groups arrive in Phase 3.</Empty>}
      {tab === 'static' && (
        <div className="card table-wrap">
          {items === null ? (
            <Empty>Loading…</Empty>
          ) : items.length === 0 ? (
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
                </tr>
              </thead>
              <tbody>
                {items.map((t) => {
                  const term = pick(t, terminalProtocols)
                  const desk = pick(t, desktopProtocols)
                  const notReady = !t.host_key_ready && term === 'ssh'
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
                      <td>
                        <button className="btn sm primary" disabled={!term || notReady || busy === t.id + term} onClick={() => term && void connect(t, term)} title={term ? term.toUpperCase() : 'no terminal protocol allowed'}>
                          {term ? term.toUpperCase() : '—'}
                        </button>
                      </td>
                      <td>
                        <button className="btn sm" disabled={!desk || busy === t.id + desk} onClick={() => desk && void connect(t, desk)} title={desk ? desk.toUpperCase() : 'no desktop protocol allowed'}>
                          {desk ? desk.toUpperCase() : '—'}
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      )}
      {prompt && (
        <Modal title={`Credentials for ${prompt.target.name}`} onClose={() => setPrompt(null)}>
          <p className="muted">This target uses your own account. Zanskar forwards these to the machine and does not store them.</p>
          <form
            onSubmit={(e) => {
              e.preventDefault()
              void connect(prompt.target, prompt.protocol, cred)
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
