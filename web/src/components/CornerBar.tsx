import { useEffect, useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { api, errorMessage } from '../api/client'
import { fmtTime } from '../api/format'
import type { HostStatus, SystemStatus, UpdateStatus } from '../api/types'
import { ConsoleCLI } from './ConsoleCLI'
import { BellIcon, GearIcon } from './icons'
import { Alert, Badge, Field, Modal } from './ui'

/** CornerBar is the admin console's top-right strip: the bell (is there a
 *  newer release), the gear (restart, reboot, stop — ADR 0032) and the
 *  command line (ADR 0027), one row of bare glyphs. */
export function CornerBar() {
  return (
    <div className="corner">
      <UpdateBell />
      <GearMenu />
      <ConsoleCLI />
    </div>
  )
}

/** upgradeHint says how this deployment takes a new release. The install
 *  from the console itself is the update unit's; until it ships, the words
 *  are the manual step. */
function upgradeHint(supervisor?: string): string {
  switch (supervisor) {
    case 'systemd':
      return 'Install the new package on the host, then restart the gateway.'
    case 'kubernetes':
      return 'Roll the deployment to the new image tag.'
    default:
      return 'Replace the binary or image, then restart the gateway.'
  }
}

function UpdateBell() {
  const [st, setSt] = useState<UpdateStatus | null>(null)
  const [sys, setSys] = useState<SystemStatus | null>(null)
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  // The install form (ADR 0032): the same guards as a reboot.
  const [installing, setInstalling] = useState(false)
  const [host, setHost] = useState<HostStatus | null>(null)
  const [wait, setWait] = useState(15)
  const [confirm, setConfirm] = useState('')
  const [code, setCode] = useState('')
  const [done, setDone] = useState('')

  useEffect(() => {
    api.get<UpdateStatus>('/admin/system/update').then(setSt).catch(() => setSt(null))
  }, [])

  const openPanel = () => {
    setOpen(true)
    setErr('')
    setDone('')
    setInstalling(false)
    api.get<SystemStatus>('/admin/system/status').then(setSys).catch(() => setSys(null))
    api.get<UpdateStatus>('/admin/system/update').then(setSt).catch(() => {})
  }
  const startInstall = () => {
    setInstalling(true)
    setErr('')
    setConfirm('')
    setCode('')
    api.get<HostStatus>('/admin/system/host').then(setHost).catch(() => setHost(null))
  }
  const needsCode = host !== null && !host.mfa_fresh
  const install = async (e: FormEvent) => {
    e.preventDefault()
    if (!st?.latest) return
    setBusy(true)
    setErr('')
    try {
      if (needsCode) await api.post('/auth/mfa/step-up', { code: code.trim() })
      await api.post('/admin/system/update/install', { version: st.latest, wait_minutes: wait, confirm: confirm.trim() })
      setDone(`Installing ${st.latest} once live sessions have finished; the gateway restarts when the installer is done.`)
      setInstalling(false)
    } catch (e2) {
      setErr(errorMessage(e2))
    } finally {
      setBusy(false)
    }
  }
  const check = async () => {
    setBusy(true)
    setErr('')
    try {
      setSt(await api.post<UpdateStatus>('/admin/system/update/check'))
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }
  const newer = !!st?.newer
  return (
    <>
      <button type="button" className="corner-btn" aria-label={newer ? `Zanskar ${st?.latest} is available` : 'Updates'} title={newer ? `Zanskar ${st?.latest} is available` : 'Updates'} onClick={openPanel}>
        <BellIcon />
        {newer && <span className="corner-dot" aria-hidden="true" />}
      </button>
      {open && (
        <Modal title="Updates" onClose={() => setOpen(false)} width={460}>
          {st && (
            <dl className="kv">
              <dt>Running</dt>
              <dd className="mono">{st.current}</dd>
              <dt>Latest</dt>
              <dd>
                {st.latest ? <span className="mono">{st.latest}</span> : <span className="muted">not known yet</span>}
                {newer && (
                  <>
                    {' '}
                    <Badge tone="accent">new</Badge>
                  </>
                )}
              </dd>
              {st.notes_url && (
                <>
                  <dt>Notes</dt>
                  <dd>
                    <a href={st.notes_url} target="_blank" rel="noreferrer">
                      Release notes
                    </a>
                  </dd>
                </>
              )}
              <dt>Checked</dt>
              <dd>
                {st.checked_at ? fmtTime(st.checked_at) : 'not yet'}
                {st.error && <span className="muted"> · {st.error}</span>}
              </dd>
            </dl>
          )}
          {st && !st.enabled && (
            <p className="muted">
              Daily checks are off; turn them on in <Link to="/admin/settings">Settings</Link>.
            </p>
          )}
          {st?.install && (
            <Alert tone={st.install.state === 'failed' ? 'danger' : st.install.state === 'done' ? 'ok' : undefined}>
              Installer, {st.install.version}: {st.install.message} ({fmtTime(st.install.at)})
            </Alert>
          )}
          {done && <Alert tone="ok">{done}</Alert>}
          {newer && !st?.installable && <p>{upgradeHint(sys?.supervisor)}</p>}
          {err && <Alert tone="danger">{err}</Alert>}
          {installing && st?.latest ? (
            <form onSubmit={(e) => void install(e)}>
              <h3 style={{ marginBottom: 8 }}>Install {st.latest}</h3>
              <Field label="Let live sessions finish for" hint="Minutes; 0 ends them now.">
                <input id="bell-wait" type="number" min={0} max={240} value={wait} onChange={(e) => setWait(Number(e.target.value))} />
              </Field>
              {host && (
                <Field label={`Type the hostname to confirm: ${host.hostname}`}>
                  <input id="bell-confirm" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" />
                </Field>
              )}
              {needsCode && (
                <Field label="Authenticator code" hint={`This action asks for a code proved within the last ${host?.step_up_minutes ?? 5} minutes.`}>
                  <input id="bell-code" value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" />
                </Field>
              )}
              <div className="actions">
                <button type="button" className="btn ghost" onClick={() => setInstalling(false)} disabled={busy}>
                  Back
                </button>
                <button type="submit" className="btn primary" disabled={busy || !confirm.trim() || (needsCode && !code.trim())}>
                  {busy ? 'Working…' : 'Install'}
                </button>
              </div>
            </form>
          ) : (
            <div className="actions">
              <button type="button" className="btn" onClick={() => void check()} disabled={busy}>
                {busy ? 'Checking…' : 'Check now'}
              </button>
              {newer && st?.installable && (
                <button type="button" className="btn primary" onClick={startInstall} disabled={busy}>
                  Update now
                </button>
              )}
            </div>
          )}
        </Modal>
      )}
    </>
  )
}

type HostAction = 'restart' | 'reboot' | 'poweroff'

const actionWords: Record<HostAction, { title: string; verb: string; done: string }> = {
  restart: { title: 'Restart gateway', verb: 'Restart', done: 'Restarting after the drain.' },
  reboot: { title: 'Reboot host', verb: 'Reboot', done: 'Rebooting the host after the drain.' },
  poweroff: { title: 'Stop host', verb: 'Stop', done: 'Powering the host off after the drain.' },
}

function GearMenu() {
  const [open, setOpen] = useState(false)
  const [host, setHost] = useState<HostStatus | null>(null)
  const [action, setAction] = useState<HostAction | null>(null)
  const [wait, setWait] = useState(15)
  const [confirm, setConfirm] = useState('')
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [done, setDone] = useState('')

  const load = () => api.get<HostStatus>('/admin/system/host').then(setHost).catch(() => setHost(null))
  const openPanel = () => {
    setOpen(true)
    setAction(null)
    setErr('')
    setDone('')
    void load()
  }
  const pick = (a: HostAction) => {
    setAction(a)
    setErr('')
    setDone('')
    setConfirm('')
    setCode('')
  }
  // A host action needs a recent authenticator code on the session; the
  // restart of the process alone does not (it is what it always was).
  const needsCode = action !== null && action !== 'restart' && host !== null && !host.mfa_fresh

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!action) return
    setBusy(true)
    setErr('')
    try {
      if (needsCode) await api.post('/auth/mfa/step-up', { code: code.trim() })
      const body = action === 'restart' ? { wait_minutes: wait } : { wait_minutes: wait, confirm: confirm.trim() }
      await api.post(`/admin/system/${action}`, body)
      setDone(actionWords[action].done)
      setAction(null)
      setCode('')
      setConfirm('')
    } catch (e2) {
      setErr(errorMessage(e2))
    } finally {
      setBusy(false)
    }
  }

  const hostOnly = action === 'reboot' || action === 'poweroff'
  return (
    <>
      <button type="button" className="corner-btn" aria-label="Gateway actions" title="Gateway actions" onClick={openPanel}>
        <GearIcon />
      </button>
      {open && (
        <Modal title="Gateway" onClose={() => setOpen(false)} width={480}>
          {done && <Alert tone="ok">{done}</Alert>}
          {err && <Alert tone="danger">{err}</Alert>}
          {!action ? (
            <div className="actions" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
              <button type="button" className="btn" onClick={() => pick('restart')}>
                Restart gateway
              </button>
              <button type="button" className="btn" onClick={() => pick('reboot')} disabled={host !== null && !host.available} title={host?.reason}>
                Reboot host
              </button>
              <button type="button" className="btn danger" onClick={() => pick('poweroff')} disabled={host !== null && !host.available} title={host?.reason}>
                Stop host
              </button>
              {host && !host.available && <p className="muted" style={{ margin: 0 }}>{host.reason}</p>}
            </div>
          ) : (
            <form onSubmit={(e) => void submit(e)}>
              <h3 style={{ marginBottom: 8 }}>{actionWords[action].title}</h3>
              {action === 'poweroff' && (
                <Alert tone="warn">Nothing here can start a stopped machine. Starting it again needs the host or the cloud console.</Alert>
              )}
              <Field label="Let live sessions finish for" hint="Minutes; 0 ends them now.">
                <input id="gear-wait" type="number" min={0} max={240} value={wait} onChange={(e) => setWait(Number(e.target.value))} />
              </Field>
              {hostOnly && host && (
                <Field label={`Type the hostname to confirm: ${host.hostname}`}>
                  <input id="gear-confirm" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" />
                </Field>
              )}
              {needsCode && (
                <Field label="Authenticator code" hint={`This action asks for a code proved within the last ${host?.step_up_minutes ?? 5} minutes.`}>
                  <input id="gear-code" value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" />
                </Field>
              )}
              <div className="actions">
                <button type="button" className="btn ghost" onClick={() => setAction(null)} disabled={busy}>
                  Back
                </button>
                <button type="submit" className={'btn ' + (action === 'poweroff' ? 'danger' : 'primary')} disabled={busy || (hostOnly && !confirm.trim()) || (needsCode && !code.trim())}>
                  {busy ? 'Working…' : actionWords[action].verb}
                </button>
              </div>
            </form>
          )}
        </Modal>
      )}
    </>
  )
}
