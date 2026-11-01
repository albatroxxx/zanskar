import { useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError, api, errorMessage } from '../api/client'
import { fmtTime } from '../api/format'
import type { ConfigResult, HostStatus, SystemStatus, UpdateStatus } from '../api/types'
import { DoneIcon } from './icons'
import { deadlineFor, doneTitle, initialProgress, observe, pacing, progressWatch, stepLabel, stepsFor, type HostAction, type Observation, type Progress, type Start } from './hostAction'
import { Alert, Field, Modal } from './ui'

const titles: Record<HostAction, { title: string; verb: string; danger?: boolean }> = {
  update: { title: 'Update', verb: 'Install' },
  restart: { title: 'Restart gateway', verb: 'Restart' },
  reboot: { title: 'Reboot host', verb: 'Reboot' },
  poweroff: { title: 'Stop host', verb: 'Stop', danger: true },
  config: { title: 'Change install settings', verb: 'Apply and restart' },
}

/** BootChange is a change to the environment file the root helper applies (ADR 0020, amended 2026-10-30). */
export interface BootChange {
  values?: Record<string, string>
  tls_mode?: 'managed' | 'proxy'
  /** The change in words, shown above the form. */
  summary: string
}

/**
 * HostActionDialog asks for an update, a restart, a reboot or a stop (ADR
 * 0032), then follows it to the end: the drain, the install or restart, the
 * gateway away, and back (2026-10-30: the dialog used to say "Installing…"
 * and stop, and the admin refreshed and ran `version` to learn the outcome).
 * It ends with a green tick or the reason it did not happen.
 */
export function HostActionDialog({ action, version, change, onClose }: { action: HostAction; version?: string; change?: BootChange; onClose: () => void }) {
  const [host, setHost] = useState<HostStatus | null>(null)
  const [wait, setWait] = useState(15)
  const [confirm, setConfirm] = useState('')
  const [code, setCode] = useState('')
  // The minutes of the request in flight, null when none is.
  const [busy, setBusy] = useState<number | null>(null)
  const [err, setErr] = useState('')
  const [start, setStart] = useState<Start | null>(null)
  const [progress, setProgress] = useState<Progress>(initialProgress)
  const [live, setLive] = useState<number | null>(null)
  const words = titles[action]

  useEffect(() => {
    api.get<HostStatus>('/admin/system/host').then(setHost).catch(() => setHost(null))
    api.get<SystemStatus>('/admin/system/status').then((s) => setLive(s.live_sessions)).catch(() => setLive(null))
  }, [])

  // While the view follows an action, the restart banner leaves the page alone.
  useEffect(() => {
    if (!start) return
    progressWatch.begin()
    return () => progressWatch.end()
  }, [start])

  const latest = useRef(progress)
  useEffect(() => {
    latest.current = progress
  }, [progress])
  useEffect(() => {
    if (!start) return
    let stop = false
    const tick = async () => {
      const o: Observation = { at: Date.now() }
      try {
        o.status = await api.get<SystemStatus>('/admin/system/status')
        if (start.action === 'update') o.update = await api.get<UpdateStatus>('/admin/system/update').catch(() => null)
        if (start.action === 'config') o.config = await api.get<ConfigResult>('/admin/settings/boot/result').catch(() => null)
      } catch (e) {
        o.error = e instanceof ApiError && e.status === 401 ? 'signed_out' : 'offline'
      }
      if (stop) return
      const next = observe(start, latest.current, o)
      setProgress(next)
      if (next.state === 'running') timer = setTimeout(() => void tick(), pacing.pollMs)
    }
    let timer = setTimeout(() => void tick(), pacing.pollMs)
    return () => {
      stop = true
      clearTimeout(timer)
    }
  }, [start])

  const needsCode = action !== 'restart' && host !== null && !host.mfa_fresh
  const typed = action !== 'restart' && action !== 'config'
  const ready = busy === null && !(typed && !confirm.trim()) && !(needsCode && !code.trim())
  /** run asks for the action, letting live sessions finish for minutes (0 ends them now). */
  const run = async (minutes: number) => {
    setBusy(minutes)
    setErr('')
    try {
      const before = await api.get<SystemStatus>('/admin/system/status')
      const installBefore = action === 'update' ? (await api.get<UpdateStatus>('/admin/system/update').catch(() => null))?.install?.at : undefined
      if (needsCode) await api.post('/auth/mfa/step-up', { code: code.trim() })
      const body = typed ? { wait_minutes: minutes, confirm: confirm.trim() } : { wait_minutes: minutes }
      let target = version
      if (action === 'update') await api.post('/admin/system/update/install', { version, ...body })
      else if (action === 'config') target = (await api.post<{ id: string }>('/admin/settings/boot', { values: change?.values, tls_mode: change?.tls_mode, wait_minutes: minutes })).id
      else await api.post(`/admin/system/${action}`, body)
      const now = Date.now()
      setProgress(initialProgress)
      setStart({ action, target, startedAt: before.started_at, installBefore, at: now, deadline: deadlineFor(action, minutes, now) })
    } catch (e2) {
      setErr(errorMessage(e2))
    } finally {
      setBusy(null)
    }
  }
  const submit = (e: FormEvent) => {
    e.preventDefault()
    void run(wait)
  }
  const cancel = async () => {
    try {
      await api.del('/admin/system/restart')
      setProgress((p) => ({ ...p, state: 'cancelled' }))
    } catch (e2) {
      setErr(errorMessage(e2))
    }
  }

  const title = action === 'update' ? `Update to ${version}` : words.title
  if (start) {
    const steps = stepsFor[action]
    const at = steps.indexOf(progress.step)
    return (
      <Modal title={title} onClose={onClose} width={480}>
        {progress.state === 'done' ? (
          <div className="action-done" role="status">
            <DoneIcon />
            <div>
              <strong>{doneTitle(start)}</strong>
              {action === 'poweroff' && <p className="muted">Start it again from the host or the cloud console.</p>}
            </div>
          </div>
        ) : (
          <ol className="action-steps" aria-live="polite">
            {steps.map((s, i) => {
              const state = progress.state === 'failed' && i === at ? 'failed' : i < at ? 'done' : i === at && progress.state === 'running' ? 'now' : 'todo'
              return (
                <li key={s} className={'action-step ' + state} aria-current={state === 'now' ? 'step' : undefined}>
                  <span className="action-mark" aria-hidden="true" />
                  <span>
                    {stepLabel(s, start)}
                    {state === 'now' && s === 'drain' && progress.live ? (
                      <span className="muted">
                        {' '}
                        · {progress.live} live{progress.until ? `, until ${fmtTime(progress.until)}` : ''}
                      </span>
                    ) : null}
                    {state === 'now' && s === 'install' && progress.message ? <span className="muted"> · {progress.message}</span> : null}
                  </span>
                </li>
              )
            })}
          </ol>
        )}
        {progress.state === 'failed' && <Alert tone="danger">{progress.message}</Alert>}
        {progress.state === 'cancelled' && <Alert tone="ok">Cancelled; the gateway carries on.</Alert>}
        {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
        <div className="actions">
          {progress.state === 'running' && progress.step === 'drain' && (
            <button type="button" className="btn ghost" onClick={() => void cancel()}>
              Cancel {action === 'poweroff' ? 'stop' : action === 'config' ? 'change' : action}
            </button>
          )}
          {progress.state === 'done' && action === 'update' ? (
            <button type="button" className="btn primary" onClick={() => window.location.reload()}>
              Reload console
            </button>
          ) : (
            <button type="button" className={'btn' + (progress.state === 'running' ? ' ghost' : ' primary')} onClick={onClose}>
              Close
            </button>
          )}
        </div>
      </Modal>
    )
  }
  return (
    <Modal title={title} onClose={onClose} width={480}>
      {action === 'poweroff' && <Alert tone="warn">Starting it again needs the host or the cloud console.</Alert>}
      {change && <p className="config-change">{change.summary}</p>}
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      <form onSubmit={submit}>
        <Field label="Let live sessions finish for" hint={`Minutes; 0 ends them now.${live === null ? '' : live === 0 ? ' None live.' : ` ${live} live.`}`}>
          <input id="action-wait" type="number" min={0} max={240} value={wait} onChange={(e) => setWait(Number(e.target.value))} />
        </Field>
        {typed && host && (
          <Field label={`Type the hostname to confirm: ${host.hostname}`}>
            <input id="action-confirm" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" />
          </Field>
        )}
        {needsCode && (
          <Field label="Authenticator code" hint={`Covers host actions for ${host?.step_up_minutes ?? 5} minutes`}>
            <input id="action-code" value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" />
          </Field>
        )}
        {/* "<verb> now" skips the wait without typing 0 (2026-11-01); it
            asks for the same hostname and code. With the wait already 0, the
            main button says it. */}
        <div className="actions">
          <button type="button" className="btn ghost" onClick={onClose} disabled={busy !== null}>
            Cancel
          </button>
          {wait > 0 && (
            <button type="button" className="btn" onClick={() => void run(0)} disabled={!ready}>
              {busy === 0 ? 'Working…' : `${words.verb} now`}
            </button>
          )}
          <button type="submit" className={'btn ' + (words.danger ? 'danger' : 'primary')} disabled={!ready}>
            {busy !== null && busy === wait ? 'Working…' : wait > 0 ? words.verb : `${words.verb} now`}
          </button>
        </div>
      </form>
    </Modal>
  )
}
