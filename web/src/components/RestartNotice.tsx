import { useEffect, useState } from 'react'
import { api, errorMessage } from '../api/client'
import { fmtTime } from '../api/format'
import type { SystemStatus } from '../api/types'
import { Alert, Confirm } from './ui'

const POLL_MS = 30_000
const RECONNECT_MS = 2_000

function supervisorNote(s: SystemStatus['supervisor']) {
  switch (s) {
    case 'systemd':
      return 'systemd starts the service again within a few seconds.'
    case 'kubernetes':
      return 'The pod restarts on its own.'
    default:
      return 'Make sure your process manager restarts the service; without one the gateway stops.'
  }
}

/**
 * RestartNotice is the admin portal's banner for the one thing the console
 * cannot apply live: a boot setting changed in the environment file (ADR
 * 0020). It names the variables that changed (never their values), counts
 * the live sessions a restart would affect, and offers a restart that drains
 * them first. While the gateway is away it polls until a fresh process
 * answers, then reloads.
 */
export function RestartNotice() {
  const [status, setStatus] = useState<SystemStatus | null>(null)
  const [gone, setGone] = useState<string | null>(null) // started_at of the process being replaced
  const [confirming, setConfirming] = useState(false)
  const [wait, setWait] = useState(true)
  const [minutes, setMinutes] = useState(15)
  const [err, setErr] = useState('')

  useEffect(() => {
    let cancelled = false
    const tick = () =>
      api
        .get<SystemStatus>('/admin/system/status')
        .then((s) => {
          if (cancelled) return
          // A different start time is the fresh process: reload for its
          // bundle. Seen either after the server was away, or straight away
          // when the restart was quick enough to fall between two polls.
          if ((gone && s.started_at !== gone) || (status?.draining && s.started_at !== status.started_at)) {
            window.location.reload()
            return
          }
          setStatus(s)
        })
        .catch(() => {
          // The server is away: after a restart request that is expected.
          if (!cancelled && status?.draining) setGone(status.started_at)
        })
    void tick()
    const t = setInterval(tick, gone || status?.draining ? RECONNECT_MS : POLL_MS)
    return () => {
      cancelled = true
      clearInterval(t)
    }
  }, [gone, status?.draining, status?.started_at])

  if (gone) return <Alert tone="warn">Restarting the gateway… this page reloads when it is back.</Alert>
  if (!status) return null
  const env = status.env_file
  const masterKey = env.changed?.includes('ZANSKAR_MASTER_KEY')
  const restart = async (waitMinutes: number) => {
    setErr('')
    try {
      setStatus(await api.post<SystemStatus>('/admin/system/restart', { wait_minutes: waitMinutes }))
    } catch (e) {
      setErr(errorMessage(e))
      throw e
    }
  }
  const cancel = async () => {
    setErr('')
    try {
      setStatus(await api.del<SystemStatus>('/admin/system/restart'))
    } catch (e) {
      setErr(errorMessage(e))
    }
  }
  const sessions = status.live_sessions === 1 ? '1 live session' : `${status.live_sessions} live sessions`

  if (status.draining && status.drain) {
    return (
      <Alert tone="warn">
        <strong>Restarting.</strong>{' '}
        {status.live_sessions > 0
          ? `Waiting for ${sessions} to end, until ${fmtTime(status.drain.deadline)}; any still open then are ended. No new session can start meanwhile.`
          : 'No session is live; the gateway is stopping now.'}{' '}
        {supervisorNote(status.supervisor)}
        {err && <div>{err}</div>}
        <div className="actions" style={{ marginTop: 8 }}>
          {status.live_sessions > 0 && (
            <button className="btn sm danger" onClick={() => void restart(0).catch(() => {})}>End {sessions} and restart now</button>
          )}
          <button className="btn sm" onClick={() => void cancel()}>Cancel restart</button>
        </div>
      </Alert>
    )
  }
  if (env.state === 'unreadable') {
    return (
      <Alert tone="warn">
        <strong>Cannot check {env.path} for changes.</strong> {env.error} Boot settings changed there apply only after a restart, and the console cannot tell you when that is due.
      </Alert>
    )
  }
  if (!status.restart_required) return null
  return (
    <>
      <Alert tone={masterKey ? 'danger' : 'warn'}>
        <strong>Restart required.</strong> {env.changed?.join(', ')} changed in {env.path} after the gateway started ({fmtTime(status.started_at)}). Boot settings apply only to a fresh process.
        {masterKey && (
          <div style={{ marginTop: 6 }}>
            <strong>ZANSKAR_MASTER_KEY differs.</strong> A restart will fail to open every stored secret unless the change came from <code>zanskar key rotate-master</code>. Check before restarting.
          </div>
        )}
        <div className="actions" style={{ marginTop: 8 }}>
          <button className="btn sm primary" onClick={() => setConfirming(true)}>Restart the gateway…</button>
          <span className="muted">{sessions} now. {supervisorNote(status.supervisor)}</span>
        </div>
      </Alert>
      {confirming && (
        <Confirm
          title="Restart the gateway?"
          confirmLabel="Restart"
          danger={!wait || status.live_sessions > 0}
          onClose={() => setConfirming(false)}
          onConfirm={() => restart(wait ? minutes : 0)}
          body={
            <div>
              <p>
                {status.live_sessions > 0 ? `${sessions} would be cut off by an immediate restart.` : 'No session is live, so a restart is quick.'} New sessions are refused until the fresh process is up. {supervisorNote(status.supervisor)}
              </p>
              <p className="field inline">
                <input id="rs-wait" type="radio" name="rs" checked={wait} onChange={() => setWait(true)} />
                <label htmlFor="rs-wait">Wait for live sessions to end, up to</label>
                <input id="rs-min" type="number" min={1} max={240} value={minutes} onChange={(e) => setMinutes(Math.max(1, Math.min(240, Number(e.target.value) || 1)))} style={{ width: 70 }} disabled={!wait} />
                <label htmlFor="rs-min">minutes, then end them</label>
              </p>
              <p className="field inline">
                <input id="rs-now" type="radio" name="rs" checked={!wait} onChange={() => setWait(false)} />
                <label htmlFor="rs-now">End live sessions and restart now</label>
              </p>
              <p className="muted">Users in an ended session see that the gateway is restarting; the session is recorded as ended by a gateway restart. The request is written to the audit log.</p>
            </div>
          }
        />
      )}
    </>
  )
}
