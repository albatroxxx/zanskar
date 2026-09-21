import { useEffect, useState } from 'react'
import { api, ApiError, errorMessage } from '../../api/client'
import type { ConnectResponse, Page, ReachableInstance } from '../../api/types'
import { Alert, Modal } from '../../components/ui'

/** Relative age of an ISO timestamp, e.g. "12 min ago". */
export function fmtAgo(iso?: string | null): string {
  if (!iso) return ''
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)} min ago`
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`
  return `${Math.floor(s / 86400)} d ago`
}

/**
 * FailoverDialog is shown when a session on an autoscaling instance ends with
 * target_lost. It offers the healthy pool and never switches on its own. When
 * the pool is empty, only Exit remains.
 */
export function FailoverDialog({ sessionId, asgId, protocol, lostLabel, onExit, onSwitched }: {
  sessionId: string
  asgId: string
  protocol: string
  lostLabel?: string
  onExit: () => void
  onSwitched: (res: ConnectResponse) => void
}) {
  const [instances, setInstances] = useState<ReachableInstance[] | null>(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState('')
  const [reload, setReload] = useState(0)
  const load = () => setReload((n) => n + 1)

  useEffect(() => {
    let cancelled = false
    api
      .get<Page<ReachableInstance>>(`/me/autoscaling-groups/${encodeURIComponent(asgId)}/instances`)
      .then((p) => {
        if (!cancelled) setInstances(p.items)
      })
      .catch((e) => {
        if (cancelled) return
        setErr(errorMessage(e))
        setInstances([])
      })
    return () => {
      cancelled = true
    }
  }, [asgId, reload])

  const switchTo = async (instanceId?: string) => {
    setBusy(instanceId ?? 'newest')
    setErr('')
    try {
      const res = await api.post<ConnectResponse>(`/sessions/${encodeURIComponent(sessionId)}/failover`, instanceId ? { asg_instance_id: instanceId } : {})
      onSwitched(res)
    } catch (e) {
      if (e instanceof ApiError && e.code === 'no_healthy_instances') {
        setInstances([])
        setErr('')
      } else if (e instanceof ApiError && e.code === 'instance_unhealthy') {
        setErr('That instance is no longer healthy. Pick another.')
        load()
      } else {
        setErr(errorMessage(e))
      }
    } finally {
      setBusy('')
    }
  }

  const empty = instances !== null && instances.length === 0

  return (
    <Modal title={empty ? 'No healthy instances' : 'Instance lost'} onClose={onExit} width={560}>
      <p>
        {lostLabel ? `${lostLabel} left the healthy pool. ` : 'The instance you were on left the healthy pool. '}
        {empty ? 'The group has no healthy instance to switch to right now.' : `Switch to another instance in this group over ${protocol.toUpperCase()}, or exit.`}
      </p>
      {err && <Alert tone="danger">{err}</Alert>}
      {instances === null && <p className="muted">Loading healthy instances…</p>}
      {instances && instances.length > 0 && (
        <div className="failover-list">
          {instances.map((i) => (
            <div key={i.id} className="failover-row">
              <div>
                <span className="mono">{i.instance_id}</span>
                <span className="muted"> · {i.availability_zone} · launched {fmtAgo(i.launched_at)}</span>
              </div>
              <button id={`fo-${i.id}`} className="btn sm" disabled={busy !== ''} onClick={() => void switchTo(i.id)}>
                {busy === i.id ? 'Switching…' : 'Switch'}
              </button>
            </div>
          ))}
        </div>
      )}
      <div className="actions" style={{ justifyContent: 'space-between' }}>
        <a href="#refresh" onClick={(e) => { e.preventDefault(); load() }} className="muted">Refresh</a>
        <span>
          <button className="btn" onClick={onExit} disabled={busy !== ''}>Exit</button>
          {!empty && instances && (
            <button id="fo-newest" className="btn primary" style={{ marginLeft: 8 }} disabled={busy !== ''} onClick={() => void switchTo()}>
              {busy === 'newest' ? 'Switching…' : 'Switch to newest'}
            </button>
          )}
        </span>
      </div>
    </Modal>
  )
}
