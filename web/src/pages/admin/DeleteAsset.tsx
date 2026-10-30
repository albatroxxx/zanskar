import { useEffect, useState, type FormEvent } from 'react'
import { api, errorMessage } from '../../api/client'
import type { AssetUsage } from '../../api/types'
import { useSubmit } from '../../components/submit'
import { Alert, Field, Modal } from '../../components/ui'

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`

/**
 * DeleteAsset deletes a target or an autoscaling group after saying what
 * else goes with it (ADR 0036, amended 2026-10-30): the policies it is taken
 * out of, the grants and policies that leaves empty, the live sessions that
 * end and the access requests that close. Deleting was refused while any
 * policy named the asset, so an administrator edited every one first; the
 * name typed back stands in for that care.
 */
export function DeleteAsset({ name, path, onClose, onDeleted }: { name: string; path: string; onClose: () => void; onDeleted: () => void }) {
  const [usage, setUsage] = useState<AssetUsage | null>(null)
  const [loadErr, setLoadErr] = useState('')
  const [typed, setTyped] = useState('')
  const { busy, err, submit } = useSubmit()

  useEffect(() => {
    api.get<AssetUsage>(`${path}/usage`).then(setUsage).catch((e) => setLoadErr(errorMessage(e)))
  }, [path])

  const emptied = usage ? usage.policies.reduce((n, p) => n + p.grants_removed, 0) : 0
  const left = usage ? usage.policies.filter((p) => p.no_grants_left).map((p) => p.name) : []
  const effects: string[] = []
  if (usage) {
    if (usage.policies.length) effects.push(`Removes it from ${plural(usage.policies.length, 'policy', 'policies')}: ${usage.policies.map((p) => p.name).join(', ')}`)
    if (emptied) effects.push(`${plural(emptied, 'grant is', 'grants are')} left naming nothing and removed`)
    if (left.length) effects.push(`${left.join(', ')} ${left.length === 1 ? 'is' : 'are'} left with no grant and grant${left.length === 1 ? 's' : ''} nobody`)
    if (usage.live_sessions) effects.push(`Ends ${plural(usage.live_sessions, 'live session', 'live sessions')}`)
    if (usage.open_requests) effects.push(`Closes ${plural(usage.open_requests, 'open access request', 'open access requests')}`)
  }
  const ok = typed.trim() === name

  const run = (e: FormEvent) => {
    e.preventDefault()
    if (!ok) return
    void submit(async () => {
      await api.del(path)
      onDeleted()
    })
  }
  return (
    <Modal title={`Delete ${name}?`} onClose={onClose} width={480}>
      {loadErr && <Alert tone="danger">{loadErr}</Alert>}
      {!usage && !loadErr && <p className="muted">Checking what it is used by…</p>}
      {usage &&
        (effects.length ? (
          <ul className="delete-effects">
            {effects.map((x) => (
              <li key={x}>{x}</li>
            ))}
          </ul>
        ) : (
          <p className="muted">No policy, session or request names it.</p>
        ))}
      <form onSubmit={run}>
        <Field label={`Type ${name} to confirm`}>
          <input id="delete-confirm" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} />
        </Field>
        {err && <Alert tone="danger">{err}</Alert>}
        <div className="actions">
          <button type="button" className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button type="submit" className="btn danger" disabled={busy || !ok || !usage}>
            {busy ? 'Deleting…' : 'Delete'}
          </button>
        </div>
      </form>
    </Modal>
  )
}
