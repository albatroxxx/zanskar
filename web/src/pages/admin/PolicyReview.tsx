import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, errorMessage } from '../../api/client'
import { fmtTime } from '../../api/format'
import type { Policy, PolicySubject } from '../../api/types'
import { Alert, Badge, Loading, PageHead } from '../../components/ui'

/** One subject as GET /access-policies/{id}/review lists it (ADR 0040). */
interface ReviewSubject extends PolicySubject {
  name: string
  people: { user_id: string; username: string; last_used_at?: string }[]
  last_used_at?: string
}

interface ReviewView {
  policy: Policy
  subjects: ReviewSubject[]
  reviewer_name?: string
  due: boolean
}

/** Unused for this long reads as a question for the reviewer. */
const STALE_MS = 90 * 24 * 60 * 60_000

const key = (s: PolicySubject) => `${s.kind}:${s.id}`

/** lastUse says when a subject last used the policy, warning past 90 days. */
function lastUse(at: string | undefined, now: number) {
  if (!at) return <Badge tone="warn">never used</Badge>
  if (now - Date.parse(at) > STALE_MS) return <><Badge tone="warn">unused 90+ days</Badge> <span className="muted">{fmtTime(at)}</span></>
  return fmtTime(at)
}

/**
 * PolicyReview is one policy's access review (2026-11-03, idea 4; ADR 0040):
 * every subject, the people behind it and when they last used the policy,
 * kept or removed one by one, with a note. Completing it removes those
 * marked, ends what that took away, stamps the policy reviewed and records
 * the decisions as a policy.review event, the evidence an audit asks for.
 */
export function PolicyReview() {
  const { id = '' } = useParams()
  const [v, setV] = useState<ReviewView | null>(null)
  const [remove, setRemove] = useState<Set<string>>(new Set())
  const [note, setNote] = useState('')
  const [err, setErr] = useState('')
  const [done, setDone] = useState('')
  const [busy, setBusy] = useState(false)
  // Read once per load, so a render stays pure.
  const [now, setNow] = useState(0)

  const load = useCallback(() => {
    api
      .get<ReviewView>(`/access-policies/${encodeURIComponent(id)}/review`)
      .then((r) => {
        setV(r)
        setNow(Date.now())
      })
      .catch((e) => setErr(errorMessage(e)))
  }, [id])
  useEffect(load, [load])

  const toggle = (s: PolicySubject) =>
    setRemove((cur) => {
      const next = new Set(cur)
      if (next.has(key(s))) next.delete(key(s))
      else next.add(key(s))
      return next
    })

  const complete = async () => {
    if (!v) return
    setBusy(true)
    setErr('')
    try {
      const gone = v.subjects.filter((s) => remove.has(key(s))).map((s) => ({ kind: s.kind, id: s.id }))
      const r = await api.post<ReviewView>(`/access-policies/${encodeURIComponent(id)}/review`, { remove: gone, note: note.trim() })
      setV(r)
      setRemove(new Set())
      setNote('')
      setDone(gone.length ? `Review complete: ${gone.length} removed, ${r.subjects.length} kept.` : `Review complete: everyone kept.`)
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <PageHead title={v ? `Review ${v.policy.name}` : 'Access review'} lead="When each person last used it; keep who still needs it.">
        <Link className="btn" to="/admin/policies">Policies</Link>
      </PageHead>
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      {done && <Alert tone="ok" onDismiss={() => setDone('')}>{done}</Alert>}
      {!v ? (
        !err && <Loading />
      ) : (
        <>
          <p className="muted">
            {v.policy.reviewed_at ? <>Last reviewed {fmtTime(v.policy.reviewed_at)}{v.reviewer_name && <> by {v.reviewer_name}</>}.</> : 'Never reviewed.'}{' '}
            {v.due && <Badge tone="warn">review due</Badge>}
          </p>
          <div className="card table-wrap">
            {v.subjects.length === 0 ? (
              <p className="muted">This policy covers no one.</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Who</th>
                    <th>People</th>
                    <th>Last used</th>
                    <th>Decision</th>
                  </tr>
                </thead>
                <tbody>
                  {v.subjects.map((s) => {
                    const out = remove.has(key(s))
                    return (
                      <tr key={key(s)} className={out ? 'off' : undefined}>
                        <td>
                          <strong>{s.name || s.id}</strong> <span className="muted">{s.kind}</span>
                        </td>
                        <td>
                          {s.people.length === 0 ? (
                            <span className="muted">nobody</span>
                          ) : (
                            s.people.map((p) => (
                              <div key={p.user_id}>
                                {p.username} <span className="muted">{p.last_used_at ? fmtTime(p.last_used_at) : 'never'}</span>
                              </div>
                            ))
                          )}
                        </td>
                        <td>{lastUse(s.last_used_at, now)}</td>
                        <td>
                          <label className="field inline">
                            <input type="checkbox" checked={out} onChange={() => toggle(s)} aria-label={`Remove ${s.name || s.id}`} /> Remove
                          </label>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </div>
          <div className="card">
            <label className="field">
              <span>Note</span>
              <textarea value={note} onChange={(e) => setNote(e.target.value)} maxLength={2000} placeholder="What this review found, for the audit log" />
            </label>
            <div className="actions">
              <button type="button" className={'btn ' + (remove.size ? 'danger' : 'primary')} disabled={busy} onClick={() => void complete()}>
                {remove.size ? `Remove ${remove.size} and complete review` : 'Keep everyone and complete review'}
              </button>
            </div>
          </div>
        </>
      )}
    </>
  )
}
