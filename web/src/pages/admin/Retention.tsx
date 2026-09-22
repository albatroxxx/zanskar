import { useEffect, useState, type FormEvent } from 'react'
import { api, errorMessage } from '../../api/client'
import { fmtTime } from '../../api/format'
import type { RetentionPolicy } from '../../api/types'
import { Alert, Empty, Field, PageHead } from '../../components/ui'

const GiB = 1024 * 1024 * 1024

/**
 * Retention lets an admin set how long session recordings are kept: keep by age
 * (days), with a total-size cap as a backstop that deletes the oldest early if
 * the disk would otherwise fill. Zero disables that dimension; both zero (the
 * default) keeps everything. The server sweeps hourly and audits every purge.
 */
export function Retention() {
  const [loaded, setLoaded] = useState<RetentionPolicy | null>(null)
  const [days, setDays] = useState(0)
  const [gib, setGib] = useState(0)
  const [err, setErr] = useState('')
  const [saved, setSaved] = useState(false)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    api
      .get<RetentionPolicy>('/admin/retention')
      .then((p) => {
        setLoaded(p)
        setDays(p.max_age_days)
        setGib(Math.round((p.max_total_bytes / GiB) * 100) / 100)
      })
      .catch((e) => setErr(errorMessage(e)))
  }, [])

  const save = async (e: FormEvent) => {
    e.preventDefault()
    setErr('')
    setSaved(false)
    if (days < 0 || gib < 0) {
      setErr('Values must not be negative.')
      return
    }
    setBusy(true)
    try {
      const p = await api.put<RetentionPolicy>('/admin/retention', {
        max_age_days: Math.round(days),
        max_total_bytes: Math.round(gib * GiB),
      })
      setLoaded(p)
      setDays(p.max_age_days)
      setGib(Math.round((p.max_total_bytes / GiB) * 100) / 100)
      setSaved(true)
    } catch (e2) {
      setErr(errorMessage(e2))
    } finally {
      setBusy(false)
    }
  }

  if (!loaded && !err) return <Empty>Loading…</Empty>

  const off = days === 0 && gib === 0
  return (
    <>
      <PageHead
        title="Recording retention"
        lead="How long session recordings are kept. The gateway deletes recordings past this policy every hour and records each deletion in the audit log; the recording's metadata stays so the audit trail still resolves."
      />
      {err && <Alert tone="danger">{err}</Alert>}
      {saved && <Alert tone="ok">Retention policy saved.</Alert>}

      <form className="card" onSubmit={save} style={{ maxWidth: 560 }}>
        <Field label="Keep recordings for (days)" hint="0 keeps recordings indefinitely by age.">
          <input type="number" min={0} step={1} value={days} onChange={(e) => setDays(Number(e.target.value))} />
        </Field>
        <Field label="Total size cap (GiB)" hint="A backstop: when recordings exceed this, the oldest are deleted early even if within the day limit. 0 means no cap.">
          <input type="number" min={0} step={0.5} value={gib} onChange={(e) => setGib(Number(e.target.value))} />
        </Field>

        {off && (
          <Alert tone="warn">
            Retention is off: recordings are kept forever and the disk will grow without bound. Set a day
            limit, a size cap, or both.
          </Alert>
        )}

        <div className="actions">
          <button className="btn primary" disabled={busy}>{busy ? 'Saving…' : 'Save policy'}</button>
        </div>
        {loaded?.updated_at && (
          <p className="muted" style={{ marginTop: 12, fontSize: '0.82rem' }}>
            Last changed {fmtTime(loaded.updated_at)}. See the audit log for who changed it.
          </p>
        )}
      </form>
    </>
  )
}
