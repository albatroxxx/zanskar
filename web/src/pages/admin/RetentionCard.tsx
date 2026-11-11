import { useEffect, useState, type FormEvent } from 'react'
import { api, errorMessage } from '../../api/client'
import { fmtTime } from '../../api/format'
import type { RetentionPolicy } from '../../api/types'
import { Alert, Field } from '../../components/ui'

const GiB = 1024 * 1024 * 1024

/**
 * RetentionCard, on the Settings page beside recording storage (it had a page
 * of its own until 2026-10-30), sets how long session recordings are kept:
 * keep by age (days), with a total-size cap as a backstop that deletes the
 * oldest early if the disk would otherwise fill. Zero disables that
 * dimension; both zero (the default) keeps everything. The server sweeps
 * hourly and audits every purge.
 */
export function RetentionCard() {
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

  const off = days === 0 && gib === 0
  const storedGib = loaded ? Math.round((loaded.max_total_bytes / GiB) * 100) / 100 : 0
  const dirty = !!loaded && (days !== loaded.max_age_days || gib !== storedGib)
  const discard = () => {
    if (!loaded) return
    setDays(loaded.max_age_days)
    setGib(storedGib)
    setErr('')
  }
  // The same row as every other setting (live, 2026-11-11): Save only with a
  // change, Discard beside it, "Changed" on the same line, and number boxes
  // the size of a number rather than the page's width.
  return (
    <form className="card" id="settings-recording-retention" onSubmit={save}>
      <h2>Recording retention</h2>
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      {!loaded && !err ? (
        <p className="muted">Loading…</p>
      ) : (
        <>
          <Field label="Keep recordings for (days)" hint="0 = no age limit">
            <input className="narrow" type="number" min={0} step={1} value={days} onChange={(e) => { setDays(Number(e.target.value)); setSaved(false) }} />
          </Field>
          <Field label="Total size cap (GiB)" hint="Oldest go first past the cap; 0 = no cap">
            <input className="narrow" type="number" min={0} step={0.5} value={gib} onChange={(e) => { setGib(Number(e.target.value)); setSaved(false) }} />
          </Field>

          {off && (
            <Alert tone="warn">
              Retention is off: recordings are kept forever.
            </Alert>
          )}

          <div className="actions">
            <button type="submit" className="btn primary sm" disabled={!dirty || busy}>{busy ? 'Saving…' : 'Save'}</button>
            <button type="button" className="btn sm" disabled={!dirty || busy} onClick={discard}>Discard</button>
            {saved && <span className="muted">Saved.</span>}
            {loaded?.updated_at && <span className="muted">Changed {fmtTime(loaded.updated_at)}</span>}
          </div>
        </>
      )}
    </form>
  )
}
