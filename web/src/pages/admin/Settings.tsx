import { useEffect, useState, type FormEvent } from 'react'
import { api, errorMessage } from '../../api/client'
import { fmtTime } from '../../api/format'
import type { Setting } from '../../api/types'
import { Alert, Empty, Field, PageHead } from '../../components/ui'

const MAX = 4000

/**
 * Settings holds the runtime settings an admin edits in place and the
 * gateway applies without a restart. First entry: the login banner, the
 * system-use notification shown on the sign-in page before any credential
 * is entered (NIST AC-8 and the equivalents in ISO 27001 and PCI DSS).
 */
export function Settings() {
  const [loaded, setLoaded] = useState<Setting | null>(null)
  const [text, setText] = useState('')
  const [err, setErr] = useState('')
  const [saved, setSaved] = useState(false)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    api
      .get<Setting>('/admin/settings/login-banner')
      .then((s) => {
        setLoaded(s)
        setText(s.value)
      })
      .catch((e) => setErr(errorMessage(e)))
  }, [])

  const dirty = loaded !== null && text !== loaded.value
  const save = async (e: FormEvent) => {
    e.preventDefault()
    setErr('')
    setSaved(false)
    setBusy(true)
    try {
      const s = await api.put<Setting>('/admin/settings/login-banner', { value: text })
      setLoaded(s)
      setText(s.value)
      setSaved(true)
    } catch (e2) {
      setErr(errorMessage(e2))
    } finally {
      setBusy(false)
    }
  }

  if (!loaded && !err) return <Empty>Loading…</Empty>
  return (
    <>
      <PageHead title="Settings" lead="Runtime settings, applied the moment they are saved. Listen address, database and master key are set at install in the environment file and are not editable here." />
      {err && <Alert tone="danger">{err}</Alert>}
      {saved && <Alert tone="ok">Saved. The sign-in page shows it from the next load.</Alert>}
      <div className="card">
        <h2>Login banner</h2>
        <p className="muted">A system-use notification shown above the sign-in form, before any credential is entered: whose system this is, that use is monitored and recorded, and what consent signing in implies. Plain text; line breaks are kept. Empty hides it. Every change is recorded in the audit log with the previous and the new text.</p>
        <form onSubmit={(e) => void save(e)}>
          <Field label="Banner text" hint={`${text.length} / ${MAX} characters`}>
            <textarea id="s-banner" value={text} onChange={(e) => setText(e.target.value)} rows={8} maxLength={MAX} placeholder={'This system is the property of Example Ltd. Access is restricted to authorised users.\nAll activity, including every session, is recorded and may be reviewed. By signing in you consent to this monitoring.'} />
          </Field>
          {text.trim() && (
            <Field label="Preview">
              <div className="login-banner" aria-hidden="true">{text.trim()}</div>
            </Field>
          )}
          <div className="actions">
            <button type="button" className="btn" disabled={!dirty || busy} onClick={() => setText(loaded?.value ?? '')}>Discard</button>
            <button className="btn primary" disabled={!dirty || busy}>{busy ? 'Saving…' : 'Save'}</button>
            {loaded?.updated_at && <span className="muted">Last changed {fmtTime(loaded.updated_at)}</span>}
          </div>
        </form>
      </div>
    </>
  )
}
