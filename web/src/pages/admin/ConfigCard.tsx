import { useState } from 'react'
import { ApiError, api, errorMessage } from '../../api/client'
import { Alert, Badge } from '../../components/ui'

/** One change an import makes, or would (ADR 0043). */
interface Change {
  kind: 'group' | 'target' | 'policy'
  name: string
  action: 'create' | 'update' | 'unchanged'
  problem?: string
  error?: string
  applied?: boolean
}

interface Result {
  applied: boolean
  changes: Change[]
}

const actionTone = (c: Change) => (c.problem || c.error ? 'danger' : c.action === 'unchanged' ? undefined : c.action === 'create' ? 'ok' : 'warn')

/**
 * ConfigCard, in Settings, takes the configuration out as a YAML file and
 * brings one in (2026-11-03, idea 10; ADR 0043): groups, hosts, databases,
 * applications and access policies, by name, without secrets. An import
 * shows its plan first; nothing changes until Apply, and every change goes
 * through the same checks and audit as one made here by hand.
 */
export function ConfigCard() {
  const [file, setFile] = useState<{ name: string; text: string } | null>(null)
  const [plan, setPlan] = useState<Result | null>(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const send = async (text: string, apply: boolean): Promise<Result> => {
    try {
      return await api.upload<Result>('/admin/config/import' + (apply ? '?apply=true' : ''), text, 'application/yaml')
    } catch (e) {
      // A plan with problems, or an apply the API stopped, still says what it did.
      if (e instanceof ApiError && e.body && typeof e.body === 'object' && 'changes' in e.body) return e.body as Result
      throw e
    }
  }

  const choose = async (f: File | undefined) => {
    setErr('')
    setPlan(null)
    if (!f) return
    const text = await f.text()
    setFile({ name: f.name, text })
    setBusy(true)
    try {
      setPlan(await send(text, false))
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const apply = async () => {
    if (!file) return
    setBusy(true)
    setErr('')
    try {
      setPlan(await send(file.text, true))
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const problems = plan?.changes.filter((c) => c.problem).length ?? 0
  const pending = plan?.changes.filter((c) => c.action !== 'unchanged').length ?? 0
  return (
    <div className="card" id="settings-configuration-file">
      <h2>Configuration file</h2>
      <p className="muted">Groups, hosts, databases, applications and policies as YAML, by name, for git or another gateway. Credentials are named, never copied.</p>
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      <div className="actions">
        <a className="btn" href="/api/v1/admin/config/export" download>Export</a>
        <label className="btn">
          Import…
          <input type="file" accept=".yaml,.yml,application/yaml,text/yaml" className="sr-only" aria-label="Import a configuration file" onChange={(e) => void choose(e.target.files?.[0])} />
        </label>
      </div>
      {plan && (
        <>
          <p>
            {plan.applied ? (
              <>Imported {file?.name}.</>
            ) : problems > 0 ? (
              <>{file?.name} cannot be imported: {problems} {problems === 1 ? 'problem' : 'problems'} below. Nothing changed.</>
            ) : pending === 0 ? (
              <>{file?.name} matches this gateway; nothing to change.</>
            ) : (
              <>{file?.name} would change {pending} {pending === 1 ? 'thing' : 'things'}. Nothing has changed yet.</>
            )}
          </p>
          <table className="config-plan">
            <thead>
              <tr>
                <th>Kind</th>
                <th>Name</th>
                <th>Change</th>
              </tr>
            </thead>
            <tbody>
              {plan.changes.map((c) => (
                <tr key={`${c.kind}:${c.name}`}>
                  <td>{c.kind}</td>
                  <td><strong>{c.name}</strong></td>
                  <td>
                    <Badge tone={actionTone(c)}>{c.error ? 'refused' : c.applied ? `${c.action}d` : c.action}</Badge>
                    {(c.problem || c.error) && <span className="sync-error"> {c.problem || c.error}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!plan.applied && problems === 0 && pending > 0 && (
            <div className="actions">
              <button type="button" className="btn primary" disabled={busy} onClick={() => void apply()}>{busy ? 'Applying…' : `Apply ${pending} ${pending === 1 ? 'change' : 'changes'}`}</button>
            </div>
          )}
        </>
      )}
    </div>
  )
}
