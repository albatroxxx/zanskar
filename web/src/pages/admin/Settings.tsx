import { useEffect, useState } from 'react'
import { api, errorMessage } from '../../api/client'
import { fmtTime } from '../../api/format'
import type { BootSetting, RuntimeSetting, SettingsListing } from '../../api/types'
import { Alert, Badge, Empty, Field, PageHead } from '../../components/ui'

/**
 * Settings holds the two kinds of configuration (ADR 0020): runtime settings
 * the gateway applies the moment they are saved, and boot settings fixed at
 * install in the environment file and shown here read-only, with the variable
 * to edit. A runtime setting has a built-in default, may take an install-time
 * value from its environment variable, and may be overridden here; Reset
 * drops the console value so the environment or the default applies again.
 */
export function Settings() {
  const [listing, setListing] = useState<SettingsListing | null>(null)
  const [err, setErr] = useState('')

  const load = () =>
    api
      .get<SettingsListing>('/admin/settings')
      .then(setListing)
      .catch((e) => setErr(errorMessage(e)))
  useEffect(() => {
    void load()
  }, [])

  if (!listing && !err) return <Empty>Loading…</Empty>
  const categories: string[] = []
  for (const s of listing?.runtime ?? []) if (!categories.includes(s.category)) categories.push(s.category)
  const replace = (v: RuntimeSetting) => setListing((l) => (l ? { ...l, runtime: l.runtime.map((s) => (s.key === v.key ? v : s)) } : l))

  return (
    <>
      <PageHead title="Settings" lead="Runtime settings apply the moment they are saved, without a restart. A value set here overrides the environment file; Reset goes back to it. Boot settings are fixed at install and listed below with the variable to edit." />
      {err && <Alert tone="danger">{err}</Alert>}
      {categories.map((c) => (
        <div className="card" key={c}>
          <h2>{c}</h2>
          {listing?.runtime
            .filter((s) => s.category === c)
            .map((s) => <SettingRow key={s.key} setting={s} onChange={replace} />)}
        </div>
      ))}
      {listing && <BootTable boot={listing.boot} />}
    </>
  )
}

function sourceBadge(s: RuntimeSetting) {
  switch (s.source) {
    case 'console':
      return <Badge tone="accent">Set in console</Badge>
    case 'environment':
      return (
        <span title={`From ${s.env_var} in the environment file`}>
          <Badge>From {s.env_var}</Badge>
        </span>
      )
    default:
      return <Badge>Default</Badge>
  }
}

function SettingRow({ setting, onChange }: { setting: RuntimeSetting; onChange: (v: RuntimeSetting) => void }) {
  const [value, setValue] = useState(setting.value)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [saved, setSaved] = useState(false)
  const dirty = value !== setting.value

  const run = async (fn: () => Promise<RuntimeSetting>) => {
    setErr('')
    setSaved(false)
    setBusy(true)
    try {
      const v = await fn()
      onChange(v)
      setValue(v.value)
      setSaved(true)
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }
  const save = () => run(() => api.put<RuntimeSetting>(`/admin/settings/${setting.key}`, { value }))
  const reset = () => run(() => api.del<RuntimeSetting>(`/admin/settings/${setting.key}`))
  const id = 's-' + setting.key.replace(/\W/g, '-')

  let input
  switch (setting.type) {
    case 'bool':
      input = (
        <span className="field inline" style={{ margin: 0 }}>
          <input id={id} type="checkbox" checked={value === 'true'} onChange={(e) => setValue(e.target.checked ? 'true' : 'false')} />
          <label htmlFor={id}>{value === 'true' ? 'On' : 'Off'}</label>
        </span>
      )
      break
    case 'enum':
      input = (
        <select id={id} value={value} onChange={(e) => setValue(e.target.value)}>
          {(setting.enum ?? []).map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
      )
      break
    case 'text':
      input = <textarea id={id} value={value} onChange={(e) => setValue(e.target.value)} rows={6} placeholder={setting.key === 'login_banner' ? 'This system is the property of Example Ltd. Access is restricted to authorised users.\nAll activity, including every session, is recorded and may be reviewed. By signing in you consent to this monitoring.' : undefined} />
      break
    default:
      input = <input id={id} value={value} onChange={(e) => setValue(e.target.value)} placeholder={setting.type === 'hostport' ? 'host:port' : undefined} />
  }

  return (
    <div className="setting-row">
      <div className="setting-head">
        <label htmlFor={id}>
          <strong>{setting.title}</strong>
        </label>
        {sourceBadge(setting)}
      </div>
      <p className="muted">{setting.description}</p>
      {input}
      {setting.key === 'login_banner' && value.trim() && (
        <Field label="Preview">
          <div className="login-banner" aria-hidden="true">{value.trim()}</div>
        </Field>
      )}
      {err && <Alert tone="danger">{err}</Alert>}
      <div className="actions">
        <button type="button" className="btn primary sm" disabled={!dirty || busy} onClick={() => void save()}>{busy ? 'Saving…' : 'Save'}</button>
        <button type="button" className="btn sm" disabled={!dirty || busy} onClick={() => setValue(setting.value)}>Discard</button>
        {setting.source === 'console' && (
          <button type="button" className="btn sm" disabled={busy} onClick={() => void reset()} title={setting.env_var ? `Go back to ${setting.env_var} from the environment file, or the default` : 'Go back to the default'}>
            Reset
          </button>
        )}
        {saved && <span className="muted">Applied.</span>}
        {setting.source === 'console' && setting.updated_at && <span className="muted">Changed {fmtTime(setting.updated_at)}</span>}
      </div>
    </div>
  )
}

function BootTable({ boot }: { boot: BootSetting[] }) {
  return (
    <div className="card table-wrap">
      <h2>Set at install</h2>
      <p className="muted">Read once when the gateway starts, from the environment file (usually <code>/etc/zanskar/env</code>). To change one, edit the variable and restart the service. Secrets are not shown.</p>
      <table>
        <thead>
          <tr>
            <th>Setting</th>
            <th>Value</th>
            <th>Variable</th>
          </tr>
        </thead>
        <tbody>
          {boot.map((b) => (
            <tr key={b.key}>
              <td>
                <strong>{b.title}</strong>
                {b.description && <div className="muted">{b.description}</div>}
              </td>
              <td className="mono">{b.value}</td>
              <td className="mono muted">{b.env_var}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
