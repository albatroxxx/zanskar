import { useEffect, useState } from 'react'
import { ApiError, api, errorMessage } from '../../api/client'
import { fmtTime, setDisplayZone } from '../../api/format'
import type { BootSetting, RuntimeSetting, SettingsListing, SystemMetrics, SystemStatus } from '../../api/types'
import { Alert, Badge, Empty, Field, PageHead } from '../../components/ui'
import { TLSCard } from './TLSCard'
import { StorageCard } from './StorageCard'
import { RetentionCard } from './RetentionCard'

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
  const [changed, setChanged] = useState<string[]>([])
  const [err, setErr] = useState('')

  const load = () =>
    api
      .get<SettingsListing>('/admin/settings')
      .then(setListing)
      .catch((e) => setErr(errorMessage(e)))
  // A link to one section (the old Retention page sends its visitors to
  // #settings-recording-retention) lands on it once the page has drawn.
  useEffect(() => {
    const id = window.location.hash.slice(1)
    if (listing && id) document.getElementById(id)?.scrollIntoView()
  }, [listing])
  useEffect(() => {
    void load()
    api
      .get<SystemStatus>('/admin/system/status')
      .then((s) => setChanged(s.env_file.changed ?? []))
      .catch(() => {})
  }, [])

  if (!listing && !err) return <Empty>Loading…</Empty>
  const categories: string[] = []
  for (const s of listing?.runtime ?? []) if (!categories.includes(s.category)) categories.push(s.category)
  const replace = (v: RuntimeSetting) => setListing((l) => (l ? { ...l, runtime: l.runtime.map((s) => (s.key === v.key ? v : s)) } : l))

  return (
    <>
      <PageHead title="Settings" />
      {err && <Alert tone="danger">{err}</Alert>}
      <nav className="jump" aria-label="Sections">
        {[...categories, 'TLS certificate', 'Recording storage', 'Recording retention', 'Set at install'].map((c) => (
          <a key={c} href={'#' + sectionId(c)}>{c}</a>
        ))}
      </nav>
      {categories.map((c) => (
        <div className="card" key={c} id={sectionId(c)}>
          <h2>{c}</h2>
          {listing?.runtime
            .filter((s) => s.category === c)
            .map((s) => <SettingRow key={s.key} setting={s} onChange={replace} />)}
        </div>
      ))}
      <TLSCard />
      <StorageCard />
      <RetentionCard />
      {listing && <BootTable boot={listing.boot} changed={changed} />}
    </>
  )
}

/** sectionId is the anchor of a section card, from its heading. */
function sectionId(heading: string): string {
  return 'settings-' + heading.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
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

/** defaultGuacd is where a package install runs guacd. */
const defaultGuacd = '127.0.0.1:4822'

function SettingRow({ setting, onChange }: { setting: RuntimeSetting; onChange: (v: RuntimeSetting) => void }) {
  const [value, setValue] = useState(setting.value)
  // Whether guacd answers, for the Desktops row.
  const [reach, setReach] = useState('')
  useEffect(() => {
    if (setting.key !== 'desktop.guacd_addr') return
    api
      .get<SystemMetrics>('/admin/system/metrics')
      .then((m) => setReach(m.guacd ? (m.guacd.reachable ? 'guacd reachable' : `guacd unreachable at ${m.guacd.address}`) : ''))
      .catch(() => setReach(''))
  }, [setting.key, setting.value])
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [saved, setSaved] = useState(false)
  // A setting that decides where a credential is sent asks for a fresh
  // authenticator code (threat model risk 7): the gateway answers
  // step_up_required, the row shows a code field, and the next attempt
  // proves the code first.
  const [needCode, setNeedCode] = useState(false)
  const [code, setCode] = useState('')
  const dirty = value !== setting.value

  const run = async (fn: () => Promise<RuntimeSetting>) => {
    setErr('')
    setSaved(false)
    setBusy(true)
    try {
      if (needCode && code.trim()) await api.post('/auth/mfa/step-up', { code: code.trim() })
      const v = await fn()
      onChange(v)
      setValue(v.value)
      // Every time on the page follows the zone from the next render on.
      if (v.key === 'display.time_zone') setDisplayZone(v.value)
      setSaved(true)
      setNeedCode(false)
      setCode('')
    } catch (e) {
      if (e instanceof ApiError && e.code === 'step_up_required') {
        setNeedCode(true)
        setErr('')
      } else {
        setErr(errorMessage(e))
      }
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
    case 'hostport':
      if (setting.key === 'desktop.guacd_addr') {
        // On or off is the choice an administrator makes; where guacd runs
        // is an install detail, under Advanced (2026-10-30).
        const on = value.trim() !== ''
        input = (
          <>
            <span className="field inline" style={{ margin: 0 }}>
              <input id={id} type="checkbox" checked={on} onChange={(e) => setValue(e.target.checked ? setting.value.trim() || defaultGuacd : '')} />
              <label htmlFor={id}>{on ? 'On' : 'Off'}</label>
              {on && reach && <span className="muted">· {reach}</span>}
            </span>
            <details className="advanced">
              <summary>Advanced</summary>
              <Field label="guacd address" hint="host:port">
                <input id={id + '-addr'} value={value} onChange={(e) => setValue(e.target.value)} placeholder={defaultGuacd} />
              </Field>
            </details>
          </>
        )
        break
      }
      input = <input id={id} value={value} onChange={(e) => setValue(e.target.value)} placeholder="host:port" />
      break
    case 'timezone':
      // Typed, with every zone the browser knows offered as it is typed.
      input = (
        <>
          <input id={id} value={value} onChange={(e) => setValue(e.target.value)} list={id + '-zones'} autoComplete="off" spellCheck={false} />
          <datalist id={id + '-zones'}>
            {timeZones().map((z) => (
              <option key={z} value={z}>
                {z}
              </option>
            ))}
          </datalist>
        </>
      )
      break
    case 'text':
      input = <textarea id={id} value={value} onChange={(e) => setValue(e.target.value)} rows={6} placeholder={setting.key === 'login_banner' ? 'This system is the property of Example Ltd. Access is restricted to authorised users.\nAll activity, including every session, is recorded and may be reviewed. By signing in you consent to this monitoring.' : undefined} />
      break
    default:
      if (setting.key === 'database.proxy_image' || setting.key === 'apps.browser_image') {
        // The default follows the gateway's version; a custom image is for a
        // private mirror and is the one setting that would otherwise go
        // stale across upgrades (2026-10-30).
        input = (
          <details className="advanced" open={setting.source !== 'default' || undefined}>
            <summary>{setting.source === 'default' ? 'Default: follows the gateway version' : 'Custom image'}</summary>
            <input id={id} value={value} onChange={(e) => setValue(e.target.value)} spellCheck={false} />
          </details>
        )
        break
      }
      input = <input id={id} value={value} onChange={(e) => setValue(e.target.value)} />
  }
  const customImage = (setting.key === 'database.proxy_image' || setting.key === 'apps.browser_image') && setting.source !== 'default'

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
      {customImage && <Alert tone="warn">A custom image does not follow upgrades: change it with each release, or Reset to follow the gateway.</Alert>}
      {setting.key === 'login_banner' && value.trim() && (
        <Field label="Preview">
          <div className="login-banner" aria-hidden="true">{value.trim()}</div>
        </Field>
      )}
      {needCode && (
        <Field label="Authenticator code" hint="Required for this setting">
          <input id={id + '-code'} inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} autoFocus />
        </Field>
      )}
      {err && <Alert tone="danger">{err}</Alert>}
      <div className="actions">
        <button type="button" className="btn primary sm" disabled={!dirty || busy || (needCode && !code.trim())} onClick={() => void save()}>{busy ? 'Saving…' : 'Save'}</button>
        <button type="button" className="btn sm" disabled={!dirty || busy} onClick={() => setValue(setting.value)}>Discard</button>
        {setting.source === 'console' && (
          <button type="button" className="btn sm" disabled={busy || (needCode && !code.trim())} onClick={() => void reset()} title={setting.env_var ? `Go back to ${setting.env_var} from the environment file, or the default` : 'Go back to the default'}>
            Reset
          </button>
        )}
        {saved && <span className="muted">Applied.</span>}
        {setting.source === 'console' && setting.updated_at && <span className="muted">Changed {fmtTime(setting.updated_at)}</span>}
      </div>
    </div>
  )
}

/** changedIn: a boot row lists its variables as "A, B" or a family "ZANSKAR_X_*"; match either. */
function changedIn(envVar: string, changed: string[]) {
  return envVar.split(',').map((v) => v.trim()).some((v) => (v.endsWith('*') ? changed.some((c) => c.startsWith(v.slice(0, -1))) : changed.includes(v)))
}

function BootTable({ boot, changed }: { boot: BootSetting[]; changed: string[] }) {
  return (
    <div className="card table-wrap" id="settings-set-at-install">
      <h2>Set at install</h2>
      <p className="muted">From <code>/etc/zanskar/env</code>; edit and restart to change.</p>
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
              <td className="mono">
                {b.value}
                {changedIn(b.env_var, changed) && (
                  <>
                    {' '}
                    <Badge tone="warn">changed in file</Badge>
                  </>
                )}
              </td>
              <td className="mono muted">{b.env_var}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/** timeZones lists the zones this browser can show, for the time zone setting. */
function timeZones(): string[] {
  const intl = Intl as unknown as { supportedValuesOf?: (key: string) => string[] }
  try {
    return intl.supportedValuesOf?.('timeZone') ?? []
  } catch {
    return []
  }
}
