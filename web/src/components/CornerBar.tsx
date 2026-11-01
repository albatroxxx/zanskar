import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, errorMessage } from '../api/client'
import { fmtTime } from '../api/format'
import type { HostStatus, SystemStatus, UpdateStatus } from '../api/types'
import { ConsoleCLI } from './ConsoleCLI'
import { HostActionDialog } from './HostActionDialog'
import type { HostAction } from './hostAction'
import { shownTheme, themeEvent, toggleTheme } from '../styles/theme'
import { BellIcon, GearIcon, ThemeIcon } from './icons'
import { CornerPopover, MenuItem, MenuSeparator } from './Popover'
import { Alert, Badge } from './ui'

/** CornerBar is the admin console's top-right strip: the theme, the bell
 *  (is there a newer release), the gear (restart, reboot, stop — ADR 0032)
 *  and the command line (ADR 0027), one row of bare glyphs. */
export function CornerBar() {
  return (
    <div className="corner">
      <ThemeToggle />
      <UpdateBell />
      <GearMenu />
      <ConsoleCLI />
    </div>
  )
}

/** CornerThemeOnly is the access and audit portals' corner: the theme switch alone. */
export function CornerThemeOnly() {
  return (
    <div className="corner">
      <ThemeToggle />
    </div>
  )
}

/** ThemeToggle switches this browser between the light and the dark theme,
 *  one click each way (2026-11-01; it was a menu of System, Light and Dark;
 *  the theme for everyone is in Settings). The circle's dark half turns half
 *  a turn whenever the theme drawn changes, whatever changed it (this switch,
 *  Settings, the device), always the same way round. */
function ThemeToggle() {
  const [view, setView] = useState(() => {
    const shown = shownTheme()
    return { shown, turns: shown === 'dark' ? 1 : 0 }
  })
  useEffect(() => {
    const follow = () =>
      setView((v) => {
        const shown = shownTheme()
        return shown === v.shown ? v : { shown, turns: v.turns + 1 }
      })
    window.addEventListener(themeEvent, follow)
    const device = window.matchMedia?.('(prefers-color-scheme: dark)')
    device?.addEventListener('change', follow)
    return () => {
      window.removeEventListener(themeEvent, follow)
      device?.removeEventListener('change', follow)
    }
  }, [])
  const label = view.shown === 'dark' ? 'Switch to the light theme' : 'Switch to the dark theme'
  return (
    <button type="button" className="corner-btn theme-toggle" aria-label={label} title={label} onClick={() => toggleTheme()}>
      <ThemeIcon turns={view.turns} />
    </button>
  )
}

/** upgradeHint says how this deployment takes a new release. The install
 *  from the console itself is the update unit's; until it ships, the words
 *  are the manual step. */
function upgradeHint(supervisor?: string): string {
  switch (supervisor) {
    case 'systemd':
      return 'Install the new package on the host, then restart the gateway.'
    case 'kubernetes':
      return 'Roll the deployment to the new image tag.'
    default:
      return 'Replace the binary or image, then restart the gateway.'
  }
}

function UpdateBell() {
  const [st, setSt] = useState<UpdateStatus | null>(null)
  const [sys, setSys] = useState<SystemStatus | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [installing, setInstalling] = useState(false)

  useEffect(() => {
    api.get<UpdateStatus>('/admin/system/update').then(setSt).catch(() => setSt(null))
    api.get<SystemStatus>('/admin/system/status').then(setSys).catch(() => setSys(null))
  }, [])

  const check = async () => {
    setBusy(true)
    setErr('')
    try {
      setSt(await api.post<UpdateStatus>('/admin/system/update/check'))
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }
  const newer = !!st?.newer
  const label = newer ? `Zanskar ${st?.latest} is available` : 'Updates'
  return (
    <>
      <CornerPopover label={label} icon={<BellIcon />} dot={newer} kind="dialog" width={340}>
        {(close) => (
          <>
            <h3 className="corner-panel-title">Updates</h3>
            {st && (
              <dl className="kv">
                <dt>Running</dt>
                <dd className="mono">{st.current}</dd>
                <dt>Latest</dt>
                <dd>
                  {st.latest ? <span className="mono">{st.latest}</span> : <span className="muted">not known yet</span>}
                  {newer && (
                    <>
                      {' '}
                      <Badge tone="accent">new</Badge>
                    </>
                  )}
                </dd>
                {st.notes_url && (
                  <>
                    <dt>Notes</dt>
                    <dd>
                      <a href={st.notes_url} target="_blank" rel="noreferrer">
                        Release notes
                      </a>
                    </dd>
                  </>
                )}
                <dt>Checked</dt>
                <dd>
                  {st.checked_at ? fmtTime(st.checked_at) : 'not yet'}
                  {st.error && <span className="muted"> · {st.error}</span>}
                </dd>
              </dl>
            )}
            {st && !st.enabled && (
              <p className="muted">
                Daily checks are off; <Link to="/admin/settings">Settings</Link>.
              </p>
            )}
            {st?.install && (
              <Alert tone={st.install.state === 'failed' ? 'danger' : st.install.state === 'done' ? 'ok' : undefined}>
                Installer, {st.install.version}: {st.install.message} ({fmtTime(st.install.at)})
              </Alert>
            )}
            {newer && !st?.installable && <p>{upgradeHint(sys?.supervisor)}</p>}
            {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
            <div className="actions">
              <button type="button" className="btn sm" onClick={() => void check()} disabled={busy}>
                {busy ? 'Checking…' : 'Check now'}
              </button>
              {newer && st?.installable && (
                <button
                  type="button"
                  className="btn sm primary"
                  onClick={() => {
                    close()
                    setInstalling(true)
                  }}
                >
                  Update now
                </button>
              )}
            </div>
          </>
        )}
      </CornerPopover>
      {installing && st?.latest && <HostActionDialog action="update" version={st.latest} onClose={() => setInstalling(false)} />}
    </>
  )
}

function GearMenu() {
  const [host, setHost] = useState<HostStatus | null>(null)
  const [action, setAction] = useState<HostAction | null>(null)

  useEffect(() => {
    api.get<HostStatus>('/admin/system/host').then(setHost).catch(() => setHost(null))
  }, [])

  const hostOff = host !== null && !host.available
  return (
    <>
      <CornerPopover label="Gateway actions" icon={<GearIcon />} kind="menu">
        {(close) => {
          const pick = (a: HostAction) => {
            close()
            setAction(a)
          }
          return (
            <>
              <MenuItem onSelect={() => pick('restart')}>Restart gateway</MenuItem>
              <MenuItem onSelect={() => pick('reboot')} disabled={hostOff}>
                Reboot host
              </MenuItem>
              <MenuSeparator />
              <MenuItem onSelect={() => pick('poweroff')} disabled={hostOff} danger>
                Stop host
              </MenuItem>
              {hostOff && host?.reason && <p className="menu-note">{host.reason}</p>}
            </>
          )
        }}
      </CornerPopover>
      {action && <HostActionDialog action={action} onClose={() => setAction(null)} />}
    </>
  )
}
