import { Fragment, useEffect, useState } from 'react'
import { Link, NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'
import { canConnect } from '../auth/home'
import { AccessNotices } from './AccessNotices'
import { ConsoleCLI } from './ConsoleCLI'
import { RestartNotice } from './RestartNotice'

export interface NavItem {
  to: string
  label: string
  end?: boolean
  /** badge, when set, is polled once a minute; a positive count shows beside the label. */
  badge?: () => Promise<number>
}

/** NavBadge shows a count next to a nav label: 1 to 99, then "99+", nothing at zero. */
function NavBadge({ load }: { load: () => Promise<number> }) {
  const [n, setN] = useState(0)
  useEffect(() => {
    const tick = () => load().then(setN).catch(() => {})
    void tick()
    const t = setInterval(tick, 60_000)
    return () => clearInterval(t)
  }, [load])
  if (n <= 0) return null
  return <span className="nav-badge" aria-label={`${n} pending`}>{n > 99 ? '99+' : n}</span>
}

/** Shell is the sidebar layout shared by the user, admin and auditor portals. */
export function Shell({ portal, items }: { portal: 'user' | 'admin' | 'audit'; items: NavItem[] }) {
  const { user, logout, hasRole, refresh } = useAuth()
  const nav = useNavigate()
  const sub = portal === 'user' ? 'access' : portal === 'admin' ? 'admin' : 'audit'
  // The brand goes to the first page of the portal you are in. It asks the
  // server about the session first: a stale one then lands on sign-in (the
  // route guard sends it there) instead of on a page whose data 401s.
  const home = portal === 'user' ? '/' : '/' + portal
  const goHome = async (e: React.MouseEvent) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return // new tab or window: leave it to the browser
    e.preventDefault()
    await refresh()
    nav(home)
  }
  // Links to the other portals this account may enter. A review-only account
  // (auditor without user) has no user portal to switch to.
  const others: { to: string; label: string }[] = []
  if (portal !== 'user' && canConnect(user)) others.push({ to: '/', label: 'User portal' })
  if (portal !== 'admin' && hasRole('admin')) others.push({ to: '/admin', label: 'Admin' })
  // Admins review the log inside their own console (Events, Recordings), so
  // only a non-admin auditor gets a switch to the audit portal.
  if (portal !== 'audit' && hasRole('auditor') && !hasRole('admin')) others.push({ to: '/audit', label: 'Audit' })
  return (
    <div className="shell">
      <aside className="sidebar">
        <Link className="brand" to={home} onClick={(e) => void goHome(e)} title="Back to the first page">
          <img src="/logo-mark.svg" alt="" />
          <div>
            Zanskar
            <small>{sub}</small>
          </div>
        </Link>
        <nav>
          {items.map((it) => (
            <NavLink key={it.to} to={it.to} end={it.end}>
              {it.label}
              {it.badge && <NavBadge load={it.badge} />}
            </NavLink>
          ))}
        </nav>
        <div className="spacer" />
        <div className="me">
          <div>
            <strong>{user?.display_name}</strong>
            <br />
            <span className="mono">{user?.username}</span>
          </div>
          <div className="switch">
            {others.map((o, i) => (
              <Fragment key={o.to}>
                {i > 0 && ' · '}
                <NavLink to={o.to}>{o.label}</NavLink>
              </Fragment>
            ))}
          </div>
          <button className="btn sm ghost" onClick={() => void logout()} style={{ alignSelf: 'flex-start' }}>
            Sign out
          </button>
        </div>
      </aside>
      <main className={'main' + (portal === 'admin' ? ' has-cli' : '')}>
        {portal === 'admin' && <ConsoleCLI />}
        {portal === 'user' && <AccessNotices />}
        {portal === 'admin' && <RestartNotice />}
        <Outlet />
      </main>
    </div>
  )
}
