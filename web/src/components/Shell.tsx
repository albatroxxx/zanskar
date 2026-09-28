import { Fragment } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'
import { canConnect } from '../auth/home'

export interface NavItem { to: string; label: string; end?: boolean }

/** Shell is the sidebar layout shared by the user, admin and auditor portals. */
export function Shell({ portal, items }: { portal: 'user' | 'admin' | 'audit'; items: NavItem[] }) {
  const { user, logout, hasRole } = useAuth()
  const sub = portal === 'user' ? 'access' : portal === 'admin' ? 'admin' : 'audit'
  // Links to the other portals this account may enter. A review-only account
  // (auditor without user) has no user portal to switch to.
  const others: { to: string; label: string }[] = []
  if (portal !== 'user' && canConnect(user)) others.push({ to: '/', label: 'User portal' })
  if (portal !== 'admin' && hasRole('admin')) others.push({ to: '/admin', label: 'Admin' })
  if (portal !== 'audit' && hasRole('admin', 'auditor')) others.push({ to: '/audit', label: 'Audit' })
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <img src="/logo-mark.svg" alt="" />
          <div>
            Zanskar
            <small>{sub}</small>
          </div>
        </div>
        <nav>
          {items.map((it) => (
            <NavLink key={it.to} to={it.to} end={it.end}>
              {it.label}
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
      <main className="main">
        <Outlet />
      </main>
    </div>
  )
}
