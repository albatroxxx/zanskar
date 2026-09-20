import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'

export interface NavItem { to: string; label: string; end?: boolean }

/** Shell is the sidebar layout shared by the user, admin and auditor portals. */
export function Shell({ portal, items }: { portal: 'user' | 'admin' | 'audit'; items: NavItem[] }) {
  const { user, logout, hasRole } = useAuth()
  const sub = portal === 'user' ? 'access' : portal === 'admin' ? 'admin' : 'audit'
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
            {portal !== 'user' && <NavLink to="/">User portal</NavLink>}
            {portal !== 'admin' && hasRole('admin') && (
              <>
                {portal !== 'user' && ' · '}
                <NavLink to="/admin">Admin</NavLink>
              </>
            )}
            {portal !== 'audit' && hasRole('admin', 'auditor') && (
              <>
                {' · '}
                <NavLink to="/audit">Audit</NavLink>
              </>
            )}
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
