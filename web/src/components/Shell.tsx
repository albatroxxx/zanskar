import { Fragment, Suspense, useEffect, useState } from 'react'
import { Link, NavLink, Outlet, useNavigate } from 'react-router-dom'
import type { User } from '../api/types'
import { fmtTime } from '../api/format'
import { useAuth } from '../auth/AuthContext'
import { canConnect } from '../auth/home'
import { AccessNotices } from './AccessNotices'
import { ConsoleCLI } from './ConsoleCLI'
import { RestartNotice } from './RestartNotice'
import { Badge, Modal } from './ui'

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
  const { user, logout, hasRole, refresh, mfaEnrolled } = useAuth()
  const [accountOpen, setAccountOpen] = useState(false)
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
  if (portal !== 'user' && canConnect(user)) others.push({ to: '/', label: 'Access portal' })
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
          {/* Just the username: it is the one line that is always unique. The
              rest of the account — full name, email, whatever an identity
              provider fills in — lives behind it. */}
          <button className="me-user mono" onClick={() => setAccountOpen(true)}>{user?.username}</button>

          <div className="switch">
            {others.map((o, i) => (
              <Fragment key={o.to}>
                {i > 0 && ' · '}
                <NavLink to={o.to}>{o.label}</NavLink>
              </Fragment>
            ))}
          </div>
          <button className="btn sm ghost" onClick={() => void logout()} style={{ alignSelf: 'flex-start' }}>
            {/* The door-and-arrow sign-out glyph; the text stays, so the icon
                is decoration and hidden from screen readers. */}
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
              <polyline points="16 17 21 12 16 7" />
              <line x1="21" y1="12" x2="9" y2="12" />
            </svg>
            Sign out
          </button>
        </div>
      </aside>
      <main className="main">
        {portal === 'admin' && <ConsoleCLI />}
        {portal === 'user' && <AccessNotices />}
        {portal === 'admin' && <RestartNotice />}
        {/* The admin and audit pages load on demand (ADR 0010), so the
            sign-in page does not carry the whole console. */}
        <Suspense fallback={<div className="empty">Loading…</div>}>
          <Outlet />
        </Suspense>
      </main>
      {/* At the root, not in the sidebar: the sticky sidebar is a stacking
          context, and a fixed dialog inside it paints under the main column. */}
      {accountOpen && user && <AccountModal user={user} mfaEnrolled={mfaEnrolled} onClose={() => setAccountOpen(false)} />}
    </div>
  )
}

/** AccountModal is the account behind the sidebar's username: what Zanskar
 *  knows today, and where an identity provider's fields (full name, email,
 *  department and the like) land once one is connected. */
function AccountModal({ user, mfaEnrolled, onClose }: { user: User; mfaEnrolled: boolean; onClose: () => void }) {
  return (
    <Modal title="Account" onClose={onClose} width={420}>
      <dl className="kv">
        <dt>Username</dt>
        <dd className="mono">{user.username}</dd>
        <dt>Full name</dt>
        <dd>{user.display_name || <span className="muted">not set</span>}</dd>
        <dt>Email</dt>
        <dd>{user.email || <span className="muted">not set</span>}</dd>
        <dt>Roles</dt>
        <dd>{user.roles.join(', ')}</dd>
        <dt>Status</dt>
        <dd>{user.status}</dd>
        <dt>Authenticator</dt>
        <dd>{mfaEnrolled ? <Badge tone="ok">enrolled</Badge> : <Badge>not enrolled</Badge>}</dd>
        {user.last_login_at && (
          <>
            <dt>Last sign-in</dt>
            <dd>{fmtTime(user.last_login_at)}</dd>
          </>
        )}
        <dt>Created</dt>
        <dd>{fmtTime(user.created_at)}</dd>
      </dl>
      <p className="muted" style={{ marginBottom: 0 }}>
        A connected identity provider fills in more — full name, email, department — the way directory attributes do.
      </p>
    </Modal>
  )
}
