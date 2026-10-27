import { lazy, Suspense } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { useAuth } from './auth/AuthContext'
import { SessionExpired } from './auth/SessionExpired'
import { Empty } from './components/ui'
import { Shell } from './components/Shell'
import type { Role } from './api/types'
import { homeFor } from './auth/home'
import { api } from './api/client'
import type { AccessRequest, Page } from './api/types'
import { Login } from './pages/Login'
import { Launch } from './pages/Launch'
import { Targets } from './pages/user/Targets'
import { MySessions } from './pages/user/MySessions'
import { MyAccess } from './pages/user/MyAccess'

// The terminal pulls in xterm; load it only when a session opens.
const Terminal = lazy(() => import('./pages/user/Terminal').then((m) => ({ default: m.Terminal })))
const Desktop = lazy(() => import('./pages/user/Desktop').then((m) => ({ default: m.Desktop })))
const Shadow = lazy(() => import('./pages/audit/Shadow').then((m) => ({ default: m.Shadow })))
import { adminRoutes } from './pages/admin'
import { adminAuditRoutes, auditRoutes } from './pages/audit'

function Guard({ roles, children }: { roles?: Role[]; children: React.ReactNode }) {
  const auth = useAuth()
  const loc = useLocation()
  if (auth.status === 'loading') return <div className="empty">Loading…</div>
  if (auth.status === 'unreachable') return <Unreachable />
  // The query string is part of where the user was going (a filter, a tab).
  if (auth.status !== 'full') return <Navigate to="/login" state={{ from: loc.pathname + loc.search }} replace />
  if (roles && !auth.hasRole(...roles)) {
    // Send the account to the portal it does have. An account with no role at
    // all (which the API refuses to create) would otherwise bounce forever.
    const home = homeFor(auth.user)
    if (home === loc.pathname || !auth.user?.roles.length) return <NoPortal />
    return <Navigate to={home} replace />
  }
  return <>{children}</>
}

/** Unreachable is the first load while the gateway does not answer: the brand
 *  and the sentence, so the page is recognisably ours while the console asks
 *  again (review U4). Once a portal is open the shell stays and the API
 *  client's own notices take over. */
function Unreachable() {
  return (
    <div className="unreachable" role="status">
      <div className="brand"><img src="/logo-mark.svg" alt="" /><span>ZANSKAR</span></div>
      <p>The gateway is not answering; trying again…</p>
    </div>
  )
}

function NoPortal() {
  const { logout } = useAuth()
  return (
    <div className="empty">
      <p>This account has no role that opens a portal. Ask an administrator to grant one.</p>
      <button className="btn sm ghost" onClick={() => void logout()}>Sign out</button>
    </div>
  )
}

// AdminToConsole sends an admin who follows an old /audit link to the same
// page inside the admin console, which now holds Events and Recordings; the
// audit portal is for review-only accounts. /audit itself is the auditor's
// dashboard, so an admin landing there goes to their own (ADR 0029).
function AdminToConsole({ children }: { children: React.ReactNode }) {
  const auth = useAuth()
  const loc = useLocation()
  if (!auth.hasRole('admin')) return <>{children}</>
  const rest = loc.pathname.replace(/^\/audit\/?/, '')
  return <Navigate to={(rest ? '/admin/' + rest : '/admin') + loc.search} replace />
}

// Home resolves "/home" and unknown paths to the portal the account may
// enter. It waits for the account to be known: sent to "/" while the probe
// is still out, an administrator would land in the access portal, which
// admits them too, instead of the console.
function Home() {
  const auth = useAuth()
  if (auth.status === 'loading') return <div className="empty">Loading…</div>
  if (auth.status === 'unreachable') return <Unreachable />
  if (auth.status !== 'full') return <Navigate to="/" replace />
  return <Navigate to={homeFor(auth.user)} replace />
}

// pendingApprovals feeds the Approvals badge: how many requests await a decision.
const pendingApprovals = () => api.get<Page<AccessRequest>>('/access-requests?status=pending').then((p) => (p.items ?? []).length)

// The user portal and the session pages are for accounts that can connect
// (ADR 0006); the API refuses auditor-only accounts on every route behind
// them, so the UI hides what would only fail.
const connectRoles: Role[] = ['user', 'admin']

export default function App() {
  return (
    <>
      {/* Mounted outside the routes so an expired session is announced once,
          whichever page the user is on. */}
      <SessionExpired />
      <Routes>
      <Route path="/login" element={<Login />} />
      {/* An application host sends a browser here to be let in (ADR 0033);
          the page asks the API for the hand-off and sends it straight back. */}
      <Route
        path="/launch"
        element={
          <Guard roles={connectRoles}>
            <Launch />
          </Guard>
        }
      />
      <Route
        path="/terminal"
        element={
          <Guard roles={connectRoles}>
            <Suspense fallback={<Empty>Loading terminal</Empty>}>
              <Terminal />
            </Suspense>
          </Guard>
        }
      />
      <Route
        path="/desktop"
        element={
          <Guard roles={connectRoles}>
            <Suspense fallback={<Empty>Loading desktop</Empty>}>
              <Desktop />
            </Suspense>
          </Guard>
        }
      />
      <Route
        path="/audit/shadow/:id"
        element={
          <Guard roles={['admin', 'auditor']}>
            <Suspense fallback={<Empty>Connecting</Empty>}>
              <Shadow />
            </Suspense>
          </Guard>
        }
      />
      <Route
        path="/"
        element={
          <Guard roles={connectRoles}>
            <Shell
              portal="user"
              items={[
                { to: '/', label: 'Targets', end: true },
                { to: '/access', label: 'My access' },
                { to: '/sessions', label: 'My sessions' },
              ]}
            />
          </Guard>
        }
      >
        <Route index element={<Targets />} />
        <Route path="access" element={<MyAccess />} />
        <Route path="sessions" element={<MySessions />} />
      </Route>
      <Route
        path="/admin"
        element={
          <Guard roles={['admin']}>
            <Shell
              portal="admin"
              items={[
                { to: '/admin', label: 'Dashboard', end: true },
                { to: '/admin/hosts', label: 'Hosts' },
                { to: '/admin/databases', label: 'Databases' },
                { to: '/admin/applications', label: 'Applications' },
                { to: '/admin/autoscaling', label: 'Autoscaling' },
                { to: '/admin/credentials', label: 'Credentials' },
                { to: '/admin/policies', label: 'Policies' },
                { to: '/admin/approvals', label: 'Approvals', badge: pendingApprovals },
                { to: '/admin/users', label: 'Users & groups' },
                { to: '/admin/identity-providers', label: 'Identity providers' },
                { to: '/admin/sessions', label: 'Sessions' },
                { to: '/admin/retention', label: 'Retention' },
                { to: '/admin/settings', label: 'Settings' },
                { to: '/admin/logs', label: 'Logs' },
                { to: '/admin/events', label: 'Events' },
                { to: '/admin/recordings', label: 'Recordings' },
              ]}
            />
          </Guard>
        }
      >
        {adminRoutes}
        {adminAuditRoutes}
      </Route>
      <Route
        path="/audit"
        element={
          <Guard roles={['admin', 'auditor']}>
            <AdminToConsole>
              <Shell
                portal="audit"
                items={[
                  { to: '/audit', label: 'Dashboard', end: true },
                  { to: '/audit/events', label: 'Events' },
                  { to: '/audit/recordings', label: 'Recordings' },
                  { to: '/audit/sessions', label: 'Sessions' },
                ]}
              />
            </AdminToConsole>
          </Guard>
        }
      >
        {auditRoutes}
      </Route>
      {/* The sign-in landing: resolves to the portal the account belongs in
          (ADR 0029). A named route rather than the * fallback, so the login
          page and the gateway's single sign-on have a stable next= to send
          an account whose roles they do not know yet. */}
      <Route path="/home" element={<Home />} />
      <Route path="*" element={<Home />} />
      </Routes>
    </>
  )
}
