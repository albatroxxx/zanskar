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
import { Targets } from './pages/user/Targets'
import { MySessions } from './pages/user/MySessions'
import { MyAccess } from './pages/user/MyAccess'

// The terminal pulls in xterm; load it only when a session opens.
const Terminal = lazy(() => import('./pages/user/Terminal').then((m) => ({ default: m.Terminal })))
const Desktop = lazy(() => import('./pages/user/Desktop').then((m) => ({ default: m.Desktop })))
const Shadow = lazy(() => import('./pages/audit/Shadow').then((m) => ({ default: m.Shadow })))
import { adminRoutes } from './pages/admin'
import { auditRoutes } from './pages/audit'

function Guard({ roles, children }: { roles?: Role[]; children: React.ReactNode }) {
  const auth = useAuth()
  const loc = useLocation()
  if (auth.status === 'loading') return <div className="empty">Loading…</div>
  if (auth.status !== 'full') return <Navigate to="/login" state={{ from: loc.pathname }} replace />
  if (roles && !auth.hasRole(...roles)) {
    // Send the account to the portal it does have. An account with no role at
    // all (which the API refuses to create) would otherwise bounce forever.
    const home = homeFor(auth.user)
    if (home === loc.pathname || !auth.user?.roles.length) return <NoPortal />
    return <Navigate to={home} replace />
  }
  return <>{children}</>
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

// Home resolves "/" and unknown paths to the portal the account may enter.
function Home() {
  const auth = useAuth()
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
                { to: '/admin', label: 'Targets', end: true },
                { to: '/admin/autoscaling', label: 'Autoscaling' },
                { to: '/admin/credentials', label: 'Credentials' },
                { to: '/admin/policies', label: 'Policies' },
                { to: '/admin/approvals', label: 'Approvals', badge: pendingApprovals },
                { to: '/admin/users', label: 'Users & groups' },
                { to: '/admin/identity-providers', label: 'Identity providers' },
                { to: '/admin/sessions', label: 'Sessions' },
                { to: '/admin/retention', label: 'Retention' },
                { to: '/audit', label: 'Audit & recordings' },
              ]}
            />
          </Guard>
        }
      >
        {adminRoutes}
      </Route>
      <Route
        path="/audit"
        element={
          <Guard roles={['admin', 'auditor']}>
            <Shell
              portal="audit"
              items={[
                { to: '/audit', label: 'Events', end: true },
                { to: '/audit/recordings', label: 'Recordings' },
              ]}
            />
          </Guard>
        }
      >
        {auditRoutes}
      </Route>
      <Route path="*" element={<Home />} />
      </Routes>
    </>
  )
}
