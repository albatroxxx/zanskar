import { lazy, Suspense } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { useAuth } from './auth/AuthContext'
import { Empty } from './components/ui'
import { Shell } from './components/Shell'
import type { Role } from './api/types'
import { Login } from './pages/Login'
import { Targets } from './pages/user/Targets'
import { MySessions } from './pages/user/MySessions'

// The terminal pulls in xterm; load it only when a session opens.
const Terminal = lazy(() => import('./pages/user/Terminal').then((m) => ({ default: m.Terminal })))
const Desktop = lazy(() => import('./pages/user/Desktop').then((m) => ({ default: m.Desktop })))
import { adminRoutes } from './pages/admin'
import { auditRoutes } from './pages/audit'

function Guard({ roles, children }: { roles?: Role[]; children: React.ReactNode }) {
  const auth = useAuth()
  const loc = useLocation()
  if (auth.status === 'loading') return <div className="empty">Loading…</div>
  if (auth.status !== 'full') return <Navigate to="/login" state={{ from: loc.pathname }} replace />
  if (roles && !auth.hasRole(...roles)) return <Navigate to="/" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/terminal"
        element={
          <Guard>
            <Suspense fallback={<Empty>Loading terminal</Empty>}>
              <Terminal />
            </Suspense>
          </Guard>
        }
      />
      <Route
        path="/desktop"
        element={
          <Guard>
            <Suspense fallback={<Empty>Loading desktop</Empty>}>
              <Desktop />
            </Suspense>
          </Guard>
        }
      />
      <Route
        path="/"
        element={
          <Guard>
            <Shell
              portal="user"
              items={[
                { to: '/', label: 'Targets', end: true },
                { to: '/sessions', label: 'My sessions' },
              ]}
            />
          </Guard>
        }
      >
        <Route index element={<Targets />} />
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
                { to: '/admin/credentials', label: 'Credentials' },
                { to: '/admin/policies', label: 'Policies' },
                { to: '/admin/users', label: 'Users & groups' },
                { to: '/admin/identity-providers', label: 'Identity providers' },
                { to: '/admin/sessions', label: 'Sessions' },
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
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
