import { Navigate, Route } from 'react-router-dom'
import { Dashboard, Targets, Databases, Applications, Autoscaling, Credentials, Policies, Approvals, UsersGroups, IdentityProviders, Sessions, Settings, Logs } from './pages'

// Admin pages, one per file. Paths match the sidebar in App.tsx. The console
// lands on the dashboard (ADR 0029); hosts moved to /admin/hosts.
export const adminRoutes = (
  <>
    <Route index element={<Dashboard />} />
    <Route path="hosts" element={<Targets />} />
    <Route path="databases" element={<Databases />} />
    <Route path="applications" element={<Applications />} />
    <Route path="autoscaling" element={<Autoscaling />} />
    <Route path="credentials" element={<Credentials />} />
    <Route path="policies" element={<Policies />} />
    <Route path="approvals" element={<Approvals />} />
    <Route path="users" element={<UsersGroups />} />
    <Route path="identity-providers" element={<IdentityProviders />} />
    <Route path="sessions" element={<Sessions />} />
    {/* Retention is a section of Settings now (2026-10-30); old links land on it. */}
    <Route path="retention" element={<Navigate to="/admin/settings#settings-recording-retention" replace />} />
    <Route path="settings" element={<Settings />} />
    <Route path="logs" element={<Logs />} />
  </>
)
