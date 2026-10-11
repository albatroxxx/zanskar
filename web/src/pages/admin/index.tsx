import { Route } from 'react-router-dom'
import { Targets, Databases, Autoscaling, Credentials, Policies, Approvals, UsersGroups, IdentityProviders, Sessions, Retention, Settings, Logs } from './pages'

// Admin pages, one per file. Paths match the sidebar in App.tsx.
export const adminRoutes = (
  <>
    <Route index element={<Targets />} />
    <Route path="databases" element={<Databases />} />
    <Route path="autoscaling" element={<Autoscaling />} />
    <Route path="credentials" element={<Credentials />} />
    <Route path="policies" element={<Policies />} />
    <Route path="approvals" element={<Approvals />} />
    <Route path="users" element={<UsersGroups />} />
    <Route path="identity-providers" element={<IdentityProviders />} />
    <Route path="sessions" element={<Sessions />} />
    <Route path="retention" element={<Retention />} />
    <Route path="settings" element={<Settings />} />
    <Route path="logs" element={<Logs />} />
  </>
)
