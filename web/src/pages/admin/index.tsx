import { lazy } from 'react'
import { Route } from 'react-router-dom'

// Each admin page is its own chunk, fetched when first opened (ADR 0010):
// the sign-in page and the user portal do not download the admin console.
const Targets = lazy(() => import('./Targets').then((m) => ({ default: m.Targets })))
const Databases = lazy(() => import('./Databases').then((m) => ({ default: m.Databases })))
const Autoscaling = lazy(() => import('./Autoscaling').then((m) => ({ default: m.Autoscaling })))
const Credentials = lazy(() => import('./Credentials').then((m) => ({ default: m.Credentials })))
const Policies = lazy(() => import('./Policies').then((m) => ({ default: m.Policies })))
const Approvals = lazy(() => import('./Approvals').then((m) => ({ default: m.Approvals })))
const UsersGroups = lazy(() => import('./UsersGroups').then((m) => ({ default: m.UsersGroups })))
const IdentityProviders = lazy(() => import('./IdentityProviders').then((m) => ({ default: m.IdentityProviders })))
const Sessions = lazy(() => import('./Sessions').then((m) => ({ default: m.Sessions })))
const Retention = lazy(() => import('./Retention').then((m) => ({ default: m.Retention })))
const Settings = lazy(() => import('./Settings').then((m) => ({ default: m.Settings })))
const Logs = lazy(() => import('./Logs').then((m) => ({ default: m.Logs })))

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
