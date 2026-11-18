import { Navigate, Route } from 'react-router-dom'
import { FabricMoved } from './FabricMoved'
import { Dashboard, Targets, Databases, Applications, Autoscaling, Fabric, Cloud, Credentials, Policies, PolicyEditor, PolicyReview, Approvals, UsersGroups, IdentityProviders, Sessions, Settings, Logs } from './pages'

// Admin pages, one per file. Paths match the sidebar in App.tsx. The console
// lands on the dashboard (ADR 0029); hosts moved to /admin/hosts.
export const adminRoutes = (
  <>
    <Route index element={<Dashboard />} />
    <Route path="hosts" element={<Targets />} />
    <Route path="databases" element={<Databases />} />
    <Route path="applications" element={<Applications />} />
    <Route path="autoscaling" element={<Autoscaling />} />
    {/* Kubernetes (Fabric in the code, ADR 0048) holds the clusters; its page sends an old autoscaling tab address back. */}
    <Route path="kubernetes" element={<Fabric />} />
    <Route path="kubernetes/:kind" element={<Fabric />} />
    {/* Cloud accounts (ADR 0050): a role in an account is a target. */}
    <Route path="cloud" element={<Cloud />} />
    {/* The section's address until 2.0.0 (2026-11-16); a bookmarked tab keeps its platform. */}
    <Route path="fabric" element={<FabricMoved />} />
    <Route path="fabric/:kind" element={<FabricMoved />} />
    <Route path="credentials" element={<Credentials />} />
    <Route path="policies" element={<Policies />} />
    <Route path="policies/new" element={<PolicyEditor />} />
    <Route path="policies/:id" element={<PolicyEditor />} />
    <Route path="policies/:id/review" element={<PolicyReview />} />
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
