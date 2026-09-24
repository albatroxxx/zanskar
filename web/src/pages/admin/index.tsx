import { Route } from 'react-router-dom'
import { Targets } from './Targets'
import { Autoscaling } from './Autoscaling'
import { Credentials } from './Credentials'
import { Policies } from './Policies'
import { Approvals } from './Approvals'
import { UsersGroups } from './UsersGroups'
import { IdentityProviders } from './IdentityProviders'
import { Sessions } from './Sessions'
import { Retention } from './Retention'

// Admin pages, one per file. Paths match the sidebar in App.tsx.
export const adminRoutes = (
  <>
    <Route index element={<Targets />} />
    <Route path="autoscaling" element={<Autoscaling />} />
    <Route path="credentials" element={<Credentials />} />
    <Route path="policies" element={<Policies />} />
    <Route path="approvals" element={<Approvals />} />
    <Route path="users" element={<UsersGroups />} />
    <Route path="identity-providers" element={<IdentityProviders />} />
    <Route path="sessions" element={<Sessions />} />
    <Route path="retention" element={<Retention />} />
  </>
)
