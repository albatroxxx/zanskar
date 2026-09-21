import { Route } from 'react-router-dom'
import { Targets } from './Targets'
import { Credentials } from './Credentials'
import { Policies } from './Policies'
import { UsersGroups } from './UsersGroups'
import { IdentityProviders } from './IdentityProviders'
import { Sessions } from './Sessions'

// Admin pages, one per file. Paths match the sidebar in App.tsx.
export const adminRoutes = (
  <>
    <Route index element={<Targets />} />
    <Route path="credentials" element={<Credentials />} />
    <Route path="policies" element={<Policies />} />
    <Route path="users" element={<UsersGroups />} />
    <Route path="identity-providers" element={<IdentityProviders />} />
    <Route path="sessions" element={<Sessions />} />
  </>
)
