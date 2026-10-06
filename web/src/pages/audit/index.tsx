import { Route } from 'react-router-dom'
import { Events } from './Events'
import { Recordings } from './Recordings'
import { Player } from './Player'
import { Sessions } from '../admin/Sessions'

// Auditor portal: read-only review of the audit chain, session recordings and
// live sessions, which an auditor can watch but not end.
// Every read here is itself audited.
export const auditRoutes = (
  <>
    <Route index element={<Events />} />
    <Route path="recordings" element={<Recordings />} />
    <Route path="recordings/:id" element={<Player />} />
    <Route path="sessions" element={<Sessions />} />
  </>
)

// The same pages inside the admin console (ADR 0006), so an admin reviews
// the log without leaving it for a second portal.
export const adminAuditRoutes = (
  <>
    <Route path="events" element={<Events />} />
    <Route path="recordings" element={<Recordings />} />
    <Route path="recordings/:id" element={<Player />} />
  </>
)
