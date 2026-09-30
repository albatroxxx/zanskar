import { Route } from 'react-router-dom'
import { Events } from './Events'
import { Recordings } from './Recordings'
import { Player } from './Player'

// Auditor portal: read-only review of the audit chain and session recordings.
// Every read here is itself audited.
export const auditRoutes = (
  <>
    <Route index element={<Events />} />
    <Route path="recordings" element={<Recordings />} />
    <Route path="recordings/:id" element={<Player />} />
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
