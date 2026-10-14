import { Route } from 'react-router-dom'
import { Dashboard, Events, Recordings, Player, Sessions } from './pages'

// Auditor portal: read-only review of the audit chain, session recordings and
// live sessions, which an auditor can watch but not end.
// Every read of rows here is itself audited; the dashboard's counts are not
// rows, which is why landing on it writes no audit.read event (ADR 0029).
export const auditRoutes = (
  <>
    <Route index element={<Dashboard />} />
    <Route path="events" element={<Events />} />
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
