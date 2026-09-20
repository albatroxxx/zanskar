import { Route } from 'react-router-dom'
import { Events } from './Events'
import { Recordings } from './Recordings'
import { Player } from './Player'

// Auditor portal: read-only review of the audit chain and session recordings.
// Admins reach the same pages (ADR 0006); every read here is itself audited.
export const auditRoutes = (
  <>
    <Route index element={<Events />} />
    <Route path="recordings" element={<Recordings />} />
    <Route path="recordings/:id" element={<Player />} />
  </>
)
