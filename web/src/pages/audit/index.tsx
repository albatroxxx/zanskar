import { lazy } from 'react'
import { Route } from 'react-router-dom'

// Loaded when first opened (ADR 0010); the player brings asciinema-player,
// which no other page needs.
const Events = lazy(() => import('./Events').then((m) => ({ default: m.Events })))
const Recordings = lazy(() => import('./Recordings').then((m) => ({ default: m.Recordings })))
const Player = lazy(() => import('./Player').then((m) => ({ default: m.Player })))
const Sessions = lazy(() => import('../admin/Sessions').then((m) => ({ default: m.Sessions })))

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
