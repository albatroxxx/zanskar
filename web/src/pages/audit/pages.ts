import { lazy } from 'react'

// Loaded when first opened (ADR 0010); the player brings asciinema-player,
// which no other page needs. They live apart from the route tables, which
// export elements rather than components, so fast refresh keeps working.
export const Events = lazy(() => import('./Events').then((m) => ({ default: m.Events })))
export const Recordings = lazy(() => import('./Recordings').then((m) => ({ default: m.Recordings })))
export const Player = lazy(() => import('./Player').then((m) => ({ default: m.Player })))
export const Sessions = lazy(() => import('../admin/Sessions').then((m) => ({ default: m.Sessions })))
