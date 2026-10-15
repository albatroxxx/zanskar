import { lazy } from 'react'

// Each admin page is its own chunk, fetched when first opened (ADR 0010):
// the sign-in page and the user portal do not download the admin console.
// They live apart from the route table, which exports elements rather than
// components, so fast refresh keeps working on both.
export const Dashboard = lazy(() => import('./Dashboard').then((m) => ({ default: m.Dashboard })))
export const Targets = lazy(() => import('./Targets').then((m) => ({ default: m.Targets })))
export const Databases = lazy(() => import('./Databases').then((m) => ({ default: m.Databases })))
export const Applications = lazy(() => import('./Applications').then((m) => ({ default: m.Applications })))
export const Autoscaling = lazy(() => import('./Autoscaling').then((m) => ({ default: m.Autoscaling })))
export const Credentials = lazy(() => import('./Credentials').then((m) => ({ default: m.Credentials })))
export const Policies = lazy(() => import('./Policies').then((m) => ({ default: m.Policies })))
export const Approvals = lazy(() => import('./Approvals').then((m) => ({ default: m.Approvals })))
export const UsersGroups = lazy(() => import('./UsersGroups').then((m) => ({ default: m.UsersGroups })))
export const IdentityProviders = lazy(() => import('./IdentityProviders').then((m) => ({ default: m.IdentityProviders })))
export const Sessions = lazy(() => import('./Sessions').then((m) => ({ default: m.Sessions })))
export const Retention = lazy(() => import('./Retention').then((m) => ({ default: m.Retention })))
export const Settings = lazy(() => import('./Settings').then((m) => ({ default: m.Settings })))
export const Logs = lazy(() => import('./Logs').then((m) => ({ default: m.Logs })))
