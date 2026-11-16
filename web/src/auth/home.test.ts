import { describe, expect, it } from 'vitest'
import { homeFor } from './home'

// ADR 0029: sign-in lands on the portal's dashboard — administrators on
// /admin, accounts that can connect on the access portal, review-only
// accounts on /audit.
describe('homeFor', () => {
  it('lands an administrator on the admin dashboard', () => {
    expect(homeFor({ roles: ['admin'] })).toBe('/admin')
    expect(homeFor({ roles: ['admin', 'user'] })).toBe('/admin')
    expect(homeFor({ roles: ['admin', 'auditor'] })).toBe('/admin')
  })

  it('lands a user on the access portal and an auditor on the audit portal', () => {
    expect(homeFor({ roles: ['user'] })).toBe('/')
    expect(homeFor({ roles: ['user', 'auditor'] })).toBe('/')
    expect(homeFor({ roles: ['auditor'] })).toBe('/audit')
  })

  // ADR 0049: an account that only decides lands on its approvals; one that
  // also connects lands on the access portal, where the approvals are a link.
  it('lands an approver who cannot connect on the approvals, and one who can on the access portal', () => {
    expect(homeFor({ roles: ['approver'] })).toBe('/approvals')
    expect(homeFor({ roles: ['approver', 'user'] })).toBe('/')
    expect(homeFor({ roles: ['approver', 'auditor'] })).toBe('/audit')
  })

  it('sends an unknown account to the sign-in fallback', () => {
    expect(homeFor(null)).toBe('/')
    expect(homeFor({ roles: [] })).toBe('/')
  })
})
