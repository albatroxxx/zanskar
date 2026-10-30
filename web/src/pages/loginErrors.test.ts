import { describe, expect, it } from 'vitest'
import { safeReturnPath, signInError } from './loginErrors'

// L6: the page put whatever ?error= held inside the gateway's own alert, so
// a link could make the real sign-in page show an attacker's words. Only
// the reasons the gateway sends are shown, each in plain words.
describe('signInError', () => {
  it('says what a known reason means', () => {
    expect(signInError('not_provisioned')).toBe('There is no account for you here yet. Ask an administrator to add you.')
    expect(signInError('domain_not_allowed')).toMatch(/email domain/)
    expect(signInError('reauth_not_done')).toMatch(/instead of asking for your password again/)
  })

  it('never repeats text it was handed', () => {
    const lure = 'Your account is locked. Call +1 555 0100 to unlock it'
    expect(signInError(lure)).toBe('Single sign-on did not complete. Try again, or ask an administrator.')
    expect(signInError('constructor')).toBe('Single sign-on did not complete. Try again, or ask an administrator.')
  })

  it('says nothing when there is no reason', () => {
    expect(signInError(null)).toBe('')
    expect(signInError('')).toBe('')
  })
})

// L7: after sign-in the page goes back to where the user was. Only a path
// on this site is accepted, so a crafted value cannot send them elsewhere.
describe('safeReturnPath', () => {
  it('keeps a path on this site', () => {
    expect(safeReturnPath('/admin/targets?tab=2#x')).toBe('/admin/targets?tab=2#x')
    expect(safeReturnPath('/')).toBe('/')
  })

  it('refuses anything that could leave it', () => {
    for (const bad of ['//evil.example/x', '/\\evil.example', 'https://evil.example', 'javascript:alert(1)', 'admin', '/\tx', '', undefined, null, 42]) {
      expect(safeReturnPath(bad)).toBe('/')
    }
  })
})
