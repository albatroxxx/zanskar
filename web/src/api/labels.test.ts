// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest'
import { sessionUser } from './labels'

describe('sessionUser', () => {
  it('names the person who opened the session', () => {
    expect(sessionUser({ username: 'alice', user_id: 'u1' })).toBe('alice')
  })

  it('marks a person whose account was deleted, under the name they had', () => {
    expect(sessionUser({ username: 'alice', user_id: 'u1', user_deleted: true })).toBe('alice (deleted)')
  })

  it('falls back to a short id for a session from before names were kept', () => {
    expect(sessionUser({ user_id: '0123456789abcdef', user_deleted: true })).toBe('01234567…')
    expect(sessionUser({ user_id: '' })).toBe('—')
  })
})
