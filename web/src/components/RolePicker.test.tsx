import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { normalizeRoles } from '../api/roles'
import type { Role } from '../api/types'
import { RolePicker } from './RolePicker'

afterEach(() => cleanup())

// 2026-11-03: with admin ticked, the auditor and user boxes still asked to
// be ticked too, though an administrator already reviews and connects.

function Harness({ start, seen }: { start: Role[]; seen: (r: Role[]) => void }) {
  const [roles, setRoles] = useState<Role[]>(start)
  return (
    <RolePicker
      value={roles}
      onChange={(r) => {
        seen(r)
        setRoles(r)
      }}
      idPrefix="t"
    />
  )
}

const box = (name: Role) => screen.getByLabelText(name) as HTMLInputElement

describe('the role picker', () => {
  it('shows auditor and user included, greyed out, once admin is ticked', async () => {
    const seen = vi.fn()
    render(<Harness start={['user']} seen={seen} />)
    const user = userEvent.setup()
    expect(box('auditor').disabled).toBe(false)
    expect(screen.queryByText('Admin includes auditor and user.')).toBeNull()
    await user.click(box('admin'))
    expect(seen).toHaveBeenLastCalledWith(['admin'])
    for (const r of ['auditor', 'user'] as Role[]) {
      expect(box(r).checked).toBe(true)
      expect(box(r).disabled).toBe(true)
      expect(box(r).getAttribute('aria-describedby')).toBe('t-role-note')
    }
    expect(screen.getByText('Admin includes auditor and user.').id).toBe('t-role-note')
    expect(box('admin').getAttribute('aria-describedby')).toBeNull()
  })

  it('gives back what was chosen before admin when admin is unticked', async () => {
    const seen = vi.fn()
    render(<Harness start={['auditor', 'user']} seen={seen} />)
    const user = userEvent.setup()
    await user.click(box('admin'))
    await user.click(box('admin'))
    expect(seen).toHaveBeenLastCalledWith(['auditor', 'user'])
    expect(box('auditor').disabled).toBe(false)
    expect(box('user').checked).toBe(true)
  })

  it('opens on an administrator kept with all three as admin alone, and unticking leaves none', async () => {
    const seen = vi.fn()
    render(<Harness start={['admin']} seen={seen} />)
    await userEvent.setup().click(box('admin'))
    expect(seen).toHaveBeenLastCalledWith([])
    expect(box('user').checked).toBe(false)
  })

  it('hands on roles as the gateway keeps them', async () => {
    const seen = vi.fn()
    render(<Harness start={[]} seen={seen} />)
    const user = userEvent.setup()
    await user.click(box('user'))
    await user.click(box('auditor'))
    expect(seen).toHaveBeenLastCalledWith(['auditor', 'user'])
    await user.click(box('user'))
    expect(seen).toHaveBeenLastCalledWith(['auditor'])
  })
})

describe('normalizeRoles', () => {
  it('keeps admin alone, and the others each once in order', () => {
    expect(normalizeRoles(['user', 'admin', 'auditor'])).toEqual(['admin'])
    expect(normalizeRoles(['user', 'auditor', 'user'])).toEqual(['auditor', 'user'])
    expect(normalizeRoles([])).toEqual([])
  })
})
