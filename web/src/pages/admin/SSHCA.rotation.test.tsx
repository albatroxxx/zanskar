import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { Credential } from '../../api/types'
import { CASetup } from './SSHCA'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const ca: Credential = {
  id: 'ca1', name: 'fleet-ca', type: 'ssh_ca', mode: 'vaulted', has_secret: true, public_key: 'ssh-ed25519 AAAA fleet-ca',
  created_at: '2026-10-06T10:00:00Z', updated_at: '2026-10-06T10:00:00Z', in_use_by: { targets: 0 },
}
const prepared: Credential = { ...ca, rotation: { pending_public_key: 'ssh-ed25519 BBBB next', pending_since: '2026-10-06T11:00:00Z' } }
const cutOver: Credential = { ...ca, public_key: 'ssh-ed25519 BBBB next', rotation: { retired_public_key: 'ssh-ed25519 AAAA fleet-ca', retired_at: '2026-10-06T12:00:00Z' } }

function mount(c: Credential) {
  vi.spyOn(api, 'get').mockResolvedValue({ items: [] } as never)
  const onSaved = vi.fn()
  render(<CASetup credential={c} onClose={() => {}} onSaved={onSaved} />)
  return onSaved
}

// The setup panel is itself a dialog, so the confirmation is found by its title.
async function confirm(buttonName: string | RegExp, title: string, confirmLabel: string) {
  const user = userEvent.setup()
  await user.click(await screen.findByRole('button', { name: buttonName }))
  await user.click(within(screen.getByRole('dialog', { name: title })).getByRole('button', { name: confirmLabel }))
}

// Review finding F1: Cut over pointed at the discard endpoint passed the one
// SSHCA test. Each step of the two-phase rotation (ADR 0022) must reach its
// own endpoint: prepare and cut over are POSTs, discard is the DELETE.
describe('SSHCA, the rotation steps', () => {
  it('prepares a next key', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue(prepared as never)
    const onSaved = mount(ca)
    await confirm('Prepare next key', 'Prepare a next key?', 'Prepare')
    expect(post).toHaveBeenCalledWith('/credentials/ca1/rotate', {})
    expect(onSaved).toHaveBeenCalledWith(prepared)
  })

  it('cuts over through the cut-over endpoint, never the discard one', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue(cutOver as never)
    const del = vi.spyOn(api, 'del').mockResolvedValue(ca as never)
    const onSaved = mount(prepared)
    await confirm('Cut over to the next key', 'Cut over to the next key?', 'Cut over')
    expect(post).toHaveBeenCalledTimes(1)
    expect(post).toHaveBeenCalledWith('/credentials/ca1/rotate/cut-over')
    expect(del).not.toHaveBeenCalled()
    expect(onSaved).toHaveBeenCalledWith(cutOver)
  })

  it('discards the prepared key through the DELETE, never the cut-over', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue(cutOver as never)
    const del = vi.spyOn(api, 'del').mockResolvedValue(ca as never)
    const onSaved = mount(prepared)
    await confirm('Discard next key', 'Discard the prepared key?', 'Discard')
    expect(del).toHaveBeenCalledTimes(1)
    expect(del).toHaveBeenCalledWith('/credentials/ca1/rotate')
    expect(post).not.toHaveBeenCalled()
    expect(onSaved).toHaveBeenCalledWith(ca)
  })

  it('confirms the old key removed through the retire endpoint', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue({ ...cutOver, rotation: undefined } as never)
    mount(cutOver)
    await confirm('Old key removed from targets', 'Old key removed from every target?', 'Confirm')
    expect(post).toHaveBeenCalledWith('/credentials/ca1/rotate/retire')
  })

  it('reports a refused step and keeps the dialog open', async () => {
    vi.spyOn(api, 'post').mockRejectedValue(new Error('a target still refuses the next key'))
    mount(prepared)
    await confirm('Cut over to the next key', 'Cut over to the next key?', 'Cut over')
    expect((await screen.findAllByText(/a target still refuses the next key/)).length).toBeGreaterThan(0)
    expect(screen.getByRole('dialog', { name: 'Cut over to the next key?' })).toBeDefined()
  })
})
