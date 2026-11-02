import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import { ConfigCard } from './ConfigCard'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// 2026-11-03, idea 10 (ADR 0043): the configuration as a file; an import
// shows its plan first and changes nothing until Apply.
const yaml = 'zanskar: 1\ntargets:\n  - name: web-1\n'
const pick = async (text = yaml) => {
  const user = userEvent.setup()
  await user.upload(screen.getByLabelText('Import a configuration file'), new File([text], 'gw.yaml', { type: 'application/yaml' }))
  return user
}

describe('Configuration file', () => {
  it('exports with a download link', () => {
    render(<ConfigCard />)
    expect(screen.getByRole('link', { name: 'Export' }).getAttribute('href')).toBe('/api/v1/admin/config/export')
  })

  it('shows the plan, then applies it on request', async () => {
    const upload = vi.spyOn(api, 'upload')
      .mockResolvedValueOnce({ applied: false, changes: [{ kind: 'target', name: 'web-1', action: 'create' }, { kind: 'group', name: 'ops', action: 'unchanged' }] } as never)
      .mockResolvedValueOnce({ applied: true, changes: [{ kind: 'target', name: 'web-1', action: 'create', applied: true }, { kind: 'group', name: 'ops', action: 'unchanged' }] } as never)
    render(<ConfigCard />)
    const user = await pick()
    expect(upload).toHaveBeenCalledWith('/admin/config/import', yaml, 'application/yaml')
    expect(await screen.findByText(/gw.yaml would change 1 thing\. Nothing has changed yet\./)).toBeDefined()
    await user.click(screen.getByRole('button', { name: 'Apply 1 change' }))
    expect(upload).toHaveBeenLastCalledWith('/admin/config/import?apply=true', yaml, 'application/yaml')
    expect(await screen.findByText('Imported gw.yaml.')).toBeDefined()
    expect(screen.getByText('created')).toBeDefined()
  })

  it('says why a file cannot be imported, and offers no Apply', async () => {
    vi.spyOn(api, 'upload').mockResolvedValue({ applied: false, changes: [{ kind: 'target', name: 'db-1', action: 'create', problem: 'credential "nowhere" does not exist on this gateway; add it first' }] } as never)
    render(<ConfigCard />)
    await pick()
    expect(await screen.findByText(/cannot be imported: 1 problem below\. Nothing changed\./)).toBeDefined()
    expect(screen.getByText(/credential "nowhere" does not exist/)).toBeDefined()
    expect(screen.queryByRole('button', { name: /^Apply/ })).toBeNull()
  })

  it('shows what an apply the gateway stopped did', async () => {
    vi.spyOn(api, 'upload')
      .mockResolvedValueOnce({ applied: false, changes: [{ kind: 'target', name: 'meta', action: 'create' }] } as never)
      .mockRejectedValueOnce(new ApiError(409, { applied: true, changes: [{ kind: 'target', name: 'meta', action: 'create', error: 'the gateway does not connect to this address' }] } as never, '409'))
    render(<ConfigCard />)
    const user = await pick()
    await user.click(await screen.findByRole('button', { name: 'Apply 1 change' }))
    expect(await screen.findByText(/does not connect to this address/)).toBeDefined()
    expect(screen.getByText('refused')).toBeDefined()
  })
})
