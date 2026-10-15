import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../api/client'
import type { HostStatus, UpdateStatus } from '../api/types'
import { CornerBar } from './CornerBar'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const off = () => new ApiError(404, { code: 'not_found', message: 'off', request_id: 'r' }, '404')

const newer: UpdateStatus = { current: '1.4.0', latest: '1.5.0', notes_url: 'https://example.test/releases/#v1-5-0', newer: true, checked_at: '2026-10-15T06:00:00Z', enabled: true }
const host: HostStatus = { hostname: 'gw-test', supervisor: 'systemd', available: true, mfa_fresh: false, step_up_minutes: 5 }

function serve(update: UpdateStatus, h: HostStatus) {
  vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path === '/admin/system/update') return update as never
    if (path === '/admin/system/host') return h as never
    if (path === '/admin/system/status') return { supervisor: 'systemd' } as never
    if (path === '/admin/cli') throw off()
    throw new Error('unexpected ' + path)
  })
}

describe('the corner strip', () => {
  it('lights the bell for a newer release and shows the notes', async () => {
    serve(newer, host)
    render(
      <MemoryRouter>
        <CornerBar />
      </MemoryRouter>,
    )
    const bell = await screen.findByRole('button', { name: 'Zanskar 1.5.0 is available' })
    await userEvent.setup().click(bell)
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('1.5.0')).toBeDefined()
    expect(within(dialog).getByRole('link', { name: 'Release notes' }).getAttribute('href')).toBe('https://example.test/releases/#v1-5-0')
    expect(within(dialog).getByText(/Install the new package on the host/)).toBeDefined()
  })

  it('stays quiet when nothing is newer', async () => {
    serve({ ...newer, latest: '1.4.0', newer: false }, host)
    render(
      <MemoryRouter>
        <CornerBar />
      </MemoryRouter>,
    )
    expect(await screen.findByRole('button', { name: 'Updates' })).toBeDefined()
    expect(screen.queryByRole('button', { name: /is available/ })).toBeNull()
  })

  // ADR 0032: a reboot asks for the hostname and, when the session's proof
  // is stale, an authenticator code, and proves the code before acting.
  it('proves the authenticator, then reboots with the typed hostname', async () => {
    serve(newer, host)
    const post = vi.spyOn(api, 'post').mockResolvedValue({} as never)
    render(
      <MemoryRouter>
        <CornerBar />
      </MemoryRouter>,
    )
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Gateway actions' }))
    await user.click(await screen.findByRole('button', { name: 'Reboot host' }))
    await user.clear(screen.getByLabelText(/Let live sessions finish for/))
    await user.type(screen.getByLabelText(/Let live sessions finish for/), '0')
    await user.type(await screen.findByLabelText(/Type the hostname to confirm/), 'gw-test')
    await user.type(screen.getByLabelText('Authenticator code'), '123456')
    await user.click(screen.getByRole('button', { name: 'Reboot' }))

    expect(await screen.findByText('Rebooting the host after the drain.')).toBeDefined()
    expect(post.mock.calls[0]).toEqual(['/auth/mfa/step-up', { code: '123456' }])
    expect(post.mock.calls[1]).toEqual(['/admin/system/reboot', { wait_minutes: 0, confirm: 'gw-test' }])
  })

  it('offers no host actions off systemd, and says why', async () => {
    serve(newer, { ...host, supervisor: 'kubernetes', available: false, reason: 'host actions need a systemd host; this gateway runs under kubernetes' })
    render(
      <MemoryRouter>
        <CornerBar />
      </MemoryRouter>,
    )
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Gateway actions' }))
    const reboot = await screen.findByRole('button', { name: 'Reboot host' })
    expect(reboot.hasAttribute('disabled')).toBe(true)
    expect(screen.getByText(/runs under kubernetes/)).toBeDefined()
    expect(screen.getByRole('button', { name: 'Restart gateway' }).hasAttribute('disabled')).toBe(false)
  })
})
