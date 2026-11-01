import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../api/client'
import type { HostStatus, SystemStatus, UpdateStatus } from '../api/types'
import { CornerBar } from './CornerBar'
import { pacing } from './hostAction'
import { setConsoleTheme, themeKey } from '../styles/theme'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const off = () => new ApiError(404, { code: 'not_found', message: 'off', request_id: 'r' }, '404')

const newer: UpdateStatus = { current: '1.4.0', latest: '1.5.0', notes_url: 'https://example.test/releases/#v1-5-0', newer: true, checked_at: '2026-10-15T06:00:00Z', enabled: true, installable: false }
const host: HostStatus = { hostname: 'gw-test', supervisor: 'systemd', available: true, mfa_fresh: false, step_up_minutes: 5 }
const up = (over: Partial<SystemStatus> = {}) => ({ version: '1.4.0', started_at: 'A', supervisor: 'systemd', live_sessions: 0, draining: false, ...over }) as SystemStatus

/** serve answers the corner strip's reads; statuses are handed out in turn,
 *  the last one repeating, an Error meaning the gateway is away. */
function serve(update: UpdateStatus | (() => UpdateStatus), h: HostStatus, statuses: (SystemStatus | Error)[] = [up()]) {
  let n = 0
  return vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path === '/admin/system/update') return (typeof update === 'function' ? update() : update) as never
    if (path === '/admin/system/host') return h as never
    if (path === '/admin/system/status') {
      const s = statuses[Math.min(n++, statuses.length - 1)]
      if (s instanceof Error) throw s
      return s as never
    }
    if (path === '/admin/cli') throw off()
    throw new Error('unexpected ' + path)
  })
}

function strip() {
  render(
    <MemoryRouter>
      <CornerBar />
    </MemoryRouter>,
  )
}

beforeEach(() => {
  pacing.pollMs = 5
})

describe('the corner strip', () => {
  it('lights the bell for a newer release and drops its panel from it', async () => {
    serve(newer, host)
    strip()
    const bell = await screen.findByRole('button', { name: 'Zanskar 1.5.0 is available' })
    expect(bell.getAttribute('aria-expanded')).toBe('false')
    await userEvent.setup().click(bell)
    expect(bell.getAttribute('aria-expanded')).toBe('true')
    const panel = await screen.findByRole('dialog', { name: 'Zanskar 1.5.0 is available' })
    expect(panel.closest('.corner-pop')).toBe(bell.closest('.corner-pop'))
    expect(within(panel).getByText('1.5.0')).toBeDefined()
    expect(within(panel).getByRole('link', { name: 'Release notes' }).getAttribute('href')).toBe('https://example.test/releases/#v1-5-0')
    expect(within(panel).getByText(/Install the new package on the host/)).toBeDefined()
  })

  it('stays quiet when nothing is newer', async () => {
    serve({ ...newer, latest: '1.4.0', newer: false }, host)
    strip()
    expect(await screen.findByRole('button', { name: 'Updates' })).toBeDefined()
    expect(screen.queryByRole('button', { name: /is available/ })).toBeNull()
  })

  // 2026-10-30: the gear opened a dialog in the middle of the page; it is a
  // menu under the gear now, worked with the keyboard as menus are.
  it('drops the gear menu under the gear, arrows through it, and Escape returns to the gear', async () => {
    serve(newer, host)
    strip()
    const user = userEvent.setup()
    const gear = await screen.findByRole('button', { name: 'Gateway actions' })
    await user.click(gear)
    const menu = await screen.findByRole('menu', { name: 'Gateway actions' })
    const items = within(menu).getAllByRole('menuitem')
    expect(items.map((i) => i.textContent)).toEqual(['Restart gateway', 'Reboot host', 'Stop host'])
    await waitFor(() => expect(document.activeElement).toBe(items[0]))
    await user.keyboard('{ArrowDown}')
    expect(document.activeElement).toBe(items[1])
    await user.keyboard('{ArrowUp}{ArrowUp}')
    expect(document.activeElement).toBe(items[2])
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('menu')).toBeNull()
    expect(document.activeElement).toBe(gear)
  })

  it('closes the menu on a click outside it', async () => {
    serve(newer, host)
    strip()
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Gateway actions' }))
    expect(await screen.findByRole('menu')).toBeDefined()
    await user.click(document.body)
    expect(screen.queryByRole('menu')).toBeNull()
  })

  // ADR 0032: a reboot asks for the hostname and, when the session's proof
  // is stale, an authenticator code, and proves the code before acting.
  // Then the dialog follows it to the end (2026-10-30).
  // 2026-11-01: "Reboot now" skips the wait without typing 0, behind the
  // same hostname and code.
  it('reboots now with the typed hostname, then follows it until the host is back', async () => {
    // the bell's read, the dialog's (how many are live), the one before acting
    serve(newer, host, [up(), up({ live_sessions: 2 }), up({ draining: true, live_sessions: 1 }), new TypeError('Failed to fetch'), up({ started_at: 'B' })])
    const post = vi.spyOn(api, 'post').mockResolvedValue({} as never)
    strip()
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Gateway actions' }))
    await user.click(await screen.findByRole('menuitem', { name: 'Reboot host' }))
    expect(await screen.findByText(/Minutes; 0 ends them now\. 2 live\./)).toBeDefined()
    const now = screen.getByRole('button', { name: 'Reboot now' })
    expect((now as HTMLButtonElement).disabled).toBe(true)
    await user.type(await screen.findByLabelText(/Type the hostname to confirm/), 'gw-test')
    expect((now as HTMLButtonElement).disabled).toBe(true)
    await user.type(screen.getByLabelText('Authenticator code'), '123456')
    expect(screen.getByLabelText<HTMLInputElement>(/Let live sessions finish for/).value).toBe('15')
    await user.click(now)

    expect(await screen.findByText('Host rebooted')).toBeDefined()
    expect(screen.getByRole('button', { name: 'Close' })).toBeDefined()
    expect(post.mock.calls[0]).toEqual(['/auth/mfa/step-up', { code: '123456' }])
    expect(post.mock.calls[1]).toEqual(['/admin/system/reboot', { wait_minutes: 0, confirm: 'gw-test' }])
  })

  it('offers one button that says now once the wait is 0, and restarts at once', async () => {
    serve(newer, host, [up(), up({ live_sessions: 0 }), up(), new TypeError('Failed to fetch'), up({ started_at: 'B' })])
    const post = vi.spyOn(api, 'post').mockResolvedValue({} as never)
    strip()
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Gateway actions' }))
    await user.click(await screen.findByRole('menuitem', { name: 'Restart gateway' }))
    expect(await screen.findByText(/None live\./)).toBeDefined()
    const dialog = screen.getByRole('dialog', { name: 'Restart gateway' })
    const buttons = () => within(dialog).getAllByRole('button').map((b) => b.textContent)
    expect(buttons()).toEqual(expect.arrayContaining(['Restart now', 'Restart']))
    await user.clear(screen.getByLabelText(/Let live sessions finish for/))
    await user.type(screen.getByLabelText(/Let live sessions finish for/), '0')
    expect(buttons().filter((t) => t?.startsWith('Restart'))).toEqual(['Restart now'])
    await user.click(within(dialog).getByRole('button', { name: 'Restart now' }))

    expect(await screen.findByText('Gateway restarted')).toBeDefined()
    expect(post.mock.calls).toEqual([['/admin/system/restart', { wait_minutes: 0 }]])
  })

  it('installs a newer release and says when it is back on it', async () => {
    let calls = 0
    serve(() => ({ ...newer, installable: true, ...(calls++ > 2 ? { install: { state: 'running', version: '1.5.0', message: 'downloading', at: 'now' } } : {}) }), host, [
      up(),
      up(),
      up({ draining: true }),
      new TypeError('Failed to fetch'),
      up({ started_at: 'B', version: '1.5.0' }),
    ])
    const post = vi.spyOn(api, 'post').mockResolvedValue({} as never)
    strip()
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Zanskar 1.5.0 is available' }))
    await user.click(await screen.findByRole('button', { name: 'Update now' }))
    expect(screen.queryByRole('dialog', { name: /is available/ })).toBeNull()
    await user.type(await screen.findByLabelText(/Type the hostname to confirm/), 'gw-test')
    await user.type(screen.getByLabelText('Authenticator code'), '654321')
    await user.click(screen.getByRole('button', { name: 'Install' }))

    expect(await screen.findByText('Updated to 1.5.0')).toBeDefined()
    expect(screen.getByRole('button', { name: 'Reload console' })).toBeDefined()
    expect(post.mock.calls[0]).toEqual(['/auth/mfa/step-up', { code: '654321' }])
    expect(post.mock.calls[1]).toEqual(['/admin/system/update/install', { version: '1.5.0', wait_minutes: 15, confirm: 'gw-test' }])
  })

  it('says why an update failed, in the installer\'s words', async () => {
    let calls = 0
    serve(() => ({ ...newer, installable: true, ...(calls++ > 2 ? { install: { state: 'failed', version: '1.5.0', message: 'the release signature did not verify', at: 'now' } } : {}) }), host, [up(), up({ draining: true })])
    vi.spyOn(api, 'post').mockResolvedValue({} as never)
    strip()
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Zanskar 1.5.0 is available' }))
    await user.click(await screen.findByRole('button', { name: 'Update now' }))
    await user.type(await screen.findByLabelText(/Type the hostname to confirm/), 'gw-test')
    await user.type(screen.getByLabelText('Authenticator code'), '654321')
    await user.click(screen.getByRole('button', { name: 'Install' }))
    const alert = await screen.findByText('the release signature did not verify')
    expect(alert.closest('.alert')?.className).toContain('danger')
  })

  it('shows the installer\'s last report', async () => {
    serve({ ...newer, installable: true, install: { state: 'failed', version: '1.5.0', message: 'the release signature did not verify; nothing was installed', at: '2026-10-15T10:00:00Z' } }, host)
    strip()
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Zanskar 1.5.0 is available' }))
    expect(await screen.findByText(/the release signature did not verify/)).toBeDefined()
  })

  // 2026-11-01: the theme menu (System, Light, Dark) became a switch, one
  // click to the other theme and one back, its circle turning each time.
  it('switches the theme with one click each way, and the circle turns', async () => {
    serve(newer, host)
    strip()
    const user = userEvent.setup()
    const half = () => document.querySelector<SVGPathElement>('.theme-toggle .theme-half')!.style.transform
    // jsdom's device is light and everyone is on system
    const toDark = await screen.findByRole('button', { name: 'Switch to the dark theme' })
    expect(toDark.getAttribute('aria-haspopup')).toBeNull()
    expect(half()).toBe('rotate(0deg)')

    await user.click(toDark)
    expect(screen.queryByRole('menu')).toBeNull()
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
    expect(localStorage.getItem(themeKey)).toBe('dark')
    expect(half()).toBe('rotate(180deg)')

    await user.click(screen.getByRole('button', { name: 'Switch to the light theme' }))
    expect(document.documentElement.hasAttribute('data-theme')).toBe(false)
    expect(localStorage.getItem(themeKey)).toBeNull()
    // one way round, never back the way it came
    expect(half()).toBe('rotate(360deg)')
  })

  it('turns the circle when the theme changes elsewhere, and only then', async () => {
    serve(newer, host)
    strip()
    const half = () => document.querySelector<SVGPathElement>('.theme-toggle .theme-half')!.style.transform
    await screen.findByRole('button', { name: 'Switch to the dark theme' })
    act(() => setConsoleTheme('dark'))
    expect(screen.getByRole('button', { name: 'Switch to the light theme' })).toBeDefined()
    expect(half()).toBe('rotate(180deg)')
    act(() => setConsoleTheme('dark'))
    expect(half()).toBe('rotate(180deg)')
    act(() => setConsoleTheme('system'))
  })

  it('offers no host actions off systemd, and says why', async () => {
    serve(newer, { ...host, supervisor: 'kubernetes', available: false, reason: 'Needs a systemd host; on Kubernetes, roll the deployment.' })
    strip()
    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Gateway actions' }))
    const reboot = await screen.findByRole('menuitem', { name: 'Reboot host' })
    expect(reboot.getAttribute('aria-disabled')).toBe('true')
    expect(screen.getByText(/on Kubernetes, roll the deployment/)).toBeDefined()
    expect(screen.getByRole('menuitem', { name: 'Restart gateway' }).getAttribute('aria-disabled')).toBeNull()
    await user.click(reboot)
    expect(screen.queryByLabelText(/Type the hostname/)).toBeNull()
  })
})
