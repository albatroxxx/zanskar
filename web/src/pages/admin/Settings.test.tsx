import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../../api/client'
import type { RuntimeSetting, SettingsListing } from '../../api/types'
import { Settings } from './Settings'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

function setting(over: Partial<RuntimeSetting>): RuntimeSetting {
  return { key: 'k', category: 'General', title: 'Title', description: 'What it does.', type: 'string', default: '', value: '', source: 'default', ...over }
}

const listing: SettingsListing = {
  runtime: [
    setting({ key: 'updates.check', category: 'Updates', title: 'Check for new versions', type: 'bool', default: 'true', value: 'true' }),
    setting({ key: 'login_banner', category: 'Sign-in', title: 'Sign-in banner', type: 'text', value: '', env_var: 'ZANSKAR_LOGIN_BANNER' }),
    setting({ key: 'log.level', category: 'Logging', title: 'Log level', type: 'enum', enum: ['debug', 'info', 'warn', 'error'], default: 'info', value: 'warn', source: 'console', updated_at: '2026-10-20T10:00:00Z', env_var: 'ZANSKAR_LOG_LEVEL' }),
    setting({ key: 'guacd.addr', category: 'Desktops', title: 'guacd address', type: 'hostport', value: 'guacd:4822', source: 'environment', env_var: 'ZANSKAR_GUACD_ADDR' }),
  ],
  boot: [
    { key: 'listen', title: 'Listen address', env_var: 'ZANSKAR_LISTEN_ADDR', value: ':8443', description: 'Where the gateway listens.' },
    { key: 'db', title: 'Database', env_var: 'ZANSKAR_DB_DSN', value: 'sqlite', description: '' },
    { key: 'tls', title: 'TLS hosts', env_var: 'ZANSKAR_TLS_*', value: 'gw.example', description: '' },
  ],
}

/** serves the settings page's reads; the TLS and storage cards get the least they render with. */
function serve(l: SettingsListing = listing, changed: string[] = []) {
  return vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path === '/admin/settings') return l as never
    if (path === '/admin/system/status') return { env_file: { state: changed.length ? 'changed' : 'unchanged', changed } } as never
    if (path === '/admin/tls') return { mode: 'managed', active: { source: 'generated', hosts: ['gw'], subject: 'gw', issuer: 'gw', not_before: '2026-01-01T00:00:00Z', not_after: '2027-01-01T00:00:00Z', fingerprint: 'ab' } } as never
    if (path === '/admin/storage') return { source: 'local', counts: {}, move: { running: false, moved: 0, failed: 0, total: 0 } } as never
    return {} as never
  })
}

describe('Settings', () => {
  it('groups runtime settings by category and says where each value comes from', async () => {
    serve()
    render(<Settings />)
    expect(await screen.findByRole('heading', { name: 'Updates' })).toBeDefined()
    expect(screen.getByRole('heading', { name: 'Sign-in' })).toBeDefined()
    expect(screen.getByRole('heading', { name: 'Logging' })).toBeDefined()
    expect(screen.getByRole('heading', { name: 'Desktops' })).toBeDefined()

    const level = screen.getByText('Log level').closest('.setting-row') as HTMLElement
    expect(within(level).getByText('Set in console')).toBeDefined()
    expect(within(level).getByText(/Changed /)).toBeDefined()
    expect(within(level).getByRole('button', { name: 'Reset' })).toBeDefined()
    expect((within(level).getByLabelText('Log level') as HTMLSelectElement).value).toBe('warn')

    const guacd = screen.getByText('guacd address').closest('.setting-row') as HTMLElement
    expect(within(guacd).getByText('From ZANSKAR_GUACD_ADDR')).toBeDefined()
    expect(within(guacd).queryByRole('button', { name: 'Reset' })).toBeNull()
    expect((within(guacd).getByLabelText('guacd address') as HTMLInputElement).placeholder).toBe('host:port')

    const check = screen.getByText('Check for new versions').closest('.setting-row') as HTMLElement
    expect(within(check).getByText('Default')).toBeDefined()
    expect(within(check).getByText('On')).toBeDefined()
    // Nothing to save until something changes.
    expect((within(check).getByRole('button', { name: 'Save' }) as HTMLButtonElement).disabled).toBe(true)
  })

  it('saves a change with PUT, says it applied, and discards an unsaved one', async () => {
    serve()
    const put = vi.spyOn(api, 'put').mockResolvedValue(setting({ key: 'updates.check', category: 'Updates', title: 'Check for new versions', type: 'bool', default: 'true', value: 'false', source: 'console' }) as never)
    render(<Settings />)
    const user = userEvent.setup()
    const row = (await screen.findByText('Check for new versions')).closest('.setting-row') as HTMLElement
    await user.click(within(row).getByLabelText('On'))
    expect(within(row).getByText('Off')).toBeDefined()
    await user.click(within(row).getByRole('button', { name: 'Discard' }))
    expect(within(row).getByText('On')).toBeDefined()
    expect(put).not.toHaveBeenCalled()

    await user.click(within(row).getByLabelText('On'))
    await user.click(within(row).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(put).toHaveBeenCalledWith('/admin/settings/updates.check', { value: 'false' }))
    expect(await within(row).findByText('Applied.')).toBeDefined()
    expect(within(row).getByText('Set in console')).toBeDefined()
    expect(within(row).getByRole('button', { name: 'Reset' })).toBeDefined()
  })

  it('resets a console value with DELETE and shows a refused save in its own row', async () => {
    serve()
    const del = vi.spyOn(api, 'del').mockResolvedValue(setting({ key: 'log.level', category: 'Logging', title: 'Log level', type: 'enum', enum: ['debug', 'info', 'warn', 'error'], default: 'info', value: 'info', source: 'default' }) as never)
    vi.spyOn(api, 'put').mockRejectedValue(new ApiError(422, { code: 'invalid', message: 'guacd address must be host:port', request_id: 'r' }, '422'))
    render(<Settings />)
    const user = userEvent.setup()
    const level = (await screen.findByText('Log level')).closest('.setting-row') as HTMLElement
    await user.click(within(level).getByRole('button', { name: 'Reset' }))
    await waitFor(() => expect(del).toHaveBeenCalledWith('/admin/settings/log.level'))
    expect(await within(level).findByText('Default')).toBeDefined()
    expect((within(level).getByLabelText('Log level') as HTMLSelectElement).value).toBe('info')

    const guacd = screen.getByText('guacd address').closest('.setting-row') as HTMLElement
    await user.clear(within(guacd).getByLabelText('guacd address'))
    await user.type(within(guacd).getByLabelText('guacd address'), 'nonsense')
    await user.click(within(guacd).getByRole('button', { name: 'Save' }))
    expect(await within(guacd).findByText('guacd address must be host:port')).toBeDefined()
    expect(within(level).queryByText('guacd address must be host:port')).toBeNull()
  })

  it('previews the sign-in banner as typed', async () => {
    serve()
    render(<Settings />)
    const user = userEvent.setup()
    const row = (await screen.findByText('Sign-in banner')).closest('.setting-row') as HTMLElement
    expect(within(row).queryByText('Preview')).toBeNull()
    await user.type(within(row).getByLabelText('Sign-in banner'), 'Authorised use only.')
    expect(within(row).getByText('Preview')).toBeDefined()
    expect(row.querySelector('.login-banner')!.textContent).toBe('Authorised use only.')
  })

  it('lists install-time settings read-only, marking the ones the file has changed since start', async () => {
    serve(listing, ['ZANSKAR_DB_DSN', 'ZANSKAR_TLS_HOSTS'])
    render(<Settings />)
    const table = (await screen.findByRole('heading', { name: 'Set at install' })).closest('.card') as HTMLElement
    const rows = within(table).getAllByRole('row').slice(1)
    expect(rows.map((r) => within(r).getAllByRole('cell')[2].textContent)).toEqual(['ZANSKAR_LISTEN_ADDR', 'ZANSKAR_DB_DSN', 'ZANSKAR_TLS_*'])
    expect(within(rows[0]).queryByText('changed in file')).toBeNull()
    expect(within(rows[1]).getByText('changed in file')).toBeDefined()
    expect(within(rows[2]).getByText('changed in file')).toBeDefined()
    expect(within(table).queryByRole('textbox')).toBeNull()
  })

  it('names a failed read instead of loading forever', async () => {
    vi.spyOn(api, 'get').mockRejectedValue(new ApiError(500, { code: 'internal', message: 'database is locked', request_id: 'req-5' }, '500'))
    render(<Settings />)
    expect(await screen.findByText('database is locked (reference req-5)')).toBeDefined()
    expect(screen.queryByText('Loading…')).toBeNull()
  })
})
