import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { Credential, Target } from '../../api/types'
import { Databases } from './Databases'
import { Targets } from './Targets'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const db: Target = {
  id: 't1', name: 'orders', address: 'orders.rds.example', os_family: 'other', engine: 'postgres', engine_version: '16', database_name: 'orders',
  tls_mode: 'require', ports: { database: 5432 }, capabilities: ['database'], host_key_fingerprint: null, host_key_status: 'unknown',
  tls_fingerprint: null, winrm_tls_fingerprint: null, tags: {}, status: 'active', notes: '', credentials: { database: 'c1' },
  created_at: '2026-10-06T10:00:00Z', updated_at: '2026-10-06T10:00:00Z', last_probed_at: null,
}

const cred: Credential = { id: 'c1', name: 'orders-admin', type: 'password', mode: 'vaulted', has_secret: true, created_at: '', updated_at: '' }

function serve(targets: Target[]) {
  return vi.spyOn(api, 'get').mockImplementation(async (path: string) => ({ items: path.startsWith('/credentials') ? [cred] : targets }) as never)
}

// D14: hosts and databases were the same page written twice. One TargetsPage
// now lists a kind, adds one of that kind, and fills its own columns.
describe('TargetsPage', () => {
  it('lists its own kind in its own columns, and adds one of that kind', async () => {
    const get = serve([db])
    render(<Databases />)

    const row = (await screen.findByText('orders-admin')).closest('tr')!
    expect(get).toHaveBeenCalledWith('/targets?limit=500&kind=database')
    expect(within(row).getByText('PostgreSQL 16')).toBeDefined()
    expect(within(row).getByText('orders.rds.example:5432')).toBeDefined()
    expect(within(row).getByText('Encrypted, not verified')).toBeDefined()
    expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual(['Name', 'Engine', 'Endpoint', 'Database', 'TLS', 'Credential', 'Tags', ''])

    await userEvent.setup().click(screen.getByRole('button', { name: 'Add database' }))

    const form = screen.getByRole('dialog', { name: 'Add database' })
    expect(within(form).queryByRole('tablist')).toBeNull()
    expect(within(form).getByLabelText('Engine')).toBeDefined()
  })

  it('says how to start when there is none of its kind', async () => {
    const get = serve([])
    render(<Targets />)

    expect(await screen.findByText('No hosts yet. Add one to get started; databases are added under Databases.')).toBeDefined()
    expect(get).toHaveBeenCalledWith('/targets?limit=500&kind=host')
  })
})
