import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { Target } from '../../api/types'
import { PolicyEditor } from './PolicyEditor'
import { fromDraft, grantSummary, isImplicit, kindOf, newGrant, toDraft } from './policyModel'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const role: Target = {
  id: 'c1', name: 'prod-admin', address: '', os_family: 'other', ports: {}, capabilities: ['cloud'], host_key_fingerprint: null, host_key_status: 'unknown',
  tls_fingerprint: null, winrm_tls_fingerprint: null, tags: {}, status: 'active', state: 'active', tls_status: 'none', winrm_tls_status: 'none', notes: '', credentials: {},
  created_at: '', updated_at: '', last_probed_at: null,
  cloud_platform: 'aws', cloud_account_id: '111111111111', cloud_account_alias: 'prod', cloud_role_arn: 'arn:aws:iam::111111111111:role/Admin', cloud_max_minutes: 60,
}

// A cloud grant (ADR 0050): the kind is a cloud account's role, its one
// protocol is implied, its two doors are switches both open, and it has no
// idle (the gateway sees no request stream) nor a credential to sign in with.
describe('PolicyEditor, a cloud grant', () => {
  it('offers the kind with its switches, and hides idle and sign-in', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (p: string) => ({ items: p.startsWith('/targets') ? [role] : [] }) as never)
    render(
      <MemoryRouter initialEntries={['/admin/policies/new']}>
        <Routes>
          <Route path="/admin/policies/new" element={<PolicyEditor />} />
        </Routes>
      </MemoryRouter>,
    )
    const user = userEvent.setup()
    expect(screen.getByLabelText('Idle (minutes)')).toBeDefined()
    await user.click(screen.getByRole('radio', { name: 'Cloud account' }))
    expect((screen.getByRole('checkbox', { name: 'Console' }) as HTMLInputElement).checked).toBe(true)
    expect((screen.getByRole('checkbox', { name: 'Command line' }) as HTMLInputElement).checked).toBe(true)
    expect(screen.queryByLabelText('Idle (minutes)')).toBeNull()
    expect(screen.getByLabelText('Session (minutes)')).toBeDefined()
    expect(screen.queryByText('Sign in with')).toBeNull()
    // The role is listed under its account; no protocol chips, the protocol is implied.
    expect(await screen.findByText('prod-admin')).toBeDefined()
    expect(screen.queryByRole('checkbox', { name: /Cloud on prod-admin/ })).toBeNull()
  })

  it('sends both doors, the implied protocol and the target credential', () => {
    const d = { ...toDraft(newGrant('cloud')), targets: { c1: [] as never[] }, cloud_console: false, max: '120' }
    const { grant, error } = fromDraft(d, () => 'prod-admin')
    expect(error).toBeUndefined()
    expect(grant).toMatchObject({ kind: 'cloud', targets: [{ id: 'c1', protocols: ['cloud'] }], cloud_console: false, cloud_cli: true, sign_in: 'target', max_session_minutes: 120 })
    expect(toDraft(grant!)).toMatchObject({ cloud_console: false, cloud_cli: true })
    // Read back from a 2.0 server that never said: both open.
    expect(toDraft({ ...grant!, cloud_console: undefined, cloud_cli: undefined })).toMatchObject({ cloud_console: true, cloud_cli: true })
  })

  it('summarises the doors and the session length instead of an idle', () => {
    const g = fromDraft({ ...toDraft(newGrant('cloud')), targets: { c1: [] as never[] }, cloud_cli: false, max: '' }, () => 'prod-admin').grant!
    expect(grantSummary(g, () => 'prod-admin')).toBe("Cloud account · prod-admin · Standing · MFA · console · role's max")
    expect(isImplicit('cloud')).toBe(true)
    expect(kindOf(role)).toBe('cloud')
  })
})
