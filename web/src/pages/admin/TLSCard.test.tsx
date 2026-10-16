import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { TLSStatus } from '../../api/types'
import { TLSCard } from './TLSCard'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const cert = (source: 'generated' | 'apps', hosts: string[]) => ({
  source, subject: 'CN=x', issuer: 'CN=x', hosts, not_before: '2026-01-01T00:00:00Z', not_after: '2028-01-01T00:00:00Z', fingerprint: 'ab', self_signed: source === 'generated',
})

// The applications certificate (ADR 0033) has its own section: what it
// serves, why applications cannot be enrolled yet, and its own upload.
describe('TLSCard applications', () => {
  it('names the apps domain, the problem, and uploads to the apps route', async () => {
    const before: TLSStatus = { mode: 'managed', active: cert('generated', ['gw.example.com']), apps_domain: 'apps.example.com', apps_ready: false, apps_problem: 'upload a certificate for *.apps.example.com first' }
    vi.spyOn(api, 'get').mockResolvedValue(before as never)
    const after: TLSStatus = { ...before, apps: cert('apps', ['*.apps.example.com']), apps_ready: true, apps_problem: undefined }
    const put = vi.spyOn(api, 'put').mockResolvedValue(after as never)
    render(<TLSCard />)

    expect(await screen.findByText(/upload a certificate for \*\.apps\.example\.com first/)).toBeDefined()
    const user = userEvent.setup()
    await user.type(document.getElementById('tls-apps-cert')!, 'CERT')
    await user.type(document.getElementById('tls-apps-key')!, 'KEY')
    await user.click(screen.getByRole('button', { name: 'Upload for applications' }))

    expect(put).toHaveBeenCalledWith('/admin/tls/apps', { cert_pem: 'CERT', key_pem: 'KEY' })
    expect(await screen.findByText('Applications certificate uploaded and serving.')).toBeDefined()
    // The sentence names the domain; the certificate's facts list the name it carries.
    expect(screen.getAllByText('*.apps.example.com')).toHaveLength(2)
    expect(screen.getByText(/Applications can be enrolled/)).toBeDefined()
    expect(screen.getByRole('button', { name: 'Remove applications certificate' })).toBeDefined()
  })

  it('says to set the domain first when there is none', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({ mode: 'managed', active: cert('generated', ['gw']) } as never)
    render(<TLSCard />)
    expect(await screen.findByText(/Set the apps domain under Applications above first/)).toBeDefined()
  })
})
