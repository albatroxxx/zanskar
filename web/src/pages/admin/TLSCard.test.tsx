import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { TLSCertInfo, TLSStatus } from '../../api/types'
import { TLSCard } from './TLSCard'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const cert = (source: TLSCertInfo['source'], hosts: string[]): TLSCertInfo => ({
  source, subject: 'CN=x', issuer: 'CN=x', hosts, not_before: '2026-01-01T00:00:00Z', not_after: '2028-01-01T00:00:00Z', fingerprint: 'ab', self_signed: source === 'generated',
})

// The card manages the one certificate the gateway serves (ADR 0021): what
// is serving now, an upload that applies to the next connection, and its
// removal. Applications no longer have a certificate or a domain of their
// own (ADR 0034), so there is no second section.
describe('TLSCard', () => {
  it('shows the serving certificate and uploads a replacement to the TLS route', async () => {
    const before: TLSStatus = { mode: 'managed', active: cert('generated', ['gw.example.com']), generated: cert('generated', ['gw.example.com']) }
    vi.spyOn(api, 'get').mockResolvedValue(before as never)
    const uploaded = cert('uploaded', ['gw.example.com', 'www.example.com'])
    const put = vi.spyOn(api, 'put').mockResolvedValue({ ...before, active: uploaded, uploaded } as never)
    render(<TLSCard />)

    expect(await screen.findByText('Self-signed')).toBeDefined()
    expect(screen.getByText('gw.example.com')).toBeDefined()
    expect(screen.queryByRole('heading', { name: 'Applications' })).toBeNull()
    expect(screen.queryByText(/apps domain/)).toBeNull()

    const user = userEvent.setup()
    const upload = screen.getByRole('button', { name: 'Upload and serve' })
    expect(upload.hasAttribute('disabled')).toBe(true)
    await user.type(document.getElementById('tls-cert')!, 'CERT')
    await user.type(document.getElementById('tls-key')!, 'KEY')
    await user.click(upload)

    expect(put).toHaveBeenCalledWith('/admin/tls', { cert_pem: 'CERT', key_pem: 'KEY' })
    expect(await screen.findByText('Certificate uploaded and serving.')).toBeDefined()
    expect(screen.getByText('Uploaded')).toBeDefined()
    expect(screen.getByText('gw.example.com, www.example.com')).toBeDefined()
    expect(screen.getByRole('button', { name: 'Remove uploaded certificate' })).toBeDefined()
  })

  it('removes the uploaded certificate after a confirmation, back to the self-signed one', async () => {
    const uploaded = cert('uploaded', ['gw.example.com'])
    const generated = cert('generated', ['gw'])
    vi.spyOn(api, 'get').mockResolvedValue({ mode: 'managed', active: uploaded, uploaded, generated } as never)
    const del = vi.spyOn(api, 'del').mockResolvedValue({ mode: 'managed', active: generated, generated } as never)
    render(<TLSCard />)

    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Remove uploaded certificate' }))
    expect(screen.getByText(/browsers will warn again/)).toBeDefined()
    await user.click(screen.getByRole('button', { name: 'Remove' }))

    expect(del).toHaveBeenCalledWith('/admin/tls')
    expect(await screen.findByText('Uploaded certificate removed.')).toBeDefined()
    expect(screen.getByText('Self-signed')).toBeDefined()
  })

  it('says the proxy holds the certificate in proxy mode', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({ mode: 'proxy' } as never)
    render(<TLSCard />)
    expect(await screen.findByText(/Terminated by the proxy in front of the gateway/)).toBeDefined()
    expect(screen.queryByRole('button', { name: 'Upload and serve' })).toBeNull()
  })
})
