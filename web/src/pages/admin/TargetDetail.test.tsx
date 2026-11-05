import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { Target } from '../../api/types'
import { TargetDetail } from './TargetDetail'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const web: Target = {
  id: 't1', name: 'web-01', address: '10.0.0.5', os_family: 'linux', ports: { ssh: 22 }, capabilities: ['ssh'],
  host_key_fingerprint: null, host_key_status: 'trusted', tls_fingerprint: null, winrm_tls_fingerprint: null,
  tags: {}, status: 'active', notes: '', credentials: {}, created_at: '2026-10-06T10:00:00Z', updated_at: '2026-10-06T10:00:00Z', last_probed_at: null,
}

/** Drawer holds the target the way the targets page does: what a save returns is shown. */
function Drawer() {
  const [t, setT] = useState(web)
  return (
    <>
      <TargetDetail target={t} credentials={[]} onClose={() => {}} onChanged={setT} onDeleted={() => {}} onError={() => {}} />
      <output>status {t.status}</output>
    </>
  )
}

// The live console (2026-11-01): an RDP-only Windows host said "Host key:
// unknown", as if something were wrong with a key it never had.
describe('TargetDetail, the host key', () => {
  const probed = '2026-11-01T10:00:00Z'
  const show = (t: Target) => render(<TargetDetail target={t} credentials={[]} onClose={() => {}} onChanged={() => {}} onDeleted={() => {}} onError={() => {}} />)

  it('is not shown for a probed host without SSH', () => {
    show({ ...web, os_family: 'windows', ports: {}, capabilities: ['rdp', 'winrm'], host_key_status: 'unknown', last_probed_at: probed })
    expect(screen.queryByText('Host key')).toBeNull()
    expect(screen.getByText('RDP, WinRM')).toBeDefined()
  })

  it('is shown for a host with SSH, and for one never probed', () => {
    show({ ...web, last_probed_at: probed })
    expect(screen.getByText('Host key')).toBeDefined()
    expect(screen.getByText('SSH', { selector: 'dd' })).toBeDefined()
    cleanup()
    show({ ...web, capabilities: [], host_key_status: 'unknown' })
    expect(screen.getByText('Host key')).toBeDefined()
  })
})

// B25: Disable had no busy state, so a double-click sent two PUTs, and once
// the first had answered the second turned the target back on.
describe('TargetDetail, Disable', () => {
  it('sends one change while the first is in flight', async () => {
    let answer: (t: Target) => void = () => {}
    const put = vi.spyOn(api, 'put').mockImplementation(() => new Promise((resolve) => { answer = resolve as (t: Target) => void }))
    render(<Drawer />)

    await userEvent.setup().dblClick(screen.getByRole('button', { name: 'Disable' }))
    answer({ ...web, status: 'disabled' })

    expect(await screen.findByText('status disabled')).toBeDefined()
    expect(put).toHaveBeenCalledTimes(1)
  })

  it('is not undone by the second click of a double-click', async () => {
    const put = vi.spyOn(api, 'put').mockImplementation(async (_path: string, body?: unknown) => ({ ...web, status: (body as Target).status }) as never)
    render(<Drawer />)

    await userEvent.setup().dblClick(screen.getByRole('button', { name: 'Disable' }))

    await waitFor(() => expect(screen.getByRole('button', { name: 'Enable' })).toBeDefined())
    expect(screen.getByText('status disabled')).toBeDefined()
    expect(put).toHaveBeenCalledTimes(1)
  })
})

// 2026-11-03: an application says where its pages load from beside its
// origins; one enrolled before the word reads as the default.
describe('TargetDetail, an application\'s dependencies', () => {
  const show = (t: Target) => render(<TargetDetail target={t} credentials={[]} onClose={() => {}} onChanged={() => {}} onDeleted={() => {}} onError={() => {}} />)
  const wiki: Target = { ...web, name: 'wiki', address: 'wiki.corp', os_family: 'other', ports: {}, capabilities: [], app_upstream: 'http://wiki.corp' }

  it('says any public address by default, and its origins only when held to them', () => {
    show(wiki)
    expect(screen.getByText('Dependencies')).toBeDefined()
    expect(screen.getByText('Any public address')).toBeDefined()
    cleanup()
    show({ ...wiki, app_dependencies: 'origins' })
    expect(screen.getByText('Its origins only')).toBeDefined()
    cleanup()
    show(web)
    expect(screen.queryByText('Dependencies')).toBeNull()
  })
})

// 2026-11-03, later: what the application's sessions were refused as
// dependencies, learned from the relay, with a private host allowed in one
// click, a page marked as an endpoint's business, and an address that can
// never be allowed marked as such; an application held to its origins
// learns nothing and shows nothing.
describe('TargetDetail, blocked dependencies', () => {
  const wiki: Target = { ...web, id: 'w1', name: 'wiki', address: 'wiki.corp', os_family: 'other', ports: {}, capabilities: [], app_upstream: 'http://wiki.corp' }
  const refused = [
    { host: 'cdn.corp', port: 443, why: 'private', what: 'script', from: 'http://wiki.corp', count: 7, first_seen: '2026-11-03T10:00:00Z', last_seen: '2026-11-03T10:05:00Z' },
    { host: '169.254.169.254', port: 80, why: 'link-local', what: 'image', from: 'http://wiki.corp', count: 1, first_seen: '2026-11-03T10:00:00Z', last_seen: '2026-11-03T10:00:00Z' },
    { host: 'news.example', port: 443, why: 'not an origin of the application', what: 'document', from: '', count: 2, first_seen: '2026-11-03T10:00:00Z', last_seen: '2026-11-03T10:01:00Z' },
  ]
  const serve = () =>
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path === '/targets/w1/dependencies') return { items: refused } as never
      return new Promise(() => {}) as never
    })

  it('lists them with what asked, allows a private host in one click and marks the rest', async () => {
    const get = serve()
    const onChanged = vi.fn()
    const allowed = { ...wiki, app_private: { hosts: ['cdn.corp:443'] } }
    const put = vi.spyOn(api, 'put').mockResolvedValue(allowed as never)
    render(<TargetDetail target={wiki} credentials={[]} onClose={() => {}} onChanged={onChanged} onDeleted={() => {}} onError={() => {}} />)
    expect(await screen.findByText('cdn.corp:443')).toBeDefined()
    expect(get).toHaveBeenCalledWith('/targets/w1/dependencies')
    expect(screen.getByText('script')).toBeDefined()
    expect(screen.getByRole('button', { name: 'Never allowed: link-local' })).toBeDefined()
    expect(screen.getByText('not an endpoint')).toBeDefined()
    // a host, a kind and a time stay on one line each (live 2026-11-05: ":8/0", "docume/nt"); only the asking page may break
    expect(screen.getByRole('table').className).toContain('blocked')
    expect(screen.getByText('cdn.corp:443').closest('tr')?.querySelector('td.from')?.textContent).toBe('http://wiki.corp')
    await userEvent.setup().click(screen.getByRole('button', { name: 'Allow' }))
    await waitFor(() => expect(put).toHaveBeenCalledWith('/targets/w1', expect.objectContaining({ app_private: { hosts: ['cdn.corp:443'] } })))
    expect(onChanged).toHaveBeenCalledWith(allowed)
    await waitFor(() => expect(screen.queryByText('cdn.corp:443')).toBeNull())
    expect(screen.getByText('169.254.169.254:80')).toBeDefined()
  })

  it('leaves out what is allowed already, and forgets the list on Clear', async () => {
    serve()
    const del = vi.spyOn(api, 'del').mockResolvedValue(undefined as never)
    render(<TargetDetail target={{ ...wiki, app_private: { hosts: ['cdn.corp:443'] } }} credentials={[]} onClose={() => {}} onChanged={() => {}} onDeleted={() => {}} onError={() => {}} />)
    expect(await screen.findByText('169.254.169.254:80')).toBeDefined()
    expect(screen.queryByText('cdn.corp:443')).toBeNull()
    await userEvent.setup().click(screen.getByRole('link', { name: 'Clear' }))
    await waitFor(() => expect(del).toHaveBeenCalledWith('/targets/w1/dependencies'))
    expect(await screen.findByText('Nothing refused')).toBeDefined()
  })

  it('shows nothing for an application held to its origins', async () => {
    const get = serve()
    render(<TargetDetail target={{ ...wiki, app_dependencies: 'origins' }} credentials={[]} onClose={() => {}} onChanged={() => {}} onDeleted={() => {}} onError={() => {}} />)
    expect(screen.getByText('Its origins only')).toBeDefined()
    expect(screen.queryByText('Blocked')).toBeNull()
    expect(get).not.toHaveBeenCalledWith('/targets/w1/dependencies')
  })
})
