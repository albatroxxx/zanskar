import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import type { AutoscalingGroup, Policy, PolicyGrant, Target } from '../../api/types'
import { Policies } from './Policies'
import { newGrant, reaches, tagsMatch } from './policyModel'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// 2026-11-03 live audit, Q9: the live host-access policy held an autoscaling
// grant by tag (env test) while no group was enrolled, and nothing said so.

const targets = [
  { id: 't1', name: 'web-1', os_family: 'linux', capabilities: ['ssh'], status: 'active', tags: { env: 'test' } },
  { id: 'd1', name: 'orders', os_family: 'other', engine: 'postgres', capabilities: [], status: 'active', tags: { env: 'test' } },
] as unknown as Target[]

const grant = (over: Partial<PolicyGrant>): PolicyGrant => ({ ...newGrant('host'), ...over })

describe('tagsMatch', () => {
  it('needs every key, each with one of its values', () => {
    expect(tagsMatch({ env: ['test', 'prod'] }, { env: 'test' })).toBe(true)
    expect(tagsMatch({ env: ['test'], tier: ['web'] }, { env: 'test' })).toBe(false)
    expect(tagsMatch({ env: ['prod'] }, { env: 'test' })).toBe(false)
    expect(tagsMatch({}, { env: 'test' })).toBe(false)
    expect(tagsMatch({ env: ['test'] }, undefined)).toBe(false)
  })
})

describe('reaches', () => {
  it('counts the named targets that exist and those the tags match, of the grant\'s kind only', () => {
    expect(reaches(grant({ targets: [{ id: 't1', protocols: ['ssh'] }] }), targets, [])).toBe(1)
    expect(reaches(grant({ targets: [{ id: 'gone', protocols: ['ssh'] }] }), targets, [])).toBe(0)
    // env test matches the host and the database; a host grant counts the host only.
    expect(reaches(grant({ targets: [], tags: { match: { env: ['test'] }, protocols: ['ssh'] } }), targets, [])).toBe(1)
    expect(reaches(grant({ kind: 'database', targets: [], tags: { match: { env: ['test'] }, protocols: ['database'] } }), targets, [])).toBe(1)
  })

  it('an autoscaling grant by tag with no group enrolled opens nothing', () => {
    const g = grant({ kind: 'autoscaling', targets: [], tags: { match: { env: ['test'] }, protocols: ['ssh'] } })
    expect(reaches(g, targets, [])).toBe(0)
    const fleet = { id: 'a1', name: 'fleet', os_family: 'linux', capabilities: ['ssh'], tags: { env: 'test' } } as unknown as AutoscalingGroup
    expect(reaches(g, targets, [fleet])).toBe(1)
  })
})

describe('the policy list', () => {
  it('flags a grant that opens nothing, on the row and in its grants', async () => {
    const p: Policy = {
      id: 'p1', name: 'host-access', description: '', enabled: true, subjects: [{ kind: 'user', id: 'u1' }],
      grants: [
        grant({ id: 'g1', targets: [{ id: 't1', protocols: ['ssh'] }] }),
        grant({ id: 'g2', kind: 'autoscaling', targets: [], tags: { match: { env: ['test'] }, protocols: ['ssh'] } }),
      ],
      created_at: '', updated_at: '',
    }
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      const items = path.startsWith('/access-policies') ? [p] : path.startsWith('/targets') ? targets : path.startsWith('/users') ? [{ id: 'u1', username: 'alice', roles: ['user'] }] : []
      return { items } as never
    })
    render(<MemoryRouter><Policies /></MemoryRouter>)
    expect(await screen.findByText('1 open nothing')).toBeDefined()
    await userEvent.click(screen.getByRole('button', { name: /2 grants/ }))
    const rows = within(screen.getByRole('table', { name: 'Grants of host-access' })).getAllByRole('row')
    expect(within(rows[1]).queryByText('opens nothing')).toBeNull()
    expect(within(rows[2]).getByText('opens nothing')).toBeDefined()
  })

  it('says nothing while the lists are still loading', async () => {
    const p: Policy = {
      id: 'p1', name: 'x', description: '', enabled: true, subjects: [],
      grants: [grant({ id: 'g1', targets: [{ id: 't1', protocols: ['ssh'] }] })], created_at: '', updated_at: '',
    }
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.startsWith('/targets')) return new Promise(() => {}) as never
      return { items: path.startsWith('/access-policies') ? [p] : [] } as never
    })
    render(<MemoryRouter><Policies /></MemoryRouter>)
    expect(await screen.findByText('x')).toBeDefined()
    expect(screen.queryByText(/open(s)? nothing/)).toBeNull()
  })
})
