import { describe, expect, it } from 'vitest'
import { mappingRows, rowsToMapping } from './groupMapping'

describe('group mapping rows', () => {
  it('keeps an LDAP DN whole, "=" and all', () => {
    const { mapping, error } = rowsToMapping([
      { external: 'cn=zanskar-admins,ou=groups,dc=corp,dc=example', group: 'g-admins' },
      { external: ' ops-team ', group: 'g-ops' },
    ])
    expect(error).toBeUndefined()
    expect(mapping).toEqual({ 'cn=zanskar-admins,ou=groups,dc=corp,dc=example': 'g-admins', 'ops-team': 'g-ops' })
  })

  it('round-trips through the rows', () => {
    const m = { 'cn=ops,ou=groups,dc=corp,dc=example': 'g-ops', admins: 'g-admins' }
    expect(rowsToMapping(mappingRows(m)).mapping).toEqual(m)
  })

  it('drops blank rows and refuses half-filled or repeated ones', () => {
    expect(rowsToMapping([{ external: ' ', group: '' }])).toEqual({ mapping: {} })
    expect(rowsToMapping([{ external: 'ops-team', group: '' }]).error).toBe('mapping ops-team: choose a Zanskar group')
    expect(rowsToMapping([{ external: '', group: 'g1' }]).error).toBe('mapping 1: provider group is empty')
    expect(rowsToMapping([{ external: 'ops', group: 'g1' }, { external: 'ops ', group: 'g2' }]).error).toBe('mapping ops is given twice')
  })

  it('keeps a provider group whose name is an object property', () => {
    const { mapping } = rowsToMapping([{ external: '__proto__', group: 'g1' }, { external: 'constructor', group: 'g2' }])
    expect(Object.keys(mapping)).toEqual(['__proto__', 'constructor'])
    expect(JSON.parse(JSON.stringify(mapping))).toEqual(JSON.parse('{"__proto__":"g1","constructor":"g2"}'))
  })
})
