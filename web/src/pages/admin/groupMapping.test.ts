import { describe, expect, it } from 'vitest'
import { mappingToText, textToMapping } from './groupMapping'

describe('group mapping text', () => {
  it('keeps an LDAP DN whole: it splits at the last "="', () => {
    const { mapping, error } = textToMapping('cn=zanskar-admins,ou=groups,dc=corp,dc=example=g-admins\nops-team = g-ops')
    expect(error).toBeUndefined()
    expect(mapping).toEqual({ 'cn=zanskar-admins,ou=groups,dc=corp,dc=example': 'g-admins', 'ops-team': 'g-ops' })
  })

  it('round-trips through the text form', () => {
    const m = { 'cn=ops,ou=groups,dc=corp,dc=example': 'g-ops', admins: 'g-admins' }
    expect(textToMapping(mappingToText(m)).mapping).toEqual(m)
  })

  it('refuses a line without a group id', () => {
    expect(textToMapping('ops-team').error).toMatch(/externalGroup=groupId/)
    expect(textToMapping('ops-team=').error).toMatch(/externalGroup=groupId/)
  })
})
