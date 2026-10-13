// Group mapping as the identity-provider form edits it: one line per mapping,
// "externalGroup=zanskarGroupId". An LDAP group is best written as its full DN
// (cn=ops,ou=groups,dc=corp,dc=example), which holds "=" itself, so each line
// splits at its last "=": a Zanskar group id never contains one.

export function mappingToText(m?: Record<string, string>): string {
  return Object.entries(m ?? {}).map(([k, v]) => `${k}=${v}`).join('\n')
}

export function textToMapping(text: string): { mapping: Record<string, string>; error?: string } {
  const mapping: Record<string, string> = {}
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (!line) continue
    const i = line.lastIndexOf('=')
    if (i <= 0 || i === line.length - 1) return { mapping, error: `line "${line}" must be externalGroup=groupId` }
    mapping[line.slice(0, i).trim()] = line.slice(i + 1).trim()
  }
  return { mapping }
}
