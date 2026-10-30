// Group mapping as the identity-provider form edits it: rows of a provider
// group (an OIDC groups-claim value, or an LDAP group, best written as its
// full DN) and the Zanskar group it lands in, chosen by name, never typed as
// an id.

export interface MappingRow { external: string; group: string }

export function mappingRows(m?: Record<string, string>): MappingRow[] {
  return Object.entries(m ?? {}).map(([external, group]) => ({ external, group }))
}

/** rowsToMapping reads the rows back into the map the API takes; blank rows are dropped. */
export function rowsToMapping(rows: MappingRow[]): { mapping: Record<string, string>; error?: string } {
  // A Map, then fromEntries, so a provider group named "__proto__" stays a key.
  const seen = new Map<string, string>()
  for (const [i, r] of rows.entries()) {
    const external = r.external.trim()
    if (!external && !r.group) continue
    if (!external) return { mapping: {}, error: `mapping ${i + 1}: provider group is empty` }
    if (!r.group) return { mapping: {}, error: `mapping ${external}: choose a Zanskar group` }
    if (seen.has(external)) return { mapping: {}, error: `mapping ${external} is given twice` }
    seen.set(external, r.group)
  }
  return { mapping: Object.fromEntries(seen) }
}
