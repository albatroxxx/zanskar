/** One tag as edited: a key box and a value box. */
export interface TagRow { key: string; value: string }

// The server's limits (internal/target/target.go, internal/policy/policy.go).
export const maxTags = 32
export const maxTagLen = 64

/** tagRows lays a tag map out as rows, one per tag. */
export function tagRows(tags?: Record<string, string>): TagRow[] {
  return Object.entries(tags ?? {}).map(([key, value]) => ({ key, value }))
}

/**
 * rowsToTags reads the rows back into the map the API takes. Blank rows are
 * dropped; a value without a key, a key given twice or an over-long box is an
 * error naming the row. A policy matches on values, so it asks for one.
 */
export function rowsToTags(rows: TagRow[], opts: { valueRequired?: boolean } = {}): { tags: Record<string, string>; error?: string } {
  // A Map, then fromEntries: assigning into an object literal would turn a
  // key such as "__proto__" into a prototype and lose it.
  const seen = new Map<string, string>()
  for (const [i, r] of rows.entries()) {
    const key = r.key.trim()
    const value = r.value.trim()
    if (!key && !value) continue
    if (!key) return { tags: {}, error: `tag ${i + 1}: key is empty` }
    if (opts.valueRequired && !value) return { tags: {}, error: `tag ${key}: value is empty` }
    if (key.length > maxTagLen || value.length > maxTagLen) return { tags: {}, error: `tag ${key}: at most ${maxTagLen} characters` }
    if (seen.has(key)) return { tags: {}, error: `tag ${key} is given twice` }
    seen.set(key, value)
  }
  if (seen.size > maxTags) return { tags: {}, error: `at most ${maxTags} tags` }
  return { tags: Object.fromEntries(seen) }
}

/** tagSuggestions gathers the keys in use and the values seen under each. */
export function tagSuggestions(tagged: { tags?: Record<string, string> }[]): Record<string, string[]> {
  const out = new Map<string, Set<string>>()
  for (const t of tagged) {
    for (const [k, v] of Object.entries(t.tags ?? {})) {
      if (!out.has(k)) out.set(k, new Set())
      if (v) out.get(k)!.add(v)
    }
  }
  return Object.fromEntries([...out].map(([k, vs]) => [k, [...vs].sort((a, b) => a.localeCompare(b))]))
}
