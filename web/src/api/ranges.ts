/** The time ranges the lists offer, so a reader picks one instead of typing
 *  two timestamps, and the dashboards' "(24h)" tiles open the same "24h".
 *  "Any time" is the default; "custom" is the audit log's own. */
export const ranges: { key: string; label: string; hours?: number }[] = [
  { key: '', label: 'Any time' },
  { key: '1h', label: 'Last hour', hours: 1 },
  { key: '24h', label: 'Last 24 hours', hours: 24 },
  { key: '7d', label: 'Last 7 days', hours: 24 * 7 },
  { key: '30d', label: 'Last 30 days', hours: 24 * 30 },
]

/** sinceFor is the RFC 3339 start of a range, '' for any time or an unknown key. */
export function sinceFor(key: string, now = Date.now()): string {
  const hours = ranges.find((r) => r.key === key)?.hours
  return hours ? new Date(now - hours * 3600_000).toISOString() : ''
}
