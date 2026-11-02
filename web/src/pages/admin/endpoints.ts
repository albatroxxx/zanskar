import type { AppEndpoint } from '../../api/types'

/** How many origins an application may name beside its upstream (the server's MaxAppEndpoints). */
export const maxAppEndpoints = 31

/**
 * endpointsBody is what the form sends: rows with nothing in them are left
 * out, and sent[i] is the number the person sees on the row the server's
 * app_endpoints[i] came from. A row with a name and no address is an error.
 */
export function endpointsBody(rows: AppEndpoint[]): { body: AppEndpoint[]; sent: number[]; error?: string } {
  const body: AppEndpoint[] = []
  const sent: number[] = []
  for (const [i, r] of rows.entries()) {
    const name = r.name.trim()
    const url = r.url.trim()
    if (!name && !url) continue
    if (!url) return { body, sent, error: `Endpoint ${i + 1} has no address` }
    body.push({ name, url })
    sent.push(i + 1)
  }
  return { body, sent }
}

/** endpointWords says the server's app_endpoints[i] as the row the person filled in, and app_upstream as Upstream. */
export function endpointWords(msg: string, sent: number[]): string {
  return msg
    .replace(/app_endpoints\[(\d+)\]/g, (_, n: string) => `Endpoint ${sent[Number(n)] ?? Number(n) + 1}`)
    .replace(/\bapp_upstream\b/g, 'Upstream')
}
