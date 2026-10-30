/** The provider's sign-out page the gateway named (ADR 0035), when it is an
 *  https URL; anything else is ignored and the sign-out stays local. */
export function providerSignOut(v: unknown): string | null {
  if (typeof v !== 'string') return null
  try {
    return new URL(v).protocol === 'https:' ? v : null
  } catch {
    return null
  }
}

/** Leaving the console for another site; a seam for tests. */
export const browser = { assign: (url: string) => window.location.assign(url) }
