// What the sign-in page says after a failed single sign-on. The gateway sends
// the reason back as ?error=<code>; anything else in that parameter could be
// a link's own wording, so it is never shown (L6).

const tryAgain = 'Try again.'

const reasons: Record<string, string> = {
  // Said only after a sign-in through the provider failed, never to a page
  // that merely loads: an unsigned visitor learns nothing about the
  // provider's health they did not just find out (2026-11-03, idea 1).
  provider_unavailable: 'Single sign-on is not answering.',
  provider_denied: 'The identity provider did not sign you in.',
  state_missing: 'The sign-in took too long, or began in another tab. Start it again.',
  state_invalid: 'The sign-in took too long, or began in another tab. Start it again.',
  code_missing: `The identity provider's answer could not be used. ${tryAgain}`,
  exchange_failed: `The identity provider's answer could not be used. ${tryAgain}`,
  no_id_token: `The identity provider's answer could not be used. ${tryAgain}`,
  id_token_invalid: `The identity provider's answer could not be used. ${tryAgain}`,
  nonce_mismatch: `The identity provider's answer could not be used. ${tryAgain}`,
  claims_invalid: `The identity provider's answer could not be used. ${tryAgain}`,
  domain_not_allowed: 'Your email domain is not allowed to sign in here.',
  email_unverified: 'Your identity provider has not verified your email address.',
  not_provisioned: 'There is no account for you here.',
  account_conflict: 'This username belongs to another sign-in method.',
  provisioning_failed: `Your account could not be set up. ${tryAgain}`,
  reauth_not_done: 'The identity provider did not ask for your password again; sign out there, then sign in.',
  auth_time_missing: 'The identity provider sent no auth_time claim.',
  internal: `Something went wrong on the gateway. ${tryAgain}`,
}

/** signInError is the sentence for a ?error= value: its own for a reason the
 *  gateway sends, a general one for anything else, nothing for no value. */
export function signInError(code: string | null): string {
  if (!code) return ''
  return Object.hasOwn(reasons, code) ? reasons[code] : `Single sign-on did not complete. ${tryAgain}`
}

/** safeReturnPath is where to go after signing in: the path the user came
 *  from when it is a path on this site, otherwise the home page (L7). */
export function safeReturnPath(from: unknown): string {
  // One leading slash, not followed by another or a backslash (either makes
  // a browser read the rest as another host), and no control characters,
  // which browsers strip before parsing.
  if (typeof from === 'string' && /^\/(?![/\\])/.test(from) && !hasControl(from)) return from
  return '/'
}

const hasControl = (s: string) => [...s].some((c) => c.charCodeAt(0) < 0x20 || c.charCodeAt(0) === 0x7f)
