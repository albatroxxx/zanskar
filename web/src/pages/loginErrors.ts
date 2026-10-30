// What the sign-in page says after a failed single sign-on. The gateway sends
// the reason back as ?error=<code>; anything else in that parameter could be
// a link's own wording, so it is never shown (L6).

const tryAgain = 'Try again, or ask an administrator.'

const reasons: Record<string, string> = {
  provider_unavailable: 'The identity provider could not be reached. Try again in a moment.',
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
  email_unverified: 'Your identity provider has not verified your email address, so it cannot be used to sign in here.',
  not_provisioned: 'There is no account for you here yet. Ask an administrator to add you.',
  account_conflict: 'An account with your name already exists here and belongs to another sign-in method. Ask an administrator to link them.',
  provisioning_failed: `Your account could not be set up. ${tryAgain}`,
  reauth_not_done: 'The identity provider signed you in on an earlier session instead of asking for your password again, so the sign-in was refused. Sign out of the identity provider, then sign in again.',
  auth_time_missing: 'The identity provider did not say when you signed in, which this sign-in needs. Ask an administrator to have it send the auth_time claim.',
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
