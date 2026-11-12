import { api } from './client'

/**
 * The browser's side of security keys and passkeys (ADR 0028). The gateway
 * sends the options navigator.credentials takes, with every binary field as
 * base64url; these turn them into ArrayBuffers and the browser's answer back
 * into JSON, which the gateway verifies. Nothing here decides anything.
 */

export type KeyPurpose = 'register' | 'sign_in' | 'step_up' | 'cli'

type Json = Record<string, unknown>

/** keysInBrowser reports whether this browser can use a security key. */
export function keysInBrowser(): boolean {
  return typeof window !== 'undefined' && typeof window.PublicKeyCredential === 'function' && !!navigator.credentials
}

export function fromB64url(s: string): ArrayBuffer {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out.buffer
}

export function toB64url(buf: ArrayBuffer | ArrayBufferView): string {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const withIDs = (list: unknown) => (Array.isArray(list) ? list.map((c: Json) => ({ ...c, id: fromB64url(String(c.id)) })) : undefined)

/** creationOptions decodes registration options from the gateway. */
export function creationOptions(publicKey: Json): PublicKeyCredentialCreationOptions {
  const user = publicKey.user as Json
  return {
    ...(publicKey as unknown as PublicKeyCredentialCreationOptions),
    challenge: fromB64url(String(publicKey.challenge)),
    user: { ...(user as unknown as PublicKeyCredentialUserEntity), id: fromB64url(String(user.id)) },
    excludeCredentials: withIDs(publicKey.excludeCredentials) as PublicKeyCredentialDescriptor[] | undefined,
  }
}

/** requestOptions decodes assertion options from the gateway. */
export function requestOptions(publicKey: Json): PublicKeyCredentialRequestOptions {
  return {
    ...(publicKey as unknown as PublicKeyCredentialRequestOptions),
    challenge: fromB64url(String(publicKey.challenge)),
    allowCredentials: withIDs(publicKey.allowCredentials) as PublicKeyCredentialDescriptor[] | undefined,
  }
}

/** credentialJSON is the browser's answer as the gateway reads it. */
export function credentialJSON(c: PublicKeyCredential): Json {
  const r = c.response as AuthenticatorResponse & Partial<AuthenticatorAttestationResponse & AuthenticatorAssertionResponse>
  const response: Json = { clientDataJSON: toB64url(r.clientDataJSON) }
  if (r.attestationObject) response.attestationObject = toB64url(r.attestationObject)
  if (r.authenticatorData) response.authenticatorData = toB64url(r.authenticatorData)
  if (r.signature) response.signature = toB64url(r.signature)
  if (r.userHandle) response.userHandle = toB64url(r.userHandle)
  if (typeof r.getTransports === 'function') response.transports = r.getTransports()
  return {
    id: c.id,
    rawId: toB64url(c.rawId),
    type: c.type,
    authenticatorAttachment: c.authenticatorAttachment ?? undefined,
    clientExtensionResults: c.getClientExtensionResults?.() ?? {},
    response,
  }
}

/** askKey asks the account's keys for purpose and returns the answer to send on. */
export async function askKey(purpose: Exclude<KeyPurpose, 'register'>): Promise<Json> {
  const options = await api.post<{ publicKey: Json }>('/auth/mfa/webauthn/begin', { purpose })
  const cred = (await navigator.credentials.get({ publicKey: requestOptions(options.publicKey) })) as PublicKeyCredential | null
  if (!cred) throw new DOMException('No key answered.', 'NotAllowedError')
  return credentialJSON(cred)
}

/** createKey has the browser make a new key for this account. */
export async function createKey(currentPassword?: string): Promise<Json> {
  const options = await api.post<{ publicKey: Json }>('/auth/mfa/webauthn/begin', currentPassword ? { purpose: 'register', current_password: currentPassword } : { purpose: 'register' })
  const cred = (await navigator.credentials.create({ publicKey: creationOptions(options.publicKey) })) as PublicKeyCredential | null
  if (!cred) throw new DOMException('No key was made.', 'NotAllowedError')
  return credentialJSON(cred)
}

/** keyError is what to say when the browser's side of a ceremony failed. */
export function keyError(e: unknown): string | null {
  if (!(e instanceof DOMException)) return null
  switch (e.name) {
    case 'NotAllowedError':
    case 'AbortError':
      return 'Cancelled or timed out.'
    case 'InvalidStateError':
      return 'This key is registered already.'
    case 'SecurityError':
      return 'Keys do not work at this address.'
    default:
      return e.message || 'The key did not answer.'
  }
}
