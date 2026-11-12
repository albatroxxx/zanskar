import { describe, expect, it } from 'vitest'
import { creationOptions, credentialJSON, fromB64url, keyError, requestOptions, toB64url } from './webauthn'

const bytes = (b: ArrayBuffer) => Array.from(new Uint8Array(b))

// The gateway sends binary fields as base64url and reads them back the same
// way (ADR 0028); these are the only conversions between it and the browser.
describe('security keys, the browser side', () => {
  it('round-trips base64url, padding and the URL alphabet included', () => {
    const raw = new Uint8Array([0xfb, 0xff, 0x00, 0x3e, 0x3f, 0x01, 0x02])
    const s = toB64url(raw)
    expect(s).toBe('-_8APj8BAg')
    expect(bytes(fromB64url(s))).toEqual(Array.from(raw))
    expect(bytes(fromB64url('AQ'))).toEqual([1])
  })

  it('decodes the challenge, the user id and the keys to leave out', () => {
    const o = creationOptions({
      challenge: 'AQID', rp: { id: 'gw.example.test', name: 'Zanskar' }, user: { id: 'dXNlcg', name: 'kim', displayName: 'Kim' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }], excludeCredentials: [{ type: 'public-key', id: 'BAU' }],
    })
    expect(bytes(o.challenge as ArrayBuffer)).toEqual([1, 2, 3])
    expect(new TextDecoder().decode(o.user.id as ArrayBuffer)).toBe('user')
    expect(bytes(o.excludeCredentials![0].id as ArrayBuffer)).toEqual([4, 5])
    expect(o.rp.id).toBe('gw.example.test')
    const r = requestOptions({ challenge: 'Bwg', rpId: 'gw.example.test', allowCredentials: [{ type: 'public-key', id: 'CQ' }] })
    expect(bytes(r.challenge as ArrayBuffer)).toEqual([7, 8])
    expect(bytes(r.allowCredentials![0].id as ArrayBuffer)).toEqual([9])
  })

  it("writes the browser's answer as the gateway reads it", () => {
    const buf = (...b: number[]) => new Uint8Array(b).buffer
    const cred = {
      id: 'AQI', rawId: buf(1, 2), type: 'public-key', authenticatorAttachment: 'cross-platform',
      getClientExtensionResults: () => ({}),
      response: { clientDataJSON: buf(3), authenticatorData: buf(4), signature: buf(5), userHandle: null },
    } as unknown as PublicKeyCredential
    expect(credentialJSON(cred)).toEqual({
      id: 'AQI', rawId: 'AQI', type: 'public-key', authenticatorAttachment: 'cross-platform', clientExtensionResults: {},
      response: { clientDataJSON: 'Aw', authenticatorData: 'BA', signature: 'BQ' },
    })
  })

  it('says what a cancelled or refused ceremony means', () => {
    expect(keyError(new DOMException('x', 'NotAllowedError'))).toBe('Cancelled or timed out.')
    expect(keyError(new DOMException('x', 'InvalidStateError'))).toBe('This key is registered already.')
    expect(keyError(new DOMException('x', 'SecurityError'))).toBe('Keys do not work at this address.')
    expect(keyError(new Error('other'))).toBeNull()
  })
})
