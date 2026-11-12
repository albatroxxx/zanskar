import { useState } from 'react'
import { api, errorMessage } from '../api/client'
import { askKey, keyError, keysInBrowser } from '../api/webauthn'
import { useOptionalAuth } from '../auth/AuthContext'
import { KeyIcon } from './icons'

/**
 * KeyButton offers the account's security key beside a code field (ADR 0028):
 * the sign-in's second step, a step-up, the command line. It shows only for
 * an account that has a key; where keys cannot work here it is disabled, the
 * reason on hover. finish sends the key's answer on (a step-up by default),
 * and onDone runs once it was accepted.
 */
export function KeyButton({ purpose = 'step_up', finish, onDone, onError, className = 'btn' }: {
  purpose?: 'sign_in' | 'step_up' | 'cli'
  finish?: (credential: Record<string, unknown>) => Promise<unknown>
  onDone: () => void | Promise<void>
  onError: (message: string) => void
  className?: string
}) {
  const secondFactor = useOptionalAuth()?.secondFactor
  const [busy, setBusy] = useState(false)
  if (!secondFactor || secondFactor.keys === 0) return null
  const off = secondFactor.keys_off || (keysInBrowser() ? '' : 'This browser cannot use security keys.')
  const send = finish ?? ((credential: Record<string, unknown>) => api.post('/auth/mfa/step-up', { credential }))
  const use = async () => {
    setBusy(true)
    try {
      await send(await askKey(purpose))
      await onDone()
    } catch (e) {
      onError(keyError(e) ?? errorMessage(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <button type="button" className={className + ' key-btn'} disabled={!!off || busy} title={off || undefined} onClick={() => void use()}>
      <KeyIcon />
      <span>{busy ? 'Touch your key…' : 'Use your key'}</span>
    </button>
  )
}
