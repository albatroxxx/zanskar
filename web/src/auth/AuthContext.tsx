import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { ApiError, api, setCsrf, signInEnded } from '../api/client'
import type { LoginResponse, Me, Role, User } from '../api/types'
import { browser, providerSignOut } from './signOut'

/**
 * Auth state machine:
 *   loading  -> anonymous | partial | full, or unreachable until the gateway
 *              answers
 *   partial  = password accepted; a password change (an administrator chose
 *              the current one), then the second factor (verify or enroll),
 *              still owed
 */
/** unreachable: the gateway did not answer the session check (restarting,
 *  or the network); the console asks again rather than signing out. */
type AuthStatus = 'loading' | 'unreachable' | 'anonymous' | 'partial' | 'full'

interface AuthState {
  status: AuthStatus
  user: User | null
  mfaEnrolled: boolean
  /** which partial step is owed after password login */
  pending: 'verify' | 'enroll' | 'password' | null
}

interface AuthContextValue extends AuthState {
  login: (username: string, password: string) => Promise<LoginResponse>
  changePassword: (current: string, next: string) => Promise<LoginResponse>
  verifyTotp: (code: string) => Promise<void>
  enrollTotp: () => Promise<{ secret: string; otpauth_url: string }>
  confirmTotp: (code: string) => Promise<string[]>
  logout: () => Promise<void>
  refresh: () => Promise<void>
  hasRole: (...roles: Role[]) => boolean
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ status: 'loading', user: null, mfaEnrolled: false, pending: null })
  const retry = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const again = useRef<() => Promise<void>>(async () => {})

  const refresh = useCallback(async () => {
    clearTimeout(retry.current)
    try {
      const me = await api.get<Me>('/auth/me')
      setCsrf(me.csrf_token)
      if (me.pending) {
        // A partial session (second factor still owed) survived a reload: resume
        // the correct step — enroll or verify — with its CSRF token restored,
        // rather than bouncing to a login the stale session would reject.
        setState({ status: 'partial', user: null, mfaEnrolled: me.mfa_enrolled, pending: me.pending })
      } else {
        setState({ status: 'full', user: me.user ?? null, mfaEnrolled: me.mfa_enrolled, pending: null })
      }
    } catch (e) {
      // Only a 401 means signed out. Anything else (the restart the
      // console itself offers, a proxy between deploys, the network) says
      // nothing about the cookie: keep what is known, say the gateway is
      // not answering if nothing is known yet, and ask again (B22).
      if (e instanceof ApiError && e.status === 401) {
        setCsrf('')
        setState({ status: 'anonymous', user: null, mfaEnrolled: false, pending: null })
        return
      }
      setState((s) => (s.status === 'loading' ? { ...s, status: 'unreachable' } : s))
      retry.current = setTimeout(() => void again.current(), 3000)
    }
  }, [])
  useEffect(() => {
    again.current = refresh
    return () => clearTimeout(retry.current)
  }, [refresh])

  useEffect(() => {
    const t = setTimeout(() => void refresh(), 0)
    return () => clearTimeout(t)
  }, [refresh])

  const login = useCallback(async (username: string, password: string) => {
    const res = await api.post<LoginResponse>('/auth/login', { username, password })
    if (res.csrf_token) setCsrf(res.csrf_token)
    if (res.status === 'ok') {
      setState({ status: 'full', user: res.user ?? null, mfaEnrolled: false, pending: null })
      await refresh()
    } else {
      setState({ status: 'partial', user: null, mfaEnrolled: res.status === 'mfa_required', pending: res.status === 'mfa_required' ? 'verify' : res.status === 'password_change_required' ? 'password' : 'enroll' })
    }
    return res
  }, [refresh])

  // The step after the change is whatever sign-in would have owed next.
  const changePassword = useCallback(async (current: string, next: string) => {
    const res = await api.post<LoginResponse>('/auth/password', { current_password: current, new_password: next })
    if (res.csrf_token) setCsrf(res.csrf_token)
    if (res.status === 'ok') {
      await refresh()
    } else {
      setState({ status: 'partial', user: null, mfaEnrolled: res.status === 'mfa_required', pending: res.status === 'mfa_required' ? 'verify' : 'enroll' })
    }
    return res
  }, [refresh])

  // A 401 other than a wrong code means the half-finished sign-in is gone
  // (too many wrong codes, or it expired): drop back to the password step
  // rather than keep offering a code box that can no longer work.
  const dropIfEnded = useCallback((e: unknown) => {
    if (signInEnded(e)) {
      setCsrf('')
      setState({ status: 'anonymous', user: null, mfaEnrolled: false, pending: null })
    }
  }, [])

  const verifyTotp = useCallback(async (code: string) => {
    try {
      const res = await api.post<LoginResponse>('/auth/mfa/totp/verify', { code })
      if (res.csrf_token) setCsrf(res.csrf_token)
    } catch (e) {
      dropIfEnded(e)
      throw e
    }
    await refresh()
  }, [refresh, dropIfEnded])

  const enrollTotp = useCallback(async () => {
    return api.post<{ secret: string; otpauth_url: string }>('/auth/mfa/totp/enroll')
  }, [])

  const confirmTotp = useCallback(async (code: string) => {
    let res: { recovery_codes: string[]; csrf_token?: string }
    try {
      res = await api.post<{ recovery_codes: string[]; csrf_token?: string }>('/auth/mfa/totp/confirm', { code })
    } catch (e) {
      dropIfEnded(e)
      throw e
    }
    if (res.csrf_token) setCsrf(res.csrf_token)
    await refresh()
    return res.recovery_codes
  }, [refresh, dropIfEnded])

  const logout = useCallback(async () => {
    let redirect: unknown
    try {
      redirect = (await api.post<{ redirect?: string }>('/auth/logout'))?.redirect
    } finally {
      setCsrf('')
      setState({ status: 'anonymous', user: null, mfaEnrolled: false, pending: null })
    }
    // A session from a single sign-on provider ends there too (ADR 0035):
    // the provider signs the person out and sends them back to /login.
    const to = providerSignOut(redirect)
    if (to) browser.assign(to)
  }, [])

  const hasRole = useCallback((...roles: Role[]) => !!state.user && roles.some((r) => state.user!.roles.includes(r)), [state.user])

  const value = useMemo<AuthContextValue>(
    () => ({ ...state, login, changePassword, verifyTotp, enrollTotp, confirmTotp, logout, refresh, hasRole }),
    [state, login, changePassword, verifyTotp, enrollTotp, confirmTotp, logout, refresh, hasRole],
  )
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth outside AuthProvider')
  return ctx
}
