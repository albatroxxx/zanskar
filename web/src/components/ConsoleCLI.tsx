import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError, api, errorMessage } from '../api/client'

/**
 * The console's command line (ADR 0027): an icon at the top right of every
 * administrator page, and a panel that slides up from the bottom. It sends
 * each line to the gateway, which runs it through the same routes and checks
 * as the console. Nothing is interpreted here except clear and history.
 */

interface CLIState {
  enabled: boolean
  unlocked: boolean
  mfa_enrolled: boolean
  idle_minutes: number
}

interface Line {
  text: string
  style?: 'head' | 'ok' | 'warn' | 'error' | 'muted' | 'prompt'
}

interface Reply {
  status: 'ok' | 'error' | 'confirm' | 'cancelled'
  lines: Line[]
  expect?: string
}

const HISTORY_KEY = 'zanskar.cli.history'
const HEIGHT_KEY = 'zanskar.cli.height'
const MAX_HISTORY = 100
const MAX_TRANSCRIPT = 2000

// Storage can be unavailable (private windows, blocked site data); the
// command line works without it.
function load<T>(store: () => Storage, key: string, fallback: T): T {
  try {
    const v = store().getItem(key)
    return v ? (JSON.parse(v) as T) : fallback
  } catch {
    return fallback
  }
}
function save(store: () => Storage, key: string, v: unknown) {
  try {
    store().setItem(key, JSON.stringify(v))
  } catch {
    /* not kept; fine */
  }
}

/** TerminalIcon is a small window with a prompt in it. */
export function TerminalIcon({ size = 24 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="1.8" y="2.8" width="16.4" height="14.4" rx="2.6" />
      <path d="M1.8 6.6 H18.2" />
      <circle cx="4.4" cy="4.7" r=".55" fill="currentColor" stroke="none" />
      <circle cx="6.3" cy="4.7" r=".55" fill="currentColor" stroke="none" />
      <circle cx="8.2" cy="4.7" r=".55" fill="currentColor" stroke="none" />
      <path d="M5.2 9.2 L8.2 11.6 L5.2 14" strokeWidth="1.8" />
      <path d="M9.8 14 H14.6" strokeWidth="1.8" />
    </svg>
  )
}

// fetchState asks whether the command line is open for this sign-in. A 404
// means it is switched off (ZANSKAR_CONSOLE_CLI=off), and the icon hides.
async function fetchState(): Promise<CLIState | null> {
  try {
    return await api.get<CLIState>('/admin/cli')
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return { enabled: false, unlocked: false, mfa_enrolled: false, idle_minutes: 15 }
    return null
  }
}

export function ConsoleCLI() {
  const [state, setState] = useState<CLIState | null>(null)
  const [open, setOpen] = useState(false)
  const [transcript, setTranscript] = useState<Line[]>([])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  // A destructive command waiting for its word: the line and the word.
  const [confirm, setConfirm] = useState<{ line: string; expect: string } | null>(null)
  // A line refused because the command line had closed, run again on unlock.
  const [afterUnlock, setAfterUnlock] = useState<string | null>(null)
  const [code, setCode] = useState('')
  const [codeError, setCodeError] = useState('')
  const [height, setHeight] = useState(() => load(() => localStorage, HEIGHT_KEY, 420))
  const history = useRef<string[]>(load(() => sessionStorage, HISTORY_KEY, []))
  const cursor = useRef(-1)
  const inputRef = useRef<HTMLInputElement>(null)
  const codeRef = useRef<HTMLInputElement>(null)
  const iconRef = useRef<HTMLButtonElement>(null)
  const bodyRef = useRef<HTMLDivElement>(null)

  const refresh = useCallback(() => fetchState().then(setState), [])
  useEffect(() => {
    // fetchState never rejects: a failure resolves to null.
    void fetchState().then(setState)
  }, [])

  const toggle = useCallback(() => {
    setOpen((o) => {
      if (!o) void refresh()
      return !o
    })
  }, [refresh])

  // Ctrl+` opens and closes it from anywhere in the console.
  useEffect(() => {
    if (!state?.enabled) return
    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey && !e.metaKey && !e.altKey && e.key === '`') {
        e.preventDefault()
        toggle()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [state?.enabled, toggle])

  // Focus follows the panel: the prompt (or the code) when it opens, the
  // icon again when it closes.
  useEffect(() => {
    if (!open) return
    const el = state?.unlocked ? inputRef.current : codeRef.current
    el?.focus()
  }, [open, state?.unlocked, busy])

  useEffect(() => {
    const el = bodyRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [transcript])

  const append = (lines: Line[]) => setTranscript((t) => [...t, ...lines].slice(-MAX_TRANSCRIPT))

  const send = async (line: string, confirmWord?: string) => {
    setBusy(true)
    try {
      const reply = await api.post<Reply>('/admin/cli', { line, confirm: confirmWord ?? '' })
      append(reply.lines)
      setConfirm(reply.status === 'confirm' && reply.expect ? { line, expect: reply.expect } : null)
    } catch (err) {
      if (err instanceof ApiError && err.code === 'cli_locked') {
        setAfterUnlock(confirmWord === undefined ? line : null)
        setState((s) => (s ? { ...s, unlocked: false } : s))
        append([{ text: 'The command line closed after a while without use. Enter a fresh code to go on.', style: 'muted' }])
      } else if (!(err instanceof ApiError && err.sessionEnded)) {
        append([{ text: errorMessage(err), style: 'error' }])
      }
      setConfirm(null)
    } finally {
      setBusy(false)
    }
  }

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const line = input.trim()
    setInput('')
    cursor.current = -1
    if (confirm) {
      append([{ text: `Type ${confirm.expect} to confirm: ${line}`, style: 'prompt' }])
      void send(confirm.line, line)
      return
    }
    if (!line) return
    append([{ text: `zanskar> ${line}`, style: 'prompt' }])
    history.current = [...history.current.filter((h) => h !== line), line].slice(-MAX_HISTORY)
    save(() => sessionStorage, HISTORY_KEY, history.current)
    if (line === 'clear') {
      setTranscript([])
      return
    }
    if (line === 'history') {
      append(history.current.map((h, i) => ({ text: `${String(i + 1).padStart(4)}  ${h}` })))
      return
    }
    void send(line)
  }

  const onPromptKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Escape' && confirm) {
      e.preventDefault()
      append([{ text: 'Cancelled.', style: 'muted' }])
      setConfirm(null)
      return
    }
    if (confirm || (e.key !== 'ArrowUp' && e.key !== 'ArrowDown')) return
    const h = history.current
    if (h.length === 0) return
    e.preventDefault()
    let i = cursor.current === -1 ? h.length : cursor.current
    i = e.key === 'ArrowUp' ? Math.max(0, i - 1) : i + 1
    if (i >= h.length) {
      cursor.current = -1
      setInput('')
    } else {
      cursor.current = i
      setInput(h[i])
    }
  }

  const unlock = async (e: React.FormEvent) => {
    e.preventDefault()
    setCodeError('')
    setBusy(true)
    try {
      await api.post('/admin/cli/unlock', { code: code.trim() })
      setCode('')
      setState((s) => (s ? { ...s, unlocked: true } : s))
      const again = afterUnlock
      setAfterUnlock(null)
      if (again) {
        append([{ text: `zanskar> ${again}`, style: 'prompt' }])
        await send(again)
      }
    } catch (err) {
      setCodeError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const close = () => {
    setOpen(false)
    setTranscript([])
    setConfirm(null)
    iconRef.current?.focus()
  }

  const minimise = () => {
    setOpen(false)
    iconRef.current?.focus()
  }

  // Drag the grip to resize; the height is remembered on this browser.
  const startResize = (e: React.PointerEvent) => {
    e.preventDefault()
    const startY = e.clientY
    const startH = height
    let h = startH
    const move = (ev: PointerEvent) => {
      h = Math.min(Math.max(startH + (startY - ev.clientY), 180), window.innerHeight - 80)
      setHeight(h)
    }
    const up = () => {
      window.removeEventListener('pointermove', move)
      window.removeEventListener('pointerup', up)
      save(() => localStorage, HEIGHT_KEY, h)
    }
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
  }

  if (!state?.enabled) return null

  return (
    <>
      <button
        ref={iconRef}
        type="button"
        className={'cli-icon' + (open ? ' on' : '')}
        aria-label="Command line"
        aria-expanded={open}
        aria-controls="console-cli"
        title="Command line (Ctrl `)"
        onClick={toggle}
      >
        <TerminalIcon />
      </button>
      {open && (
        <section id="console-cli" className="cli-panel" style={{ height }} role="region" aria-label="Command line">
          <div className="cli-grip" onPointerDown={startResize} role="separator" aria-orientation="horizontal" aria-label="Resize the command line" />
          <div className="cli-bar">
            <b>
              <span className="cli-bar-icon">
                <TerminalIcon size={17} />
              </span>
              Command line
            </b>
            <span className="cli-sub">Zanskar commands only · every line is audited</span>
            <span className="cli-spacer" />
            <span className={'cli-pill' + (state.unlocked ? ' ok' : '')}>{state.unlocked ? 'Code verified' : 'Code needed'}</span>
            <button type="button" disabled={!state.unlocked || busy} onClick={() => {
              append([{ text: 'zanskar> help', style: 'prompt' }])
              void send('help')
            }}>
              Commands
            </button>
            <button type="button" onClick={minimise}>Minimise</button>
            <button type="button" onClick={close}>Close</button>
          </div>
          {!state.unlocked ? (
            <div className="cli-mfa">
              {state.mfa_enrolled ? (
                <form className="cli-card" onSubmit={(e) => void unlock(e)}>
                  <h3>Confirm it's you</h3>
                  <p>
                    The command line needs a fresh code from your authenticator app. It stays open while you use it, and asks again after {state.idle_minutes} minutes without a
                    command.
                  </p>
                  <label htmlFor="cli-code">Authenticator code</label>
                  <input
                    id="cli-code"
                    ref={codeRef}
                    className="cli-code"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    required
                  />
                  {codeError && (
                    <p className="cli-error" role="alert">
                      {codeError}
                    </p>
                  )}
                  <div className="cli-row">
                    <button className="btn primary" type="submit" disabled={busy}>
                      Open command line
                    </button>
                    <button className="cli-link" type="button" onClick={minimise}>
                      Cancel
                    </button>
                  </div>
                </form>
              ) : (
                <div className="cli-card">
                  <h3>An authenticator is needed</h3>
                  <p>
                    The command line opens only with a code from an authenticator app, and this account has none. Enrol one at your next sign-in, or ask another administrator to require
                    one for you.
                  </p>
                </div>
              )}
            </div>
          ) : (
            <div className="cli-body" ref={bodyRef} role="presentation" onClick={() => window.getSelection()?.toString() || inputRef.current?.focus()}>
              <div aria-live="polite">
                {transcript.map((l, i) => (
                  <div key={i} className={'cli-line' + (l.style ? ' ' + l.style : '')}>
                    {l.style === 'prompt' && l.text.startsWith('zanskar> ') ? (
                      <>
                        <span className="cli-ps">zanskar&gt;</span>
                        {l.text.slice(8)}
                      </>
                    ) : (
                      l.text || ' '
                    )}
                  </div>
                ))}
              </div>
              <form className="cli-prompt" onSubmit={submit}>
                <label htmlFor="cli-input" className={confirm ? 'cli-confirm' : ''}>
                  {confirm ? `Type ${confirm.expect} to confirm:` : 'zanskar>'}
                </label>
                <input
                  id="cli-input"
                  ref={inputRef}
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={onPromptKey}
                  disabled={busy}
                  autoComplete="off"
                  autoCapitalize="off"
                  spellCheck={false}
                  maxLength={1024}
                />
              </form>
            </div>
          )}
        </section>
      )}
    </>
  )
}
