import { useEffect, useRef, useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { Terminal as XTerm } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { WebLinksAddon } from '@xterm/addon-web-links'
import '@xterm/xterm/css/xterm.css'
import { fmtSeconds, protocolName } from '../../api/format'
import { FailoverDialog } from './Failover'
import { SessionEndedDialog } from './SessionEnded'
import { SESSION_ID, useSwitched, type SessionEnd, type SessionState } from './session'
import { TerminalFiles } from './TerminalFiles'
import { useFullscreen } from './fullscreen'
import { FullscreenButton } from './FullscreenButton'
import { terminalTheme } from '../../styles/theme'
import { CONTROLS_KEY, isControlsEvent } from './keys'

export function Terminal() {
  const loc = useLocation()
  const state = loc.state as SessionState | null
  if (!state) return <Navigate to="/" replace />
  // Keyed on the ticket: a failover navigates here with a new ticket and the
  // whole session (socket, xterm) is rebuilt instead of patched.
  return <TerminalSession key={state.ticket} state={state} />
}

function TerminalSession({ state }: { state: SessionState }) {
  const nav = useNavigate()
  const host = useRef<HTMLDivElement>(null)
  const pageRef = useRef<HTMLDivElement>(null)
  const { isFull, toggle: toggleFull, exit: exitFull } = useFullscreen(pageRef)
  const [sessionId, setSessionId] = useState('')
  const [elapsed, setElapsed] = useState(0)
  const [idle, setIdle] = useState(0)
  const [ended, setEnded] = useState<SessionEnd | null>(null)
  const endedRef = useRef(false)
  const [status, setStatus] = useState<'connecting' | 'live'>('connecting')
  const [filesAllowed, setFilesAllowed] = useState(false)
  const [panelOpen, setPanelOpen] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)

  // Where CONTROLS_KEY lands: the first control in the bar.
  const leaveTerminal = () => pageRef.current?.querySelector<HTMLElement>('.term-bar button')?.focus()

  useEffect(() => {
    if (!host.current) return
    const term = new XTerm({ cursorBlink: true, fontFamily: 'ui-monospace, SF Mono, Menlo, Consolas, monospace', fontSize: 13, theme: terminalTheme(), scrollback: 5000 })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.loadAddon(new WebLinksAddon())
    term.open(host.current)
    fit.fit()
    // Tab is a shell key, so xterm keeps it, and so is bare F6 (mc, htop);
    // CONTROLS_KEY moves focus from the terminal to its controls.
    term.attachCustomKeyEventHandler((e) => {
      if (isControlsEvent(e)) {
        e.preventDefault()
        leaveTerminal()
        return false
      }
      return true
    })
    // Pressed again on the bar or in the files panel, it goes back to the
    // terminal; inside the terminal the handler above has it.
    const page = pageRef.current
    const backToTerminal = (e: KeyboardEvent) => {
      if (!isControlsEvent(e) || host.current?.contains(e.target as Node)) return
      e.preventDefault()
      term.focus()
    }
    page?.addEventListener('keydown', backToTerminal)

    const scheme = location.protocol === 'https:' ? 'wss' : 'ws'
    const url = `${scheme}://${location.host}${state.ws_path}?ticket=${encodeURIComponent(state.ticket)}&cols=${term.cols}&rows=${term.rows}`
    const ws = new WebSocket(url)
    ws.binaryType = 'arraybuffer'
    wsRef.current = ws
    const start = Date.now()
    let lastInput = Date.now()
    const enc = new TextEncoder()

    ws.onmessage = (ev) => {
      if (ev.data instanceof ArrayBuffer) {
        term.write(new Uint8Array(ev.data))
        return
      }
      try {
        const c = JSON.parse(ev.data as string) as { t: string; reason?: string; msg?: string; session_id?: string; files?: boolean }
        if (c.t === 'ready') {
          setStatus('live')
          // The id addresses the file-transfer endpoints, so accept only the
          // shape the gateway generates (store.NewID: 32 hex chars).
          if (c.session_id && SESSION_ID.test(c.session_id)) setSessionId(c.session_id)
          if (c.files) setFilesAllowed(true)
        }
        if (c.t === 'end') setEnded({ reason: c.reason ?? 'user_exit', msg: c.msg })
      } catch {
        /* ignore non-JSON text */
      }
    }
    ws.onclose = (ev) => {
      setEnded((cur) => cur ?? { reason: ev.code === 1000 ? ev.reason || 'user_exit' : 'target_lost', msg: ev.code === 1008 ? ev.reason : undefined })
    }
    ws.onerror = () => setEnded((cur) => cur ?? { reason: 'error' })

    const sub = term.onData((d) => {
      lastInput = Date.now()
      if (ws.readyState === WebSocket.OPEN) ws.send(enc.encode(d))
    })
    const resize = term.onResize(({ cols, rows }) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ t: 'r', c: cols, r: rows }))
    })
    // Re-fit whenever the terminal pane changes size — a window resize and the
    // files panel opening or closing alike — so the terminal always fills it.
    const ro = new ResizeObserver(() => { try { fit.fit() } catch { /* terminal detached */ } })
    ro.observe(host.current)
    term.focus()

    const tick = setInterval(() => {
      // Freeze the counters once the session has ended: they are a live
      // reading, and a running clock on a dead session is a lie (manual QA
      // finding 4). endedRef, not the ended state, so the effect does not
      // rebuild the terminal.
      if (endedRef.current) {
        return
      }
      setElapsed(Math.floor((Date.now() - start) / 1000))
      setIdle(Math.floor((Date.now() - lastInput) / 1000))
    }, 1000)

    return () => {
      clearInterval(tick)
      ro.disconnect()
      sub.dispose()
      resize.dispose()
      ws.close()
      page?.removeEventListener('keydown', backToTerminal)
      term.dispose()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.ticket])

  const onSwitched = useSwitched('/terminal', state)
  useEffect(() => { endedRef.current = !!ended }, [ended])
  const failover = ended?.reason === 'target_lost' && !!state.asg_id && !!sessionId
  // Drop out of full screen when the session ends so the dialog and the return
  // to the target list happen in the normal page.
  useEffect(() => { if (ended) exitFull() }, [ended, exitFull])

  return (
    <div className="term-page" ref={pageRef}>
      <div className="term-bar">
        <span className="name">{state.target}</span>
        {state.instance_label && <span className="stat mono">{state.instance_label}</span>}
        {state.switched_from && <span className="stat switched">switched from {state.switched_from}</span>}
        <span className="stat">{protocolName(state.protocol)}</span>
        <span className="stat">{status === 'connecting' ? 'connecting…' : (ended ? 'ran for ' : 'elapsed ') + fmtSeconds(elapsed)}</span>
        {!ended && <span className={'stat' + (idle > 600 ? ' warn' : '')}>idle {fmtSeconds(idle)}</span>}
        <span className="grow" />
        {!ended && <span className="stat hint" title={`Press ${CONTROLS_KEY} to move between the terminal and these controls`}>{CONTROLS_KEY}: controls</span>}
        <span className="sr-only" role="status">{status === 'live' && !ended ? `Connected. Press ${CONTROLS_KEY} to move from the terminal to the controls.` : ''}</span>
        {ended ? (
          <span className="stat">Ended · recording saved</span>
        ) : (
          <span className="stat rec" title="This session is being recorded"><i className="rec-dot" aria-hidden="true" />Recording</span>
        )}
        <FullscreenButton isFull={isFull} onClick={toggleFull} />
        {filesAllowed && (
          <button className="btn sm" onClick={() => setPanelOpen((o) => !o)} aria-pressed={panelOpen}>
            {panelOpen ? 'Hide files' : 'Files'}
          </button>
        )}
        {!ended && <button className="btn sm" onClick={() => wsRef.current?.close(1000, 'user_exit')}>Disconnect</button>}
      </div>
      <div className="desk-body">
        <div className="term-host" ref={host} />
        {filesAllowed && panelOpen && sessionId && <TerminalFiles sessionId={sessionId} />}
      </div>
      {ended && failover && (
        <FailoverDialog sessionId={sessionId} asgId={state.asg_id!} protocol={state.protocol} lostLabel={state.instance_label} onExit={() => nav('/')} onSwitched={onSwitched} />
      )}
      {ended && !failover && (
        <SessionEndedDialog ended={ended} target={state.target} protocol={state.protocol} elapsed={elapsed} onClose={() => nav('/')} />
      )}
    </div>
  )
}
