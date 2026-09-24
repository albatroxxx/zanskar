import { useEffect, useRef, useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { Terminal as XTerm } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { WebLinksAddon } from '@xterm/addon-web-links'
import '@xterm/xterm/css/xterm.css'
import { fmtSeconds } from '../../api/format'
import { Modal } from '../../components/ui'
import { FailoverDialog } from './Failover'
import { TerminalFiles } from './TerminalFiles'
import { useFullscreen } from './fullscreen'
import { FullscreenButton } from './FullscreenButton'
import type { ConnectResponse } from '../../api/types'
import { terminalTheme } from '../../styles/theme'

interface TerminalState {
  ticket: string
  ws_path: string
  target: string
  protocol: string
  asg_id?: string
  asg_instance_id?: string
  instance_label?: string
  switched_from?: string
}

const reasonText: Record<string, string> = {
  user_exit: 'The session ended.',
  idle_timeout: 'Disconnected after a period without input.',
  max_duration: 'The session reached its maximum duration.',
  admin_terminated: 'An administrator ended the session.',
  target_lost: 'The connection to the target was lost.',
  error: 'The session ended because of an error.',
}

export function Terminal() {
  const loc = useLocation()
  const state = loc.state as TerminalState | null
  if (!state) return <Navigate to="/" replace />
  // Keyed on the ticket: a failover navigates here with a new ticket and the
  // whole session (socket, xterm) is rebuilt instead of patched.
  return <TerminalSession key={state.ticket} state={state} />
}

function TerminalSession({ state }: { state: TerminalState }) {
  const nav = useNavigate()
  const host = useRef<HTMLDivElement>(null)
  const pageRef = useRef<HTMLDivElement>(null)
  const { isFull, toggle: toggleFull, exit: exitFull } = useFullscreen(pageRef)
  const [sessionId, setSessionId] = useState('')
  const [elapsed, setElapsed] = useState(0)
  const [idle, setIdle] = useState(0)
  const [ended, setEnded] = useState<{ reason: string; msg?: string } | null>(null)
  const [status, setStatus] = useState<'connecting' | 'live'>('connecting')
  const [filesAllowed, setFilesAllowed] = useState(false)
  const [panelOpen, setPanelOpen] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!host.current) return
    const term = new XTerm({ cursorBlink: true, fontFamily: 'ui-monospace, SF Mono, Menlo, Consolas, monospace', fontSize: 13, theme: terminalTheme(), scrollback: 5000 })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.loadAddon(new WebLinksAddon())
    term.open(host.current)
    fit.fit()

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
          if (c.session_id) setSessionId(c.session_id)
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
      setElapsed(Math.floor((Date.now() - start) / 1000))
      setIdle(Math.floor((Date.now() - lastInput) / 1000))
    }, 1000)

    return () => {
      clearInterval(tick)
      ro.disconnect()
      sub.dispose()
      resize.dispose()
      ws.close()
      term.dispose()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.ticket])

  const onSwitched = (res: ConnectResponse) => {
    nav('/terminal', {
      replace: true,
      state: {
        ticket: res.ticket,
        ws_path: res.ws_path,
        target: state.target,
        protocol: state.protocol,
        asg_id: res.asg_id ?? state.asg_id,
        asg_instance_id: res.asg_instance_id,
        instance_label: res.instance_label,
        switched_from: state.instance_label,
      } satisfies TerminalState,
    })
  }
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
        <span className="stat">{state.protocol.toUpperCase()}</span>
        <span className="stat">{status === 'connecting' ? 'connecting…' : 'elapsed ' + fmtSeconds(elapsed)}</span>
        <span className={'stat' + (idle > 600 ? ' warn' : '')}>idle {fmtSeconds(idle)}</span>
        <span className="grow" />
        <span className="stat">recorded</span>
        <FullscreenButton isFull={isFull} onClick={toggleFull} />
        {filesAllowed && (
          <button className="btn sm" onClick={() => setPanelOpen((o) => !o)} aria-pressed={panelOpen}>
            {panelOpen ? 'Hide files' : 'Files'}
          </button>
        )}
        <button className="btn sm" onClick={() => wsRef.current?.close(1000, 'user_exit')}>Disconnect</button>
      </div>
      <div className="desk-body">
        <div className="term-host" ref={host} />
        {filesAllowed && panelOpen && sessionId && <TerminalFiles sessionId={sessionId} />}
      </div>
      {ended && failover && (
        <FailoverDialog sessionId={sessionId} asgId={state.asg_id!} protocol={state.protocol} lostLabel={state.instance_label} onExit={() => nav('/')} onSwitched={onSwitched} />
      )}
      {ended && !failover && (
        <Modal title="Session ended" onClose={() => nav('/')}>
          <p>{reasonText[ended.reason] ?? ended.reason}</p>
          {ended.msg && <p className="muted">{ended.msg}</p>}
          <div className="actions">
            <button className="btn primary" onClick={() => nav('/')}>Back to targets</button>
          </div>
        </Modal>
      )}
    </div>
  )
}
