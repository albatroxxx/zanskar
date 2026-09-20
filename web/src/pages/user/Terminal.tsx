import { useEffect, useRef, useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { Terminal as XTerm } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { WebLinksAddon } from '@xterm/addon-web-links'
import '@xterm/xterm/css/xterm.css'
import { fmtSeconds } from '../../api/format'
import { Modal } from '../../components/ui'

interface TerminalState { ticket: string; ws_path: string; target: string; protocol: string }

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
  const nav = useNavigate()
  const state = loc.state as TerminalState | null
  const host = useRef<HTMLDivElement>(null)
  const [elapsed, setElapsed] = useState(0)
  const [idle, setIdle] = useState(0)
  const [ended, setEnded] = useState<{ reason: string; msg?: string } | null>(null)
  const [status, setStatus] = useState<'connecting' | 'live'>('connecting')
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!state || !host.current) return
    const term = new XTerm({ cursorBlink: true, fontFamily: 'ui-monospace, SF Mono, Menlo, Consolas, monospace', fontSize: 13, theme: { background: '#0a1a2c' }, scrollback: 5000 })
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
        const c = JSON.parse(ev.data as string) as { t: string; reason?: string; msg?: string }
        if (c.t === 'ready') setStatus('live')
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
    const onWin = () => fit.fit()
    window.addEventListener('resize', onWin)
    term.focus()

    const tick = setInterval(() => {
      setElapsed(Math.floor((Date.now() - start) / 1000))
      setIdle(Math.floor((Date.now() - lastInput) / 1000))
    }, 1000)

    return () => {
      clearInterval(tick)
      window.removeEventListener('resize', onWin)
      sub.dispose()
      resize.dispose()
      ws.close()
      term.dispose()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  if (!state) return <Navigate to="/" replace />

  return (
    <div className="term-page">
      <div className="term-bar">
        <span className="name">{state.target}</span>
        <span className="stat">{state.protocol.toUpperCase()}</span>
        <span className="stat">{status === 'connecting' ? 'connecting…' : 'elapsed ' + fmtSeconds(elapsed)}</span>
        <span className={'stat' + (idle > 600 ? ' warn' : '')}>idle {fmtSeconds(idle)}</span>
        <span className="grow" />
        <span className="stat">recorded</span>
        <button className="btn sm" onClick={() => wsRef.current?.close(1000, 'user_exit')}>Disconnect</button>
      </div>
      <div className="term-host" ref={host} />
      {ended && (
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
