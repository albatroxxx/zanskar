import { useEffect, useRef, useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { fmtSeconds } from '../../api/format'
import { Modal } from '../../components/ui'

interface DesktopState { ticket: string; ws_path: string; target: string; protocol: string }

/**
 * Desktop renders an RDP or VNC session. The heavy lifting is done by
 * guacamole-common-js, loaded lazily; this page owns the tunnel URL, the top
 * bar and the end-of-session dialog. Arrives fully in Phase 2 once the
 * guacd sidecar is exercised end to end.
 */
export function Desktop() {
  const loc = useLocation()
  const nav = useNavigate()
  const state = loc.state as DesktopState | null
  const host = useRef<HTMLDivElement>(null)
  const [elapsed, setElapsed] = useState(0)
  const [ended, setEnded] = useState<{ reason: string; msg?: string } | null>(null)
  const disconnectRef = useRef<() => void>(() => {})

  useEffect(() => {
    if (!state || !host.current) return
    let disposed = false
    const start = Date.now()
    const tick = setInterval(() => setElapsed(Math.floor((Date.now() - start) / 1000)), 1000)
    const el = host.current
    void import('guacamole-common-js').then((mod) => {
      if (disposed) return
      const Guacamole = mod.default
      const scheme = location.protocol === 'https:' ? 'wss' : 'ws'
      const width = el.clientWidth || 1024
      const height = el.clientHeight || 768
      const dpi = Math.round(96 * (window.devicePixelRatio || 1))
      const tz = Intl.DateTimeFormat().resolvedOptions().timeZone
      const url = `${scheme}://${location.host}${state.ws_path}?ticket=${encodeURIComponent(state.ticket)}&width=${width}&height=${height}&dpi=${dpi}&tz=${encodeURIComponent(tz)}`
      const tunnel = new Guacamole.WebSocketTunnel(url)
      const client = new Guacamole.Client(tunnel)
      el.appendChild(client.getDisplay().getElement())
      client.onerror = (status: { message?: string; code?: number }) => setEnded((cur) => cur ?? { reason: status.code === 519 ? 'target_lost' : 'error', msg: status.message })
      tunnel.onerror = () => setEnded((cur) => cur ?? { reason: 'target_lost' })
      client.onstatechange = (s: number) => {
        if (s === 5) setEnded((cur) => cur ?? { reason: 'user_exit' })
      }
      const mouse = new Guacamole.Mouse(client.getDisplay().getElement())
      const send = (m: unknown) => client.sendMouseState(m as never)
      mouse.onmousedown = mouse.onmouseup = mouse.onmousemove = send
      const keyboard = new Guacamole.Keyboard(document)
      keyboard.onkeydown = (k: number) => client.sendKeyEvent(1, k)
      keyboard.onkeyup = (k: number) => client.sendKeyEvent(0, k)
      client.connect('')
      disconnectRef.current = () => client.disconnect()
      const onResize = () => client.sendSize(el.clientWidth, el.clientHeight)
      window.addEventListener('resize', onResize)
      return () => {
        window.removeEventListener('resize', onResize)
        keyboard.onkeydown = keyboard.onkeyup = null
      }
    })
    return () => {
      disposed = true
      clearInterval(tick)
      disconnectRef.current()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  if (!state) return <Navigate to="/" replace />
  return (
    <div className="term-page">
      <div className="term-bar">
        <span className="name">{state.target}</span>
        <span className="stat">{state.protocol.toUpperCase()}</span>
        <span className="stat">elapsed {fmtSeconds(elapsed)}</span>
        <span className="grow" />
        <span className="stat">recorded</span>
        <button className="btn sm" onClick={() => disconnectRef.current()}>Disconnect</button>
      </div>
      <div className="term-host" ref={host} style={{ overflow: 'hidden' }} />
      {ended && (
        <Modal title="Session ended" onClose={() => nav('/')}>
          <p>{ended.msg ?? ended.reason.replace(/_/g, ' ')}</p>
          <div className="actions">
            <button className="btn primary" onClick={() => nav('/')}>Back to targets</button>
          </div>
        </Modal>
      )}
    </div>
  )
}
