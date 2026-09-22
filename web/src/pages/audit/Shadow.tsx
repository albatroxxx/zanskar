import { useEffect, useRef, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { Terminal as XTerm } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import { fmtSeconds } from '../../api/format'
import { Modal } from '../../components/ui'
import { terminalTheme } from '../../styles/theme'

/**
 * Shadow is the read-only live view an admin or auditor opens on a running
 * session. Terminal protocols stream the tap (scrollback replay, then live
 * output); desktop protocols join the guacd connection read-only. Nothing
 * the watcher types or clicks reaches the target.
 */
export function Shadow() {
  const { id } = useParams()
  const [q] = useSearchParams()
  const nav = useNavigate()
  const protocol = q.get('protocol') ?? 'ssh'
  const target = q.get('target') ?? id ?? ''
  const isDesktop = protocol === 'rdp' || protocol === 'vnc'
  const host = useRef<HTMLDivElement>(null)
  const [elapsed, setElapsed] = useState(0)
  const [status, setStatus] = useState<'connecting' | 'live'>('connecting')
  const [ended, setEnded] = useState<string | null>(null)
  const closeRef = useRef<() => void>(() => {})

  useEffect(() => {
    if (!id || !host.current) return
    const el = host.current
    const start = Date.now()
    const tick = setInterval(() => setElapsed(Math.floor((Date.now() - start) / 1000)), 1000)
    const scheme = location.protocol === 'https:' ? 'wss' : 'ws'
    let cleanup = () => {}

    if (!isDesktop) {
      const term = new XTerm({ disableStdin: true, cursorBlink: false, fontFamily: 'ui-monospace, SF Mono, Menlo, Consolas, monospace', fontSize: 13, theme: terminalTheme(), scrollback: 10000 })
      const fit = new FitAddon()
      term.loadAddon(fit)
      term.open(el)
      fit.fit()
      const ws = new WebSocket(`${scheme}://${location.host}/ws/shadow/${encodeURIComponent(id)}`)
      ws.binaryType = 'arraybuffer'
      ws.onmessage = (ev) => {
        if (ev.data instanceof ArrayBuffer) {
          term.write(new Uint8Array(ev.data))
          return
        }
        try {
          const c = JSON.parse(ev.data as string) as { t: string; reason?: string }
          if (c.t === 'ready') setStatus('live')
          if (c.t === 'end') setEnded(c.reason ?? 'session_ended')
        } catch {
          /* ignore */
        }
      }
      ws.onclose = () => setEnded((cur) => cur ?? 'session_ended')
      ws.onerror = () => setEnded((cur) => cur ?? 'error')
      const onWin = () => fit.fit()
      window.addEventListener('resize', onWin)
      closeRef.current = () => ws.close(1000, 'watcher_left')
      cleanup = () => {
        window.removeEventListener('resize', onWin)
        ws.close()
        term.dispose()
      }
    } else {
      let disposed = false
      void import('guacamole-common-js').then((mod) => {
        if (disposed) return
        const Guacamole = mod.default
        const width = el.clientWidth || 1024
        const height = el.clientHeight || 768
        const tunnel = new Guacamole.WebSocketTunnel(`${scheme}://${location.host}/ws/shadow/${encodeURIComponent(id)}?width=${width}&height=${height}`)
        const client = new Guacamole.Client(tunnel)
        const display = client.getDisplay().getElement()
        display.style.pointerEvents = 'none'
        el.appendChild(display)
        client.onerror = () => setEnded((cur) => cur ?? 'error')
        tunnel.onerror = () => setEnded((cur) => cur ?? 'session_ended')
        client.onstatechange = (s: number) => {
          if (s === 3) setStatus('live')
          if (s === 5) setEnded((cur) => cur ?? 'session_ended')
        }
        client.connect('')
        closeRef.current = () => client.disconnect()
      })
      cleanup = () => {
        disposed = true
        closeRef.current()
      }
    }
    return () => {
      clearInterval(tick)
      cleanup()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id])

  return (
    <div className="term-page">
      <div className="term-bar">
        <span className="name">Watching {target}</span>
        <span className="stat">{protocol.toUpperCase()} · read-only</span>
        <span className="stat">{status === 'connecting' ? 'connecting…' : 'watching ' + fmtSeconds(elapsed)}</span>
        <span className="grow" />
        <span className="stat">this view is audited</span>
        <button className="btn sm" onClick={() => { closeRef.current(); nav(-1) }}>Stop watching</button>
      </div>
      <div className="term-host" ref={host} style={isDesktop ? { overflow: 'hidden' } : undefined} />
      {ended && (
        <Modal title="Session ended" onClose={() => nav(-1)}>
          <p>{ended === 'session_ended' ? 'The session you were watching has ended.' : 'The connection to the gateway was lost.'}</p>
          <div className="actions">
            <button className="btn primary" onClick={() => nav(-1)}>Back</button>
          </div>
        </Modal>
      )}
    </div>
  )
}
