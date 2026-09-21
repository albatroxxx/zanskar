import { useCallback, useEffect, useRef, useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import type { GuacObject, InputStream } from 'guacamole-common-js'
import { fmtBytes, fmtSeconds } from '../../api/format'
import { Modal } from '../../components/ui'

interface DesktopState { ticket: string; ws_path: string; target: string; protocol: string }

type GuacModule = typeof import('guacamole-common-js')['default']

interface Entry { name: string; path: string; dir: boolean }

/**
 * Desktop renders an RDP or VNC session. The heavy lifting is done by
 * guacamole-common-js, loaded lazily; this page owns the tunnel URL, the top
 * bar, the end-of-session dialog and the file panel.
 *
 * File transfer rides on guacd drive redirection: the gateway exposes a
 * per-session directory as a mapped drive named "Zanskar" inside the RDP
 * session, and the browser reads and writes it through Guacamole object
 * streams. The gateway announces whether the policy allows it with a custom
 * "zanskar" instruction right after the tunnel opens; without it the panel is
 * never shown and the bridge drops the drive protocol anyway.
 */
export function Desktop() {
  const loc = useLocation()
  const nav = useNavigate()
  const state = loc.state as DesktopState | null
  const host = useRef<HTMLDivElement>(null)
  const [elapsed, setElapsed] = useState(0)
  const [ended, setEnded] = useState<{ reason: string; msg?: string } | null>(null)
  const [flags, setFlags] = useState({ files: false, clipboard: false })
  const [panelOpen, setPanelOpen] = useState(false)
  const [fsReady, setFsReady] = useState(false)
  const [cwd, setCwd] = useState('/')
  const [entries, setEntries] = useState<Entry[] | null>(null)
  const [status, setStatus] = useState<{ text: string; err?: boolean; progress?: number } | null>(null)
  const disconnectRef = useRef<() => void>(() => {})
  const guacRef = useRef<GuacModule | null>(null)
  const fsRef = useRef<GuacObject | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!state || !host.current) return
    let disposed = false
    const start = Date.now()
    const tick = setInterval(() => setElapsed(Math.floor((Date.now() - start) / 1000)), 1000)
    const el = host.current
    void import('guacamole-common-js').then((mod) => {
      if (disposed) return
      const Guacamole = mod.default
      guacRef.current = Guacamole
      const scheme = location.protocol === 'https:' ? 'wss' : 'ws'
      const width = el.clientWidth || 1024
      const height = el.clientHeight || 768
      const dpi = Math.round(96 * (window.devicePixelRatio || 1))
      const tz = Intl.DateTimeFormat().resolvedOptions().timeZone
      const url = `${scheme}://${location.host}${state.ws_path}?ticket=${encodeURIComponent(state.ticket)}&width=${width}&height=${height}&dpi=${dpi}&tz=${encodeURIComponent(tz)}`
      const tunnel = new Guacamole.WebSocketTunnel(url)
      const client = new Guacamole.Client(tunnel)
      el.appendChild(client.getDisplay().getElement())
      client.onerror = (st) => setEnded((cur) => cur ?? { reason: st.code === 519 ? 'target_lost' : 'error', msg: st.message })
      tunnel.onerror = () => setEnded((cur) => cur ?? { reason: 'target_lost' })
      client.onstatechange = (s: number) => {
        if (s === 5) setEnded((cur) => cur ?? { reason: 'user_exit' })
      }
      client.onfilesystem = (obj) => {
        fsRef.current = obj
        obj.onundefine = () => {
          fsRef.current = null
          setFsReady(false)
        }
        setFsReady(true)
      }
      const mouse = new Guacamole.Mouse(client.getDisplay().getElement())
      const send = (m: unknown) => client.sendMouseState(m as never)
      mouse.onmousedown = mouse.onmouseup = mouse.onmousemove = send
      const keyboard = new Guacamole.Keyboard(document)
      keyboard.onkeydown = (k: number) => client.sendKeyEvent(1, k)
      keyboard.onkeyup = (k: number) => client.sendKeyEvent(0, k)
      client.connect('')
      // connect() installs the client's instruction handler; wrap it so the
      // Zanskar flags instruction is read here and everything else passes on.
      const inner = tunnel.oninstruction
      tunnel.oninstruction = (opcode, args) => {
        if (opcode === 'zanskar') {
          const next = { files: false, clipboard: false }
          for (let i = 0; i + 1 < args.length; i += 2) {
            if (args[i] === 'file') next.files = args[i + 1] === '1'
            if (args[i] === 'clipboard') next.clipboard = args[i + 1] === '1'
          }
          setFlags(next)
          return
        }
        inner?.(opcode, args)
      }
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

  const list = useCallback((dir: string) => {
    const fs = fsRef.current
    const G = guacRef.current
    if (!fs || !G) return
    setEntries(null)
    setStatus(null)
    fs.requestInputStream(dir, (stream: InputStream, mimetype: string) => {
      if (mimetype !== G.Object.STREAM_INDEX_MIMETYPE) {
        setStatus({ text: 'not a directory', err: true })
        return
      }
      const reader = new G.JSONReader(stream)
      reader.onend = () => {
        const idx = (reader.getJSON() ?? {}) as Record<string, string>
        const out: Entry[] = Object.entries(idx).map(([path, mime]) => ({
          path,
          name: path.split('/').filter(Boolean).pop() ?? path,
          dir: mime === G.Object.STREAM_INDEX_MIMETYPE,
        }))
        out.sort((a, b) => (a.dir === b.dir ? a.name.localeCompare(b.name) : a.dir ? -1 : 1))
        setEntries(out)
        setCwd(dir)
      }
    })
  }, [])

  useEffect(() => {
    if (panelOpen && fsReady) list('/')
  }, [panelOpen, fsReady, list])

  const download = (e: Entry) => {
    const fs = fsRef.current
    const G = guacRef.current
    if (!fs || !G) return
    setStatus({ text: `downloading ${e.name}` })
    fs.requestInputStream(e.path, (stream: InputStream, mimetype: string) => {
      const reader = new G.ArrayBufferReader(stream)
      const parts: ArrayBuffer[] = []
      let total = 0
      reader.ondata = (buf) => {
        parts.push(buf)
        total += buf.byteLength
        setStatus({ text: `downloading ${e.name} (${fmtBytes(total)})` })
      }
      reader.onend = () => {
        const blob = new Blob(parts, { type: mimetype || 'application/octet-stream' })
        const a = document.createElement('a')
        a.href = URL.createObjectURL(blob)
        a.download = e.name
        a.click()
        setTimeout(() => URL.revokeObjectURL(a.href), 10_000)
        setStatus({ text: `downloaded ${e.name} (${fmtBytes(total)})` })
      }
    })
  }

  const upload = async (file: File) => {
    const fs = fsRef.current
    const G = guacRef.current
    if (!fs || !G) return
    const dest = (cwd === '/' ? '' : cwd) + '/' + file.name
    const stream = fs.createOutputStream(file.type || 'application/octet-stream', dest)
    const writer = new G.ArrayBufferWriter(stream)
    const chunk = writer.blobLength // one blob per chunk, so one ack per chunk
    let offset = 0
    setStatus({ text: `uploading ${file.name}`, progress: 0 })
    try {
      await new Promise<void>((resolve, reject) => {
        writer.onack = (st) => {
          if (st && st.code && st.code >= 0x100) {
            reject(new Error(st.message || 'upload rejected'))
            return
          }
          if (offset >= file.size) {
            writer.sendEnd()
            resolve()
            return
          }
          void next()
        }
        const next = async () => {
          const buf = await file.slice(offset, offset + chunk).arrayBuffer()
          offset += buf.byteLength
          setStatus({ text: `uploading ${file.name}`, progress: file.size ? offset / file.size : 1 })
          writer.sendData(buf)
        }
        if (file.size === 0) {
          writer.sendEnd()
          resolve()
        } else {
          void next()
        }
      })
      setStatus({ text: `uploaded ${file.name} (${fmtBytes(file.size)})` })
      list(cwd)
    } catch (err) {
      setStatus({ text: `upload failed: ${err instanceof Error ? err.message : String(err)}`, err: true })
    }
  }

  if (!state) return <Navigate to="/" replace />
  const parent = cwd === '/' ? null : cwd.replace(/\/[^/]+\/?$/, '') || '/'
  return (
    <div className="term-page">
      <div className="term-bar">
        <span className="name">{state.target}</span>
        <span className="stat">{state.protocol.toUpperCase()}</span>
        <span className="stat">elapsed {fmtSeconds(elapsed)}</span>
        <span className="grow" />
        <span className="stat">recorded</span>
        {flags.files && (
          <button className="btn sm" onClick={() => setPanelOpen((o) => !o)} aria-pressed={panelOpen}>
            {panelOpen ? 'Hide files' : 'Files'}
          </button>
        )}
        <button className="btn sm" onClick={() => disconnectRef.current()}>Disconnect</button>
      </div>
      <div className="desk-body">
        <div className="term-host" ref={host} style={{ overflow: 'hidden' }} />
        {flags.files && panelOpen && (
          <aside className="files-panel" aria-label="Session files">
            <header>
              <span>Zanskar drive</span>
              <span className="grow" />
              <input ref={fileInput} id="desk-upload" type="file" hidden onChange={(e) => { const f = e.target.files?.[0]; if (f) void upload(f); e.target.value = '' }} />
              <button className="btn sm" disabled={!fsReady} onClick={() => fileInput.current?.click()}>Upload</button>
            </header>
            {!fsReady ? (
              <div className="hint">The drive appears once the desktop session has started. Inside the session it is the "Zanskar" drive; files placed there show up here.</div>
            ) : (
              <div className="list">
                <div className="entry dir" style={{ color: '#9fb6c9' }}>{cwd}</div>
                {parent !== null && (
                  <div className="entry dir" onClick={() => list(parent)}>..</div>
                )}
                {entries === null && <div className="hint">Loading…</div>}
                {entries?.length === 0 && <div className="hint">Empty. Upload a file, or save one to the Zanskar drive in the session.</div>}
                {entries?.map((e) => (
                  <div key={e.path} className={'entry' + (e.dir ? ' dir' : '')} onClick={() => (e.dir ? list(e.path) : download(e))} title={e.dir ? 'open folder' : 'download'}>
                    <span>{e.dir ? '📁' : '📄'}</span>
                    <span>{e.name}</span>
                  </div>
                ))}
              </div>
            )}
            <div className={'status' + (status?.err ? ' err' : '')}>
              {status?.text}
              {status?.progress !== undefined && <progress value={status.progress} max={1} />}
            </div>
          </aside>
        )}
      </div>
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
