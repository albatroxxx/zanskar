import { useCallback, useEffect, useRef, useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import type { Client, GuacObject, InputStream, Keyboard } from 'guacamole-common-js'
import { fmtBytes, fmtSeconds } from '../../api/format'
import { Modal } from '../../components/ui'
import { FailoverDialog } from './Failover'
import { useFullscreen } from './fullscreen'
import { FullscreenButton } from './FullscreenButton'
import type { ConnectResponse } from '../../api/types'

interface DesktopState {
  ticket: string
  ws_path: string
  target: string
  protocol: string
  asg_id?: string
  asg_instance_id?: string
  instance_label?: string
  switched_from?: string
}

type GuacModule = typeof import('guacamole-common-js')['default']

interface Entry { name: string; path: string; dir: boolean }

/** typingInField reports whether keyboard focus is in a text field on this
 *  page (the clipboard panel, for one) rather than on the desktop, in which
 *  case keystrokes must not be forwarded to the remote machine. */
function typingInField(): boolean {
  const el = document.activeElement
  if (!(el instanceof HTMLElement)) return false
  return el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement || el.isContentEditable
}

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
 *
 * The clipboard, when the policy allows it, is synced both ways: text copied
 * inside the desktop arrives through the client's clipboard stream and is
 * written to the browser clipboard; text copied in the browser is read
 * whenever the window regains focus and sent to the desktop, so a plain
 * Ctrl+V inside the session pastes it. Browsers may refuse either half
 * (permission not granted, Firefox without a user gesture), so a clipboard
 * panel with a text box is the fallback in both directions.
 */
export function Desktop() {
  const loc = useLocation()
  const state = loc.state as DesktopState | null
  if (!state) return <Navigate to="/" replace />
  // Keyed on the ticket so a failover rebuilds the whole session.
  return <DesktopSession key={state.ticket} state={state} />
}

function DesktopSession({ state }: { state: DesktopState }) {
  const nav = useNavigate()
  const host = useRef<HTMLDivElement>(null)
  const pageRef = useRef<HTMLDivElement>(null)
  const { isFull, toggle: toggleFull, exit: exitFull } = useFullscreen(pageRef)
  const [sessionId, setSessionId] = useState('')
  const [elapsed, setElapsed] = useState(0)
  const [ended, setEnded] = useState<{ reason: string; msg?: string } | null>(null)
  const [flags, setFlags] = useState({ files: false, clipboard: false })
  const [panelOpen, setPanelOpen] = useState(false)
  const [fsReady, setFsReady] = useState(false)
  const [cwd, setCwd] = useState('/')
  const [entries, setEntries] = useState<Entry[] | null>(null)
  const [status, setStatus] = useState<{ text: string; err?: boolean; progress?: number } | null>(null)
  const [clipOpen, setClipOpen] = useState(false)
  const [clipText, setClipText] = useState('')
  const [clipNote, setClipNote] = useState<string | null>(null)
  const disconnectRef = useRef<() => void>(() => {})
  const guacRef = useRef<GuacModule | null>(null)
  const clientRef = useRef<Client | null>(null)
  const fsRef = useRef<GuacObject | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)
  // Mirrors of state the window focus listener (registered once) must read.
  const clipAllowedRef = useRef(false)
  // The last text both sides agree on, so a focus sync does not echo back
  // what the desktop just sent, and unchanged text is not resent.
  const lastClipRef = useRef('')

  // pushClipboard sends text to the desktop's clipboard through a Guacamole
  // clipboard stream. The bridge drops the instruction when the policy
  // forbids it, but the flag is checked here too so nothing is attempted.
  const pushClipboard = useCallback((text: string) => {
    const client = clientRef.current
    const G = guacRef.current
    if (!client || !G || !clipAllowedRef.current || text === lastClipRef.current) return
    lastClipRef.current = text
    const writer = new G.StringWriter(client.createClipboardStream('text/plain'))
    writer.sendText(text)
    writer.sendEnd()
  }, [])

  // pullBrowserClipboard reads the browser clipboard and pushes it to the
  // desktop. It runs on window focus, the moment the user comes back from
  // copying something elsewhere. Reading needs a permission the browser may
  // not grant; then the panel is the way in.
  const pullBrowserClipboard = useCallback(async () => {
    if (!clipAllowedRef.current || !navigator.clipboard?.readText) return
    try {
      const text = await navigator.clipboard.readText()
      if (text) pushClipboard(text)
    } catch {
      setClipNote('The browser did not allow reading your clipboard. Paste into the panel and send it to the session instead.')
    }
  }, [pushClipboard])

  useEffect(() => {
    if (!host.current) return
    let disposed = false
    const start = Date.now()
    const tick = setInterval(() => setElapsed(Math.floor((Date.now() - start) / 1000)), 1000)
    const el = host.current
    // Assigned once the library has loaded; released by the effect cleanup
    // below. Guacamole.Keyboard listens on the document itself and calls
    // preventDefault on every key it handles, so leaving its handlers set
    // after the session left every form field on the site deaf (the login
    // page included) until a full reload. The library has no detach call:
    // nulling the handlers is how it is told to stop intercepting.
    let keyboard: Keyboard | null = null
    let ro: ResizeObserver | null = null
    let sizeTimer: ReturnType<typeof setTimeout> | undefined
    const onFocus = () => { void pullBrowserClipboard() }
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
      clientRef.current = client
      // Text the desktop copied: hand it to the browser clipboard, and keep it
      // in the panel in case the browser refuses (it may, unless the page is
      // focused and the permission is granted).
      client.onclipboard = (stream, mimetype) => {
        const reader = new Guacamole.StringReader(stream)
        let text = ''
        reader.ontext = (t) => { text += t }
        reader.onend = () => {
          if (!mimetype.startsWith('text/')) return
          lastClipRef.current = text
          setClipText(text)
          const write = navigator.clipboard?.writeText?.(text)
          if (!write) {
            setClipNote('Copied in the session; this browser cannot write your clipboard, so it is in the panel.')
            setClipOpen(true)
            return
          }
          write.then(() => setClipNote(null)).catch(() => {
            setClipNote('Copied in the session; the browser did not allow writing your clipboard, so it is in the panel.')
            setClipOpen(true)
          })
        }
      }
      const mouse = new Guacamole.Mouse(client.getDisplay().getElement())
      const send = (m: unknown) => client.sendMouseState(m as never)
      mouse.onmousedown = mouse.onmouseup = mouse.onmousemove = send
      keyboard = new Guacamole.Keyboard(document)
      // Keys typed into the clipboard panel (or any other field on this page)
      // belong to that field, not to the desktop: returning true tells the
      // library to leave the browser's default alone instead of preventing it.
      keyboard.onkeydown = (k: number) => {
        if (typingInField()) return true
        client.sendKeyEvent(1, k)
        return false
      }
      keyboard.onkeyup = (k: number) => {
        if (typingInField()) return
        client.sendKeyEvent(0, k)
      }
      window.addEventListener('focus', onFocus)
      client.connect('')
      // connect() installs the client's instruction handler; wrap it so the
      // Zanskar flags instruction is read here and everything else passes on.
      const inner = tunnel.oninstruction
      tunnel.oninstruction = (opcode, args) => {
        // The tunnel's internal opcode carries the Zanskar session id first.
        if (opcode === '' && args[0]) setSessionId((cur) => cur || args[0])
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
      // Resize the remote desktop to match the pane on every change — a window
      // resize and the files panel opening or closing alike. The previous
      // window-only listener missed the panel toggle, leaving the desktop at
      // its old size with dead space around it. guacd's RDP dynamic resize
      // re-renders at the new size 1:1, so no client-side scaling (and no mouse
      // remapping) is needed. Debounced so a drag-resize does not spam guacd.
      ro = new ResizeObserver(() => {
        clearTimeout(sizeTimer)
        sizeTimer = setTimeout(() => client.sendSize(el.clientWidth, el.clientHeight), 200)
      })
      ro.observe(el)
    })
    return () => {
      disposed = true
      clearInterval(tick)
      clearTimeout(sizeTimer)
      ro?.disconnect()
      window.removeEventListener('focus', onFocus)
      if (keyboard) {
        // Release anything still held (sends the key-ups while the client is
        // connected), then stop intercepting the document's key events.
        keyboard.reset()
        keyboard.onkeydown = keyboard.onkeyup = null
      }
      clientRef.current = null
      disconnectRef.current()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.ticket])

  const list = useCallback((dir: string) => {
    const fs = fsRef.current
    const G = guacRef.current
    if (!fs || !G) return
    setEntries(null)
    setStatus(null)
    fs.requestInputStream(dir, (stream: InputStream, mimetype: string) => {
      if (mimetype !== G.Object.STREAM_INDEX_MIMETYPE) {
        stream.sendAck('Not a directory', 0x0100)
        setStatus({ text: 'not a directory', err: true })
        setEntries([])
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
      // guacd sends the index only once the body is acknowledged, and the
      // readers in guacamole-common-js ack only after a blob arrives. Without
      // this readiness ack neither side moves and the panel waits forever.
      stream.sendAck('Ready', 0x0000)
    })
  }, [])

  useEffect(() => {
    if (panelOpen && fsReady) list('/')
  }, [panelOpen, fsReady, list])

  // Once the gateway says the policy allows the clipboard, seed the desktop
  // with whatever the browser holds, provided the page is focused (reading
  // an unfocused document's clipboard is refused outright).
  useEffect(() => {
    clipAllowedRef.current = flags.clipboard
    if (flags.clipboard && document.hasFocus()) void pullBrowserClipboard()
  }, [flags.clipboard, pullBrowserClipboard])

  const download = (e: Entry) => {
    const fs = fsRef.current
    const G = guacRef.current
    if (!fs || !G) return
    setStatus({ text: `downloading ${e.name}` })
    fs.requestInputStream(e.path, (stream: InputStream, mimetype: string) => {
      const reader = new G.ArrayBufferReader(stream)
      const parts: ArrayBuffer[] = []
      let total = 0
      // Acknowledged below, once the handlers are wired: guacd waits for it
      // before sending the first chunk.
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
      stream.sendAck('Ready', 0x0000)
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

  const parent = cwd === '/' ? null : cwd.replace(/\/[^/]+\/?$/, '') || '/'
  const onSwitched = (res: ConnectResponse) => {
    nav('/desktop', {
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
      } satisfies DesktopState,
    })
  }
  const failover = ended?.reason === 'target_lost' && !!state.asg_id && !!sessionId
  // Drop out of full screen when the session ends so the dialog shows normally.
  useEffect(() => { if (ended) exitFull() }, [ended, exitFull])
  return (
    <div className="term-page" ref={pageRef}>
      <div className="term-bar">
        <span className="name">{state.target}</span>
        {state.instance_label && <span className="stat mono">{state.instance_label}</span>}
        {state.switched_from && <span className="stat switched">switched from {state.switched_from}</span>}
        <span className="stat">{state.protocol.toUpperCase()}</span>
        <span className="stat">elapsed {fmtSeconds(elapsed)}</span>
        <span className="grow" />
        <span className="stat rec" title="This session is being recorded"><i className="rec-dot" aria-hidden="true" />Recording</span>
        <FullscreenButton isFull={isFull} onClick={toggleFull} />
        {flags.clipboard && (
          <button className="btn sm" onClick={() => setClipOpen((o) => !o)} aria-pressed={clipOpen}>
            {clipOpen ? 'Hide clipboard' : 'Clipboard'}
          </button>
        )}
        {flags.files && (
          <button className="btn sm" onClick={() => setPanelOpen((o) => !o)} aria-pressed={panelOpen}>
            {panelOpen ? 'Hide files' : 'Files'}
          </button>
        )}
        <button className="btn sm" onClick={() => disconnectRef.current()}>Disconnect</button>
      </div>
      <div className="desk-body">
        <div className="term-host" ref={host} style={{ overflow: 'hidden' }} />
        {flags.clipboard && clipOpen && (
          <aside className="files-panel clip-panel" aria-label="Session clipboard">
            <header>
              <span>Clipboard</span>
              <span className="grow" />
              <button className="btn sm" onClick={() => setClipOpen(false)}>Close</button>
            </header>
            <div className="hint">Text copied inside the session shows up here. Paste text below and send it to make it available inside the session; it syncs on its own when the browser allows.</div>
            <textarea value={clipText} onChange={(e) => setClipText(e.target.value)} spellCheck={false} aria-label="Clipboard text" />
            <div className="row">
              <button className="btn sm primary" disabled={!clipText} onClick={() => pushClipboard(clipText)}>Send to session</button>
              <button className="btn sm" disabled={!clipText} onClick={() => { void navigator.clipboard?.writeText(clipText).then(() => setClipNote('Copied to your clipboard.')).catch(() => setClipNote('The browser did not allow writing your clipboard; select the text and copy it.')) }}>Copy</button>
            </div>
            <div className={'status' + (clipNote ? '' : ' quiet')}>{clipNote}</div>
          </aside>
        )}
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
                <div className="entry dir">{cwd}</div>
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
      {ended && failover && (
        <FailoverDialog sessionId={sessionId} asgId={state.asg_id!} protocol={state.protocol} lostLabel={state.instance_label} onExit={() => nav('/')} onSwitched={onSwitched} />
      )}
      {ended && !failover && (
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
