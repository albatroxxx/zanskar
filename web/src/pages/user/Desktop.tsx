import { useCallback, useEffect, useRef, useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import type { Client, GuacObject, InputStream, Keyboard } from 'guacamole-common-js'
import { fmtBytes, fmtSeconds, protocolName } from '../../api/format'
import { FailoverDialog } from './Failover'
import { SessionEndedDialog } from './SessionEnded'
import { desktopEnd, saveBlob, SESSION_ID, useSwitched, type SessionEnd, type SessionState } from './session'
import { useFullscreen } from './fullscreen'
import { FullscreenButton } from './FullscreenButton'
import { browserKeys, isPasteKey, keyQueue, pressCombo } from './keys'

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
 * written to the browser clipboard; text copied in the browser is read only
 * when the user presses Ctrl+V or Cmd+V in the desktop, sent first, and the
 * keystroke follows, so the remote application pastes it. Nothing is read on
 * focus or on a timer. Browsers may refuse either half (permission not
 * granted, Firefox without a user gesture), so a clipboard panel with a text
 * box is the fallback in both directions.
 */
export function Desktop() {
  const loc = useLocation()
  const state = loc.state as SessionState | null
  if (!state) return <Navigate to="/" replace />
  // Keyed on the ticket so a failover rebuilds the whole session.
  return <DesktopSession key={state.ticket} state={state} />
}

function DesktopSession({ state }: { state: SessionState }) {
  const nav = useNavigate()
  const host = useRef<HTMLDivElement>(null)
  const pageRef = useRef<HTMLDivElement>(null)
  const { isFull, toggle: toggleFull, exit: exitFull } = useFullscreen(pageRef)
  const [sessionId, setSessionId] = useState('')
  const [elapsed, setElapsed] = useState(0)
  const [ended, setEnded] = useState<SessionEnd | null>(null)
  // False until guacd has drawn the first frame; an application's browser
  // can take a while to start, and the pane is black until then.
  const [connected, setConnected] = useState(false)
  const endedRef = useRef(false)
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
  // The session's key queue, for the browser controls an application has
  // above its pane: their keystrokes wait their turn behind the user's.
  const sendKeyRef = useRef<((pressed: 0 | 1, keysym: number) => Promise<void>) | null>(null)
  const browse = (keys: readonly number[]) => {
    const send = sendKeyRef.current
    if (send) pressCombo(send, keys)
  }
  const guacRef = useRef<GuacModule | null>(null)
  const clientRef = useRef<Client | null>(null)
  const fsRef = useRef<GuacObject | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)
  // Mirrors of state the key handler (registered once) must read.
  const clipAllowedRef = useRef(false)
  // The last text both sides agree on, so a paste does not echo back what
  // the desktop just sent, and unchanged text is not resent.
  const lastClipRef = useRef('')
  // Guacamole.Keyboard listens on the document itself and calls
  // preventDefault on every key it handles. Leaving its handlers set after
  // the page was left made every form field on the site deaf (the login page
  // included) until a full reload; leaving them set once the session ended
  // swallowed Enter, Space and Tab in the very dialog that says so, and in
  // the one offering another instance. The library has no detach call:
  // nulling the handlers is how it is told to stop intercepting.
  const keyboardRef = useRef<Keyboard | null>(null)
  const releaseKeyboard = useCallback(() => {
    const kb = keyboardRef.current
    if (!kb) return
    keyboardRef.current = null
    // Release anything still held (sends the key-ups while the client is
    // there to take them), then stop intercepting the document's keys.
    kb.reset()
    kb.onkeydown = kb.onkeyup = null
  }, [])

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
  // desktop. It runs only on the user's own paste keystroke in the desktop
  // (Ctrl+V or Cmd+V), never on its own: text copied elsewhere for something
  // else (a password, say) stays in the browser until the user pastes it
  // here, as with a native RDP client. Reading needs a permission the
  // browser may not grant; then the panel is the way in.
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
    // The clock stops when the session ends, as on the terminal page: it is a
    // live reading, and a running clock on a dead session is a lie. endedRef,
    // not the ended state, so the effect does not rebuild the session.
    const tick = setInterval(() => {
      if (!endedRef.current) setElapsed(Math.floor((Date.now() - start) / 1000))
    }, 1000)
    const el = host.current
    let ro: ResizeObserver | null = null
    let sizeTimer: ReturnType<typeof setTimeout> | undefined
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
      client.onerror = (st) => setEnded((cur) => cur ?? desktopEnd(st.code, st.message))
      tunnel.onerror = () => setEnded((cur) => cur ?? { reason: 'target_lost' })
      client.onstatechange = (s: number) => {
        if (s === 3) setConnected(true)
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
          if (!navigator.clipboard?.writeText) {
            setClipNote('Copied in the session; this browser cannot write your clipboard, so it is in the panel.')
            setClipOpen(true)
            return
          }
          navigator.clipboard.writeText(text).then(() => setClipNote(null)).catch(() => {
            setClipNote('Copied in the session; the browser did not allow writing your clipboard, so it is in the panel.')
            setClipOpen(true)
          })
        }
      }
      const mouse = new Guacamole.Mouse(client.getDisplay().getElement())
      const send = (m: unknown) => client.sendMouseState(m as never)
      mouse.onmousedown = mouse.onmouseup = mouse.onmousemove = send
      const kb = new Guacamole.Keyboard(document)
      keyboardRef.current = kb
      // Key events go out in order through one queue. A paste keystroke
      // (V with Ctrl or Cmd held) first reads the browser clipboard and
      // sends it to the desktop, and only then is the key passed on, so the
      // remote application pastes what the user meant to paste; the keys
      // after it wait their turn rather than overtaking it.
      const sendKey = keyQueue((pressed, k) => client.sendKeyEvent(pressed, k))
      sendKeyRef.current = sendKey
      // Keys typed into the clipboard panel (or any other field on this page)
      // belong to that field, not to the desktop: returning true tells the
      // library to leave the browser's default alone instead of preventing it.
      kb.onkeydown = (k: number) => {
        if (typingInField()) return true
        // F6 (keysym 0xffc3) leaves the desktop for its controls instead of
        // going to the remote machine (review U2); the browser keeps the key.
        if (k === 0xffc3) {
          pageRef.current?.querySelector<HTMLElement>('.term-bar button')?.focus()
          return true
        }
        const paste = isPasteKey(k, kb.modifiers) && clipAllowedRef.current
        void sendKey(1, k, paste ? pullBrowserClipboard : undefined)
        return false
      }
      kb.onkeyup = (k: number) => {
        if (typingInField()) return
        void sendKey(0, k)
      }
      client.connect('')
      // connect() installs the client's instruction handler; wrap it so the
      // Zanskar flags instruction is read here and everything else passes on.
      const inner = tunnel.oninstruction
      tunnel.oninstruction = (opcode, args) => {
        // The tunnel's internal opcode carries the Zanskar session id first.
        // It addresses the failover endpoint, so only the shape the gateway
        // generates is taken, as on the terminal page.
        if (opcode === '' && SESSION_ID.test(args[0] ?? '')) setSessionId((cur) => cur || args[0])
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
      releaseKeyboard()
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

  // The gateway says whether the policy allows the clipboard; until it does,
  // nothing is read or sent.
  useEffect(() => {
    clipAllowedRef.current = flags.clipboard
  }, [flags.clipboard])

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
        saveBlob(new Blob(parts, { type: mimetype || 'application/octet-stream' }), e.name)
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
  const onSwitched = useSwitched('/desktop', state)
  useEffect(() => { endedRef.current = !!ended }, [ended])
  // An ended session takes no more keys; the dialogs that follow need them.
  useEffect(() => { if (ended) releaseKeyboard() }, [ended, releaseKeyboard])
  const failover = ended?.reason === 'target_lost' && !!state.asg_id && !!sessionId
  // Drop out of full screen when the session ends so the dialog shows normally.
  useEffect(() => { if (ended) exitFull() }, [ended, exitFull])
  return (
    <div className="term-page" ref={pageRef}>
      <div className="term-bar">
        <span className="name">{state.target}</span>
        {state.instance_label && <span className="stat mono">{state.instance_label}</span>}
        {state.switched_from && <span className="stat switched">switched from {state.switched_from}</span>}
        <span className="stat">{protocolName(state.protocol)}</span>
        <span className="stat">{(ended ? 'ran for ' : 'elapsed ') + fmtSeconds(elapsed)}</span>
        <span className="grow" />
        {!ended && !connected && <span className="stat hint" role="status">Connecting…</span>}
        {!ended && <span className="stat hint" title="Press F6 to move from the desktop to these controls">F6: controls</span>}
        {ended ? (
          <span className="stat">Ended · recording saved</span>
        ) : (
          <span className="stat rec" title="This session is being recorded"><i className="rec-dot" aria-hidden="true" />Recording</span>
        )}
        {state.protocol === 'http' && !ended && (
          // An application's browser has no controls of its own (kiosk mode,
          // ADR 0034); without these a page the policy blocked was a dead end.
          <span className="browser-nav" role="group" aria-label="Browser">
            <button className="btn sm" disabled={!connected} onClick={() => browse(browserKeys.back)} aria-label="Back" title="Back">←</button>
            <button className="btn sm" disabled={!connected} onClick={() => browse(browserKeys.forward)} aria-label="Forward" title="Forward">→</button>
            <button className="btn sm" disabled={!connected} onClick={() => browse(browserKeys.reload)} aria-label="Reload" title="Reload">↻</button>
            <button className="btn sm" disabled={!connected} onClick={() => browse(browserKeys.home)} aria-label="Home" title="The application's start page">⌂</button>
          </span>
        )}
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
        {!ended && <button className="btn sm" onClick={() => disconnectRef.current()}>Disconnect</button>}
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
            <div className="hint">Copied in the session shows here; send text below into it.</div>
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
              <div className="hint">Available once the session starts, as the "Zanskar" drive.</div>
            ) : (
              <div className="list">
                <div className="entry dir">{cwd}</div>
                {parent !== null && (
                  <button type="button" className="entry dir" title="parent folder" onClick={() => list(parent)}>..</button>
                )}
                {entries === null && <div className="hint">Loading…</div>}
                {entries?.length === 0 && <div className="hint">Empty.</div>}
                {entries?.map((e) => (
                  <button type="button" key={e.path} className={'entry' + (e.dir ? ' dir' : '')} onClick={() => (e.dir ? list(e.path) : download(e))} title={e.dir ? 'open folder' : 'download'}>
                    <span aria-hidden="true">{e.dir ? '📁' : '📄'}</span>
                    <span>{e.name}</span>
                  </button>
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
        <SessionEndedDialog ended={ended} target={state.target} protocol={state.protocol} elapsed={elapsed} onClose={() => nav('/')} />
      )}
    </div>
  )
}
