import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { Link, useParams } from 'react-router-dom'
import * as AsciinemaPlayer from 'asciinema-player'
import 'asciinema-player/dist/bundle/asciinema-player.css'
import { api, errorMessage } from '../../api/client'
import { fmtBytes, fmtDuration, fmtSeconds, fmtTime } from '../../api/format'
import { sessionTarget, sessionUser } from '../../api/labels'
import type { Recording } from '../../api/types'
import { TransportIcon } from '../../components/icons'
import { Alert, Badge, Empty, PageHead, reasonBadge } from '../../components/ui'
import { useFullscreen } from '../user/fullscreen'
import { FullscreenButton } from '../user/FullscreenButton'
import { useRecordingsPath } from './paths'

type PlayerHandle = ReturnType<typeof AsciinemaPlayer.create>
/** How the terminal player sizes itself: to the card's width on the page,
 *  to the whole screen (width and height) in full screen. */
type TermFit = 'width' | 'both'
type GuacModule = typeof import('guacamole-common-js').default
type SessionRecording = InstanceType<GuacModule['SessionRecording']>

/** A command the user submitted, taken from the recording's marker events. */
interface Command { t: number; text: string }

/** Idle gaps longer than this many seconds are compressed on playback, so a
 *  reviewer is not made to sit through a lunch break in real time. */
const IDLE_LIMIT = 2
const SKIP_SECONDS = 10
const SPEEDS = [0.5, 1, 1.5, 2, 4]
/** Room kept under the replayed desktop in full screen for the transport and
 *  the stage's padding. */
const FULL_RESERVE = 72

/** parseCast reads an asciicast v2 file once: the marker events ([time, "m",
 *  label]) the gateway writes per submitted command line ("(hidden input)"
 *  marks text the remote did not echo, such as a password, which is never
 *  recorded), and the time of every event, needed by rawTime below. */
function parseCast(cast: string): { commands: Command[]; times: number[] } {
  const commands: Command[] = []
  const times: number[] = []
  for (const line of cast.split('\n')) {
    if (!line.startsWith('[')) continue
    try {
      const ev = JSON.parse(line) as [number, string, string]
      times.push(ev[0])
      if (ev[1] === 'm' && typeof ev[2] === 'string') commands.push({ t: ev[0], text: ev[2] })
    } catch {
      /* not an event line */
    }
  }
  return { commands, times }
}

/** rawTime turns a position on the player's idle-compressed clock back into
 *  recording time. Changing speed means creating the player again, and its
 *  startAt option is taken in recording time; handing it the compressed time
 *  would land earlier by every idle gap that was squeezed out so far. This
 *  mirrors the player's own limiter: each gap longer than the limit shifts
 *  every later event left by the excess. */
function rawTime(times: number[], compressed: number): number {
  let prev = 0
  let shift = 0
  for (const t of times) {
    const excess = t - prev - IDLE_LIMIT
    const next = excess > 0 ? shift + excess : shift
    if (t - next > compressed) break
    shift = next
    prev = t
  }
  return compressed + shift
}

/** Recording ids are 16 random bytes, hex-encoded (store.NewID). The id in
 *  the address bar goes into API paths, so the player asks for nothing of
 *  another shape: encoding keeps a slash from adding a path segment, but no
 *  encoding keeps a bare ".." from climbing one. */
const RECORDING_ID = /^[0-9a-f]{32}$/

/** recordingPath is a recording's API path, with the id encoded. */
function recordingPath(id: string): string {
  return `/recordings/${encodeURIComponent(id)}`
}

/** typingInField keeps playback shortcuts away from any text field. */
function typingInField(): boolean {
  const el = document.activeElement
  return el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement || el instanceof HTMLSelectElement
}

/** IconButton is one transport control: a glyph on the button, its words in
 *  the accessible name and the tooltip. */
function IconButton({ label, onClick, primary, children }: { label: string; onClick: () => void; primary?: boolean; children: ReactNode }) {
  return (
    <button type="button" className={'btn sm icon' + (primary ? ' primary' : '')} onClick={onClick} aria-label={label} title={label}>
      {children}
    </button>
  )
}

export function Player() {
  const recordingsPath = useRecordingsPath()
  const { id = '' } = useParams()
  const [rec, setRec] = useState<Recording | null>(null)
  const [err, setErr] = useState('')
  const [phase, setPhase] = useState<'idle' | 'loading' | 'playing'>('idle')
  const [commands, setCommands] = useState<Command[]>([])
  const host = useRef<HTMLDivElement>(null)
  // The stage is what goes full screen: the picture and the transport under
  // it, the way a session's whole page does, so the controls stay in reach.
  const stage = useRef<HTMLDivElement>(null)
  const { isFull, toggle: toggleFull } = useFullscreen(stage)
  const full = useRef(false)
  const termFit = useRef<TermFit>('width')
  const term = useRef<PlayerHandle | null>(null)
  const cast = useRef<{ text: string; times: number[] } | null>(null)
  const desk = useRef<SessionRecording | null>(null)
  // transport state shared by both players
  const [duration, setDuration] = useState(0)
  const [position, setPosition] = useState(0)
  const [running, setRunning] = useState(false)
  const [speed, setSpeed] = useState(1)
  const [loaded, setLoaded] = useState(false)

  useEffect(() => {
    if (!RECORDING_ID.test(id)) {
      setErr('There is no recording with that id.')
      return
    }
    api
      .get<Recording>(recordingPath(id))
      .then(setRec)
      .catch((e) => setErr(errorMessage(e)))
  }, [id])

  useEffect(() => {
    return () => {
      term.current?.dispose()
      term.current = null
      desk.current?.disconnect()
      desk.current = null
    }
  }, [])

  // ---- terminal (asciinema)

  /** mountTerminal creates the asciinema player at a point on its own clock,
   *  with a speed and fit. It is the only way to change speed or fit: the
   *  player has no setter for either. */
  const mountTerminal = useCallback((at: number, rate: number, autoPlay: boolean, fit: TermFit = termFit.current) => {
    const c = cast.current
    const el = host.current
    if (!c || !el) return
    // Focus inside the old player (its own keys, F) moves to the new one;
    // it would otherwise fall to the page and the next F would do nothing.
    const focused = el.contains(document.activeElement)
    term.current?.dispose()
    el.innerHTML = ''
    termFit.current = fit
    // Markers in the file appear on the player's timeline; the list below
    // seeks to them. The theme is neutral so it matches the console pages.
    // startAt is recording time.
    const p = AsciinemaPlayer.create({ data: c.text }, el, { fit, theme: 'asciinema', idleTimeLimit: IDLE_LIMIT, autoPlay, speed: rate, startAt: rawTime(c.times, at) })
    // A player made paused is moved to where the old one stopped (on its own
    // clock), so it shows that frame instead of a blank screen, and Play goes
    // on from there with the screen as it was. Its poster option shows the
    // frame too, but Play then clears the screen before going on.
    if (!autoPlay) void p.seek(at)
    p.addEventListener('play', () => setRunning(true))
    p.addEventListener('playing', () => setRunning(true))
    p.addEventListener('pause', () => setRunning(false))
    p.addEventListener('ended', () => setRunning(false))
    term.current = p
    setDuration(0)
    if (focused) el.querySelector<HTMLElement>('.ap-wrapper')?.focus()
  }, [])

  const playTerminal = async (r: Recording) => {
    // Streaming the recording is the audited "view". It goes through the api
    // client like every other call, so a session that has ended reaches the
    // session dialog instead of reading as a broken recording.
    const text = await (await api.download(recordingPath(r.id) + '/stream')).text()
    const parsed = parseCast(text)
    cast.current = { text, times: parsed.times }
    setCommands(parsed.commands)
    mountTerminal(0, speed, true)
  }

  const changeSpeed = (rate: number) => {
    setSpeed(rate)
    const p = term.current
    if (p) mountTerminal(p.getCurrentTime(), rate, running)
  }

  // ---- desktop (guacd stream)

  /** fitDesktop scales the replayed desktop to what the reviewer can see:
   *  never wider than the card, never taller than the viewport below the
   *  player's top edge, letterboxed inside the dark container. The previous
   *  version scaled by width only, so a tall recording ran off the bottom of
   *  the page and only half of it was visible without scrolling. In full
   *  screen the reviewer asked for the whole screen, so a recording smaller
   *  than it is drawn larger; on the page it is never drawn above its size. */
  const fitDesktop = useCallback(() => {
    const playback = desk.current
    const el = host.current
    if (!playback || !el) return
    const display = playback.getDisplay()
    const w = display.getWidth()
    const h = display.getHeight()
    if (w <= 0 || h <= 0) return
    const availW = el.clientWidth
    // The stage centres the picture in full screen, so the host's own top
    // moves with its height; measure the stage instead.
    const availH = full.current && stage.current
      ? stage.current.clientHeight - FULL_RESERVE
      : Math.max(240, window.innerHeight - el.getBoundingClientRect().top - 72)
    const scale = Math.min(full.current ? Infinity : 1, availW / w, availH / h)
    display.scale(scale)
    el.style.height = `${Math.round(h * scale)}px`
  }, [])

  const playDesktop = async (r: Recording) => {
    const Guacamole = (await import('guacamole-common-js')).default
    desk.current?.disconnect()
    if (!host.current) return
    host.current.innerHTML = ''
    // guacamole-common-js's Blob source is broken upstream: it hands parseBlob an
    // uninitialised blob, so playback dies with "undefined is not an object
    // (evaluating 't.size')", and seeking reads that same unset blob. The tunnel
    // source is the working path — it buffers the stream for seeks — so feed it
    // one. The request is same-origin, so the session cookie rides along, and the
    // GET is itself the audited "view".
    const tunnel = new Guacamole.StaticHTTPTunnel(`/api/v1${recordingPath(r.id)}/stream`, false, {})
    const playback = new Guacamole.SessionRecording(tunnel)
    const display = playback.getDisplay()
    host.current.appendChild(display.getElement())
    desk.current = playback
    display.onresize = fitDesktop
    playback.onprogress = (d) => setDuration(d)
    playback.onseek = (p) => setPosition(p)
    playback.onplay = () => setRunning(true)
    playback.onpause = () => setRunning(false)
    playback.onload = () => {
      setLoaded(true)
      fitDesktop()
      // Start only once frames exist. Calling play() straight after connect()
      // does nothing, because the tunnel has not streamed any frame yet, and
      // playback then sits at 00:00 on a blank display.
      playback.play()
    }
    // The tunnel makes its own request, so a refusal reaches the page only as
    // a status text (none at all over HTTP/2), and an expired session would
    // read as a broken recording. Asking for the recording again through the
    // api client sends an expired session to the session dialog; any other
    // failure shows what the tunnel said.
    playback.onerror = (m) => {
      void api.get<Recording>(recordingPath(r.id)).then(
        () => setErr(m ? String(m) : 'The recording could not be loaded.'),
        (e) => setErr(errorMessage(e)),
      )
    }
    playback.connect()
  }

  // Refit the desktop when the window changes, and follow the position while
  // it plays (onseek fires only for seeks, not for ordinary progress).
  useEffect(() => {
    if (phase !== 'playing' || rec?.format !== 'guac') return
    const onResize = () => fitDesktop()
    window.addEventListener('resize', onResize)
    const tick = setInterval(() => {
      const p = desk.current
      if (p && p.isPlaying()) setPosition(p.getPosition())
    }, 250)
    return () => {
      window.removeEventListener('resize', onResize)
      clearInterval(tick)
    }
  }, [phase, rec?.format, fitDesktop])

  // Full screen in and out: the desktop refits once the stage has its new
  // box (the window's resize event comes before that), and the terminal
  // player is made again at the same point with the fit for the space.
  useEffect(() => {
    full.current = isFull
    if (phase !== 'playing') return
    if (rec?.format === 'guac') {
      const frame = requestAnimationFrame(() => fitDesktop())
      return () => cancelAnimationFrame(frame)
    }
    const fit: TermFit = isFull ? 'both' : 'width'
    const p = term.current
    if (!p || termFit.current === fit) return
    mountTerminal(p.getCurrentTime(), speed, running, fit)
  }, [isFull, phase, rec?.format, speed, running, fitDesktop, mountTerminal])

  // F toggles full screen for both players. On the stage it is caught on the
  // way down, before the terminal player sees it: that player's own F would
  // make only its picture full screen, without the controls below it.
  useEffect(() => {
    const el = stage.current
    if (phase !== 'playing' || !el) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'f' || typingInField() || e.metaKey || e.ctrlKey || e.altKey) return
      e.stopPropagation()
      e.preventDefault()
      toggleFull()
    }
    el.addEventListener('keydown', onKey, true)
    return () => el.removeEventListener('keydown', onKey, true)
  }, [phase, toggleFull])

  // ---- transport, both players

  const seekBy = (deltaSeconds: number) => {
    if (rec?.format === 'guac') {
      const p = desk.current
      if (!p) return
      const to = Math.max(0, Math.min(p.getDuration(), p.getPosition() + deltaSeconds * 1000))
      setPosition(to)
      p.seek(to)
      return
    }
    const p = term.current
    if (!p) return
    void p.seek(Math.max(0, p.getCurrentTime() + deltaSeconds))
  }
  const seekTo = (ms: number) => {
    setPosition(ms)
    desk.current?.seek(ms)
  }
  const toggle = () => {
    if (rec?.format === 'guac') {
      const p = desk.current
      if (!p) return
      if (running) p.pause()
      else p.play()
      return
    }
    const p = term.current
    if (p) void (running ? p.pause() : p.play())
  }
  const replay = () => {
    if (rec?.format === 'guac') {
      const p = desk.current
      if (!p) return
      p.seek(0, () => p.play())
      setPosition(0)
      return
    }
    const p = term.current
    if (p) void p.seek(0).then(() => p.play())
  }

  // Keyboard shortcuts for the desktop player. The terminal player ships its
  // own (space, arrows, [ ] for markers, 0-9), so these stay out of its way.
  useEffect(() => {
    if (phase !== 'playing' || rec?.format !== 'guac') return
    const onKey = (e: KeyboardEvent) => {
      if (typingInField() || e.metaKey || e.ctrlKey || e.altKey) return
      switch (e.key) {
        case ' ': toggle(); break
        case 'ArrowLeft': seekBy(-SKIP_SECONDS); break
        case 'ArrowRight': seekBy(SKIP_SECONDS); break
        case 'Home': seekTo(0); break
        case 'End': seekTo(desk.current?.getDuration() ?? 0); break
        case 'f': toggleFull(); break
        default: return
      }
      e.preventDefault()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase, rec?.format, running])

  const play = async () => {
    if (!rec) return
    setPhase('loading')
    setErr('')
    try {
      if (rec.format === 'guac') await playDesktop(rec)
      else await playTerminal(rec)
      setPhase('playing')
      // Bring the player to the top of the viewport so the whole picture,
      // and the transport beneath it, are in view without scrolling.
      setTimeout(() => host.current?.scrollIntoView({ block: 'start', behavior: 'smooth' }), 50)
    } catch (e) {
      setErr(errorMessage(e))
      setPhase('idle')
    }
  }

  const s = rec?.session
  const who = s ? sessionUser(s) : ''
  const where = s ? sessionTarget(s) : ''
  const proto = s?.protocol.toUpperCase() ?? rec?.format
  const title = s ? `${who} on ${where}` : 'Recording'
  const isDesktop = rec?.format === 'guac'

  return (
    <>
      <PageHead title={title} lead={s ? `${proto} session, ${fmtTime(s.started_at)}` : undefined}>
        {rec && !rec.purged_at && (
          <>
            {/* Downloads are recorded views and audit events, like pressing Play. */}
            <a className="btn" href={`/api/v1${recordingPath(rec.id)}/download`} download title="Download the recording file (audited)">Download recording</a>
            {rec.format !== 'guac' && <a className="btn" href={`/api/v1${recordingPath(rec.id)}/transcript`} download title="Download the command lines as text (audited)">Download transcript</a>}
          </>
        )}
        <Link className="btn" to={recordingsPath}>Back to recordings</Link>
      </PageHead>
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      {!rec && !err && <Empty>Loading…</Empty>}
      {rec && (
        <>
          <div className="card">
            <h2>Details</h2>
            <dl className="kv">
              {s && (
                <>
                  <dt>User</dt>
                  <dd><strong>{who}</strong> <span className="mono muted">from {s.client_ip}</span></dd>
                  <dt>Machine</dt>
                  <dd>{where}</dd>
                  <dt>Protocol</dt>
                  <dd>{proto}</dd>
                  <dt>Started</dt>
                  <dd>{fmtTime(s.started_at)}</dd>
                  <dt>Duration</dt>
                  <dd>{fmtDuration(s.started_at, s.ended_at)}</dd>
                  <dt>Ended</dt>
                  <dd>{reasonBadge(s.end_reason)}</dd>
                </>
              )}
              <dt>Size</dt>
              <dd>{fmtBytes(rec.size_bytes)}</dd>
              <dt>Integrity</dt>
              <dd className="mono">{rec.sha256 ? `SHA-256 ${rec.sha256.slice(0, 16)}…` : <span className="muted">not finalised</span>}</dd>
              <dt>Recording</dt>
              <dd className="mono muted">{rec.id}</dd>
            </dl>
          </div>

          <div className="card">
            <h2>{isDesktop ? 'Desktop playback' : 'Terminal playback'}</h2>
            {phase === 'idle' && (
              <>
                <Alert tone="warn">Playing is logged with your name.</Alert>
                <div className="actions">
                  <button id="play" className="btn primary" onClick={() => void play()}>Play</button>
                </div>
              </>
            )}
            {phase === 'loading' && <Empty>Loading recording…</Empty>}
            <div ref={stage} className={'player-stage' + (isFull ? ' is-full' : '')}>
              <div ref={host} className={'player-host' + (isDesktop && phase !== 'idle' ? ' desk-player' : '')} />
              {phase === 'playing' && (
                <>
                  <div className="transport">
                    <IconButton label="Play again from the start" onClick={replay}><TransportIcon kind="replay" /></IconButton>
                    <IconButton label={`Back ${SKIP_SECONDS} seconds`} onClick={() => seekBy(-SKIP_SECONDS)}><TransportIcon kind="back" /></IconButton>
                    <IconButton label={running ? 'Pause' : 'Play'} onClick={toggle} primary><TransportIcon kind={running ? 'pause' : 'play'} /></IconButton>
                    <IconButton label={`Forward ${SKIP_SECONDS} seconds`} onClick={() => seekBy(SKIP_SECONDS)}><TransportIcon kind="forward" /></IconButton>
                    {isDesktop ? (
                      <>
                        <input
                          type="range"
                          min={0}
                          max={Math.max(duration, 1)}
                          value={Math.min(position, duration)}
                          onChange={(e) => seekTo(Number(e.target.value))}
                          aria-label="Playback position"
                        />
                        <span className="t">{fmtSeconds(Math.floor(position / 1000))} / {fmtSeconds(Math.floor(duration / 1000))}</span>
                      </>
                    ) : (
                      <>
                        <span className="grow" />
                        <label className="t" htmlFor="speed">Speed</label>
                        <select id="speed" className="speed" value={speed} onChange={(e) => changeSpeed(Number(e.target.value))} aria-label="Playback speed">
                          {SPEEDS.map((r) => (
                            <option key={r} value={r}>{r}×</option>
                          ))}
                        </select>
                      </>
                    )}
                    <FullscreenButton isFull={isFull} onClick={toggleFull} size={18} />
                  </div>
                  <p className="muted player-hint">
                    {isDesktop
                      ? 'Space play/pause · ← → back/forward 10 s · Home/End · F full screen. Desktop recordings play at real time; guacd streams carry no speed control.'
                      : 'On the player: Space play/pause · ← → 5 s · [ ] previous/next command · 0–9 jump to a tenth · F full screen. Speed applies from the current point.'}
                  </p>
                </>
              )}
            </div>
            {phase === 'playing' && isDesktop && loaded && duration === 0 && <p className="muted" style={{ marginTop: 10 }}>No screen frames recorded.</p>}
          </div>

          {!isDesktop && phase === 'playing' && (
            <div className="card">
              <h2>Commands</h2>
              {commands.length === 0 ? (
                <p className="muted" style={{ margin: 0 }}>No command lines recorded.</p>
              ) : (
                <>
                  <p className="muted" style={{ marginTop: 0 }}>Choose a line to jump to it. Unechoed input is hidden.</p>
                  {/* Seek by marker INDEX, not the command's original timestamp:
                      the player compresses idle gaps (idleTimeLimit), so its
                      timeline no longer matches recording time and a raw-seconds
                      seek lands in the wrong place. The i-th command is the i-th
                      marker the player read from the cast, and it resolves that to
                      the correct spot on the compressed timeline. */}
                  <ol className="commands">
                    {commands.map((c, i) => (
                      <li key={i}>
                        <button type="button" onClick={() => void term.current?.seek({ marker: i })} title="Jump to this point">
                          <span className="t">{fmtSeconds(Math.floor(c.t))}</span>
                          {c.text === '(hidden input)' ? <span className="hidden">{c.text}</span> : <span>{c.text}</span>}
                        </button>
                      </li>
                    ))}
                  </ol>
                </>
              )}
            </div>
          )}
          {isDesktop && <Badge>desktop</Badge>}
        </>
      )}
    </>
  )
}
