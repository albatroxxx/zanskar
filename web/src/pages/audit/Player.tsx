import { useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import * as AsciinemaPlayer from 'asciinema-player'
import 'asciinema-player/dist/bundle/asciinema-player.css'
import { api, errorMessage } from '../../api/client'
import { fmtBytes, fmtDuration, fmtSeconds, fmtTime, shortId } from '../../api/format'
import type { Recording } from '../../api/types'
import { Alert, Badge, Empty, PageHead, reasonBadge } from '../../components/ui'

type PlayerHandle = ReturnType<typeof AsciinemaPlayer.create>
type GuacModule = typeof import('guacamole-common-js').default
type SessionRecording = InstanceType<GuacModule['SessionRecording']>

/** A command the user submitted, taken from the recording's marker events. */
interface Command { t: number; text: string }

/** parseCommands reads asciicast v2 marker events ([time, "m", label]). The
 *  gateway writes one per submitted command line; "(hidden input)" marks text
 *  the remote did not echo, such as a password, which is never recorded. */
function parseCommands(cast: string): Command[] {
  const out: Command[] = []
  for (const line of cast.split('\n')) {
    if (!line.startsWith('[')) continue
    try {
      const ev = JSON.parse(line) as [number, string, string]
      if (ev[1] === 'm' && typeof ev[2] === 'string') out.push({ t: ev[0], text: ev[2] })
    } catch {
      /* not an event line */
    }
  }
  return out
}

async function fetchStream(id: string): Promise<Response> {
  // Streaming the recording is the audited "view"; GET needs no CSRF token.
  const res = await fetch(`/api/v1/recordings/${id}/stream`, { credentials: 'same-origin' })
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`
    try {
      const body = (await res.json()) as { message?: string }
      if (body.message) msg = body.message
    } catch {
      /* non-JSON error body */
    }
    throw new Error(msg)
  }
  return res
}

export function Player() {
  const { id = '' } = useParams()
  const [rec, setRec] = useState<Recording | null>(null)
  const [err, setErr] = useState('')
  const [phase, setPhase] = useState<'idle' | 'loading' | 'playing'>('idle')
  const [commands, setCommands] = useState<Command[]>([])
  const host = useRef<HTMLDivElement>(null)
  const term = useRef<PlayerHandle | null>(null)
  const desk = useRef<SessionRecording | null>(null)
  // desktop transport state
  const [duration, setDuration] = useState(0)
  const [position, setPosition] = useState(0)
  const [running, setRunning] = useState(false)
  const [loaded, setLoaded] = useState(false)

  useEffect(() => {
    api
      .get<Recording>(`/recordings/${id}`)
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

  const playTerminal = async (r: Recording) => {
    const text = await (await fetchStream(r.id)).text()
    setCommands(parseCommands(text))
    term.current?.dispose()
    if (!host.current) return
    host.current.innerHTML = ''
    // Markers in the file appear on the player's timeline; the list below
    // seeks to them. The theme is neutral so it matches the console pages.
    term.current = AsciinemaPlayer.create({ data: text }, host.current, { fit: 'width', theme: 'asciinema', idleTimeLimit: 2, autoPlay: true })
  }

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
    const tunnel = new Guacamole.StaticHTTPTunnel(`/api/v1/recordings/${r.id}/stream`, false, {})
    const playback = new Guacamole.SessionRecording(tunnel)
    const display = playback.getDisplay()
    const el = display.getElement()
    host.current.appendChild(el)
    const fit = () => {
      const w = display.getWidth()
      const avail = host.current?.clientWidth ?? w
      if (w > 0 && avail > 0) display.scale(Math.min(1, avail / w))
    }
    display.onresize = fit
    playback.onprogress = (d) => setDuration(d)
    playback.onseek = (p) => setPosition(p)
    playback.onplay = () => setRunning(true)
    playback.onpause = () => setRunning(false)
    playback.onload = () => {
      setLoaded(true)
      fit()
      // Start only once frames exist. Calling play() straight after connect()
      // does nothing, because the tunnel has not streamed any frame yet, and
      // playback then sits at 00:00 on a blank display.
      playback.play()
    }
    playback.onerror = (m) => setErr(String(m))
    playback.connect()
    desk.current = playback
  }

  const play = async () => {
    if (!rec) return
    setPhase('loading')
    setErr('')
    try {
      if (rec.format === 'guac') await playDesktop(rec)
      else await playTerminal(rec)
      setPhase('playing')
    } catch (e) {
      setErr(errorMessage(e))
      setPhase('idle')
    }
  }

  const s = rec?.session
  const who = s?.username ?? (s ? shortId(s.user_id) + '…' : '')
  const where = s?.target_name ?? (s?.asg_instance_id ? shortId(s.asg_instance_id) + '…' : '')
  const proto = s?.protocol.toUpperCase() ?? rec?.format
  const title = s ? `${who} on ${where}` : 'Recording'

  return (
    <>
      <PageHead title={title} lead={s ? `${proto} session, ${fmtTime(s.started_at)}` : undefined}>
        <Link className="btn" to="/audit/recordings">Back to recordings</Link>
      </PageHead>
      {err && <Alert tone="danger">{err}</Alert>}
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
            <h2>{rec.format === 'guac' ? 'Desktop playback' : 'Terminal playback'}</h2>
            {phase === 'idle' && (
              <>
                <Alert tone="warn">Pressing Play records a view: your name, this recording and its session are written to the audit log.</Alert>
                <div className="actions">
                  <button id="play" className="btn primary" onClick={() => void play()}>Play</button>
                </div>
              </>
            )}
            {phase === 'loading' && <Empty>Loading recording…</Empty>}
            <div ref={host} className={'player-host' + (rec.format === 'guac' && phase !== 'idle' ? ' desk-player' : '')} />
            {rec.format === 'guac' && phase === 'playing' && (
              <>
                <div className="transport">
                  <button className="btn sm" onClick={() => (running ? desk.current?.pause() : desk.current?.play())}>{running ? 'Pause' : 'Play'}</button>
                  <input
                    type="range"
                    min={0}
                    max={Math.max(duration, 1)}
                    value={Math.min(position, duration)}
                    onChange={(e) => {
                      const p = Number(e.target.value)
                      setPosition(p)
                      desk.current?.seek(p)
                    }}
                    aria-label="Playback position"
                  />
                  <span className="t">{fmtSeconds(Math.floor(position / 1000))} / {fmtSeconds(Math.floor(duration / 1000))}</span>
                </div>
                {loaded && duration === 0 && <p className="muted" style={{ marginTop: 10 }}>This recording holds no screen frames: the desktop session ended before anything was drawn.</p>}
              </>
            )}
          </div>

          {rec.format !== 'guac' && phase === 'playing' && (
            <div className="card">
              <h2>Commands</h2>
              {commands.length === 0 ? (
                <p className="muted" style={{ margin: 0 }}>No command lines were recorded in this session. Recordings made before command capture was added, or sessions where nothing was typed, show none.</p>
              ) : (
                <>
                  <p className="muted" style={{ marginTop: 0 }}>Each line the user submitted, in order. Click one to jump the playback to it. Input the remote did not echo, such as a password, is marked hidden and was never stored.</p>
                  <ol className="commands">
                    {commands.map((c, i) => (
                      <li key={i} onClick={() => term.current?.seek(c.t)} title="Jump to this point">
                        <span className="t">{fmtSeconds(Math.floor(c.t))}</span>
                        {c.text === '(hidden input)' ? <span className="hidden">{c.text}</span> : <span>{c.text}</span>}
                      </li>
                    ))}
                  </ol>
                </>
              )}
            </div>
          )}
          {rec.format === 'guac' && <Badge>desktop</Badge>}
        </>
      )}
    </>
  )
}
