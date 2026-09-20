import { useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import * as AsciinemaPlayer from 'asciinema-player'
import 'asciinema-player/dist/bundle/asciinema-player.css'
import { api, errorMessage } from '../../api/client'
import { fmtBytes, fmtTime } from '../../api/format'
import type { Recording } from '../../api/types'
import { Alert, Badge, Empty, PageHead } from '../../components/ui'

type PlayerHandle = ReturnType<typeof AsciinemaPlayer.create>

export function Player() {
  const { id = '' } = useParams()
  const [rec, setRec] = useState<Recording | null>(null)
  const [err, setErr] = useState('')
  const [playing, setPlaying] = useState(false)
  const [loading, setLoading] = useState(false)
  const host = useRef<HTMLDivElement>(null)
  const player = useRef<PlayerHandle | null>(null)

  useEffect(() => {
    api
      .get<Recording>(`/recordings/${id}`)
      .then(setRec)
      .catch((e) => setErr(errorMessage(e)))
  }, [id])

  useEffect(() => {
    return () => {
      player.current?.dispose()
      player.current = null
    }
  }, [])

  const play = async () => {
    if (!rec || !host.current) return
    setLoading(true)
    setErr('')
    try {
      // Streaming the recording is the audited "view"; GET needs no CSRF token.
      const res = await fetch(`/api/v1/recordings/${rec.id}/stream`, { credentials: 'same-origin', headers: { Accept: 'application/x-asciicast' } })
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
      const text = await res.text()
      player.current?.dispose()
      host.current.innerHTML = ''
      player.current = AsciinemaPlayer.create({ data: text }, host.current, { fit: 'width', theme: 'monokai', idleTimeLimit: 2, autoPlay: true })
      setPlaying(true)
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <PageHead title="Recording" lead={rec ? `Session ${rec.session_id}` : undefined}>
        <Link className="btn" to="/audit/recordings">Back to recordings</Link>
      </PageHead>
      {err && <Alert tone="danger">{err}</Alert>}
      {!rec && !err && <Empty>Loading…</Empty>}
      {rec && (
        <>
          <div className="card">
            <h2>Details</h2>
            <dl className="kv">
              <dt>Recording</dt>
              <dd className="mono">{rec.id}</dd>
              <dt>Session</dt>
              <dd className="mono">{rec.session_id}</dd>
              <dt>Format</dt>
              <dd>
                <Badge>{rec.format}</Badge>
              </dd>
              <dt>Size</dt>
              <dd>{fmtBytes(rec.size_bytes)}</dd>
              <dt>SHA-256</dt>
              <dd className="mono">{rec.sha256 || <span className="muted">not finalised</span>}</dd>
              <dt>Started</dt>
              <dd>{fmtTime(rec.started_at)}</dd>
              <dt>Finished</dt>
              <dd>{rec.finished_at ? fmtTime(rec.finished_at) : <span className="muted">still recording</span>}</dd>
            </dl>
          </div>
          <div className="card">
            <h2>Playback</h2>
            {rec.format === 'guac' ? (
              <Empty>Desktop recordings play in Phase 2.</Empty>
            ) : (
              <>
                {!playing && (
                  <>
                    <Alert tone="warn">Pressing Play records a view: your name, this recording and its session are written to the audit log.</Alert>
                    <div className="actions">
                      <button id="play" className="btn primary" disabled={loading} onClick={() => void play()}>
                        {loading ? 'Loading…' : 'Play'}
                      </button>
                    </div>
                  </>
                )}
                <div ref={host} style={{ marginTop: playing ? 0 : 12 }} />
              </>
            )}
          </div>
        </>
      )}
    </>
  )
}
