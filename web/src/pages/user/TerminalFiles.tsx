import { useCallback, useEffect, useRef, useState } from 'react'
import { api, errorMessage, query } from '../../api/client'
import { fmtBytes } from '../../api/format'

interface Entry { name: string; path: string; dir: boolean; size: number; mode: string; mtime: number }

/**
 * TerminalFiles is the SSH session's file browser (ADR 0016). Unlike the
 * desktop drive (guacd redirection), it talks to the session's SFTP endpoints
 * over HTTP — list, download and upload against the target's own filesystem,
 * bounded by what the SSH account may read and write. Every transfer is
 * audited server-side; contents are not recorded.
 */
export function TerminalFiles({ sessionId }: { sessionId: string }) {
  const [cwd, setCwd] = useState('')
  const [entries, setEntries] = useState<Entry[] | null>(null)
  const [status, setStatus] = useState<{ text: string; err?: boolean } | null>(null)
  const [busy, setBusy] = useState(false)
  const fileInput = useRef<HTMLInputElement>(null)

  const list = useCallback(async (dir: string) => {
    setEntries(null)
    setStatus(null)
    try {
      const res = await api.get<{ path: string; entries: Entry[] }>(`/sessions/${sessionId}/files${query({ path: dir })}`)
      setCwd(res.path)
      setEntries(res.entries ?? [])
    } catch (e) {
      setStatus({ text: errorMessage(e), err: true })
      setEntries([])
    }
  }, [sessionId])

  // Empty path lets the server start at the login user's home directory.
  useEffect(() => {
    const t = setTimeout(() => void list(''), 0)
    return () => clearTimeout(t)
  }, [list])

  const parent = cwd && cwd !== '/' ? cwd.replace(/\/[^/]+\/?$/, '') || '/' : null

  const download = async (e: Entry) => {
    setStatus({ text: `downloading ${e.name}…` })
    try {
      const blob = await api.download(`/sessions/${sessionId}/files/content?path=${encodeURIComponent(e.path)}`)
      const a = document.createElement('a')
      a.href = URL.createObjectURL(blob)
      a.download = e.name
      a.click()
      setTimeout(() => URL.revokeObjectURL(a.href), 10_000)
      setStatus({ text: `downloaded ${e.name} (${fmtBytes(blob.size)})` })
    } catch (err) {
      setStatus({ text: errorMessage(err), err: true })
    }
  }

  const upload = async (file: File) => {
    setBusy(true)
    setStatus({ text: `uploading ${file.name}…` })
    const dest = (cwd === '/' ? '' : cwd) + '/' + file.name
    try {
      const res = await api.upload<{ bytes: number }>(`/sessions/${sessionId}/files/content?path=${encodeURIComponent(dest)}`, file, file.type || 'application/octet-stream')
      setStatus({ text: `uploaded ${file.name} (${fmtBytes(res.bytes)})` })
      await list(cwd)
    } catch (err) {
      setStatus({ text: errorMessage(err), err: true })
    } finally {
      setBusy(false)
    }
  }

  return (
    <aside className="files-panel" aria-label="Session files">
      <header>
        <span>Files</span>
        <span className="grow" />
        <button className="btn sm" title="Refresh" aria-label="Refresh" disabled={!cwd || entries === null} onClick={() => void list(cwd)}>↻</button>
        <input ref={fileInput} type="file" hidden onChange={(e) => { const f = e.target.files?.[0]; if (f) void upload(f); e.target.value = '' }} />
        <button className="btn sm" disabled={busy || !cwd} onClick={() => fileInput.current?.click()}>Upload</button>
      </header>
      <div className="list">
        <div className="entry dir">{cwd || '…'}</div>
        {parent !== null && <div className="entry dir" onClick={() => void list(parent)}>..</div>}
        {entries === null && <div className="hint">Loading…</div>}
        {entries?.length === 0 && <div className="hint">Empty.</div>}
        {entries?.map((e) => (
          <div
            key={e.path}
            className={'entry' + (e.dir ? ' dir' : '')}
            title={e.dir ? 'open folder' : 'download'}
            onClick={() => { if (e.dir) void list(e.path); else void download(e) }}
          >
            <span>{e.dir ? '📁' : '📄'}</span>
            <span>{e.name}</span>
            {!e.dir && <span className="size">{fmtBytes(e.size)}</span>}
          </div>
        ))}
      </div>
      <div className={'status' + (status?.err ? ' err' : '')}>{status?.text}</div>
    </aside>
  )
}
