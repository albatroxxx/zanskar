import { useEffect, useState, type ReactNode } from 'react'

export function PageHead({ title, lead, children }: { title: string; lead?: string; children?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {lead && <p>{lead}</p>}
      </div>
      {children && <div className="actions">{children}</div>}
    </div>
  )
}

export function Badge({ tone, children }: { tone?: 'ok' | 'warn' | 'danger' | 'accent'; children: ReactNode }) {
  return <span className={'badge' + (tone ? ' ' + tone : '')}>{children}</span>
}

export function Alert({ tone, children }: { tone?: 'ok' | 'warn' | 'danger'; children: ReactNode }) {
  return <div className={'alert' + (tone ? ' ' + tone : '')} role={tone === 'danger' ? 'alert' : 'status'}>{children}</div>
}

export function Modal({ title, onClose, children, width }: { title: string; onClose: () => void; children: ReactNode; width?: number }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title} style={width ? { width: `min(${width}px, 100%)` } : undefined}>
        <h2>{title}</h2>
        {children}
      </div>
    </div>
  )
}

export function Confirm({ title, body, confirmLabel, danger, onConfirm, onClose }: { title: string; body: ReactNode; confirmLabel?: string; danger?: boolean; onConfirm: () => Promise<void> | void; onClose: () => void }) {
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  return (
    <Modal title={title} onClose={onClose}>
      <div>{body}</div>
      {err && <Alert tone="danger">{err}</Alert>}
      <div className="actions">
        <button className="btn" onClick={onClose} disabled={busy}>Cancel</button>
        <button
          className={'btn ' + (danger ? 'danger' : 'primary')}
          disabled={busy}
          onClick={async () => {
            setBusy(true)
            setErr('')
            try {
              await onConfirm()
              onClose()
            } catch (e) {
              setErr(e instanceof Error ? e.message : String(e))
            } finally {
              setBusy(false)
            }
          }}
        >
          {confirmLabel ?? 'Confirm'}
        </button>
      </div>
    </Modal>
  )
}

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <div className="field">
      <label>{label}</label>
      {children}
      {hint && <span className="hint">{hint}</span>}
    </div>
  )
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>
}

export function Tags({ tags }: { tags?: Record<string, string> }) {
  const entries = Object.entries(tags ?? {})
  if (entries.length === 0) return <span className="muted">none</span>
  return (
    <>
      {entries.map(([k, v]) => (
        <span className="tag" key={k}>
          {k}={v}
        </span>
      ))}
    </>
  )
}

export function reasonBadge(reason?: string) {
  if (!reason) return <Badge tone="accent">live</Badge>
  const tone = reason === 'user_exit' ? undefined : reason === 'target_lost' || reason === 'error' ? 'danger' : 'warn'
  return <Badge tone={tone}>{reason.replace(/_/g, ' ')}</Badge>
}
