import { Children, cloneElement, isValidElement, useEffect, useId, useRef, useState, type ReactElement, type ReactNode } from 'react'

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

// Dialogs nest: a detail dialog opens edit, IAM and confirm dialogs on top of
// itself. Only the topmost one may answer Escape, so each registers on a shared
// stack; the stack also decides when the page behind can scroll again.
const openModals: symbol[] = []

export function Modal({ title, onClose, children, width }: { title: string; onClose: () => void; children: ReactNode; width?: number }) {
  const me = useRef(Symbol('modal'))
  const box = useRef<HTMLDivElement>(null)
  const titleId = useId()

  // Mount-only: register, lock the page behind the dialog, and move focus into
  // it unless a child already claimed focus (autoFocus on the first field).
  // On unmount, return focus to whatever opened the dialog.
  useEffect(() => {
    const id = me.current
    openModals.push(id)
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const prevOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    if (box.current && !box.current.contains(document.activeElement)) box.current.focus()
    return () => {
      const i = openModals.lastIndexOf(id)
      if (i >= 0) openModals.splice(i, 1)
      if (openModals.length === 0) document.body.style.overflow = prevOverflow
      opener?.focus()
    }
  }, [])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && openModals[openModals.length - 1] === me.current) {
        e.stopPropagation()
        onClose()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div ref={box} className="modal" role="dialog" aria-modal="true" aria-labelledby={titleId} tabIndex={-1} style={width ? { width: `min(${width}px, 100%)` } : undefined}>
        <div className="modal-head">
          <h2 id={titleId}>{title}</h2>
        </div>
        <div className="modal-body">{children}</div>
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

type ControlProps = { id?: string; 'aria-describedby'?: string }

// A field's one input, select or textarea, or a component given an id that it
// puts on its own control (CredentialSelect, say).
function isControl(c: ReactNode): c is ReactElement<ControlProps> {
  return isValidElement<ControlProps>(c) && (c.type === 'input' || c.type === 'select' || c.type === 'textarea' || typeof c.props.id === 'string')
}

// The label names its control, so a screen reader reads it and a click on it
// focuses the box; the hint is read as the control's description. A field
// holding a group (checkboxes, buttons) is a named group instead.
export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  const auto = useId()
  const hintId = hint ? auto + '-hint' : undefined
  const parts = Children.toArray(children)
  const at = parts.filter(isControl).length === 1 ? parts.findIndex(isControl) : -1
  const control = at >= 0 ? (parts[at] as ReactElement<ControlProps>) : null
  if (!control) {
    return (
      <div className="field" role="group" aria-labelledby={auto + '-label'} aria-describedby={hintId}>
        <label id={auto + '-label'}>{label}</label>
        {children}
        {hint && <span className="hint" id={hintId}>{hint}</span>}
      </div>
    )
  }
  const id = control.props.id ?? auto
  const describedBy = [control.props['aria-describedby'], hintId].filter(Boolean).join(' ') || undefined
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {parts.map((c, i) => (i === at ? cloneElement(control, { id, 'aria-describedby': describedBy }) : c))}
      {hint && <span className="hint" id={hintId}>{hint}</span>}
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
