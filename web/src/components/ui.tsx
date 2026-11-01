import { Children, cloneElement, isValidElement, useEffect, useId, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactElement, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { useSubmit } from './submit'
import { CloseIcon, StateIcon } from './icons'

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

/**
 * Tabs is a row of tabs that switches what is shown below it. The open tab
 * is announced as selected, not only drawn so; the arrow keys, Home and End
 * move between the tabs, and Tab moves on past them, as assistive technology
 * expects of a tab list. value may be '' when nothing is picked yet.
 */
export function Tabs<K extends string>({ label, tabs, value, onChange }: { label: string; tabs: { key: K; label: ReactNode }[]; value: K | ''; onChange: (key: K) => void }) {
  const buttons = useRef<(HTMLButtonElement | null)[]>([])
  const open = tabs.findIndex((t) => t.key === value)
  const onKeyDown = (e: ReactKeyboardEvent<HTMLButtonElement>, i: number) => {
    const last = tabs.length - 1
    const to = ({ ArrowRight: i === last ? 0 : i + 1, ArrowLeft: i === 0 ? last : i - 1, Home: 0, End: last } as Record<string, number>)[e.key]
    if (to === undefined) return
    e.preventDefault()
    buttons.current[to]?.focus()
    onChange(tabs[to].key)
  }
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {tabs.map((t, i) => (
        <button
          key={t.key}
          ref={(el) => {
            buttons.current[i] = el
          }}
          type="button"
          role="tab"
          aria-selected={i === open}
          tabIndex={i === Math.max(open, 0) ? 0 : -1}
          className={i === open ? 'active' : ''}
          onClick={() => onChange(t.key)}
          onKeyDown={(e) => onKeyDown(e, i)}
        >
          {t.label}
        </button>
      ))}
    </div>
  )
}

export function Badge({ tone, children }: { tone?: 'ok' | 'warn' | 'danger' | 'accent'; children: ReactNode }) {
  return <span className={'badge' + (tone ? ' ' + tone : '')}>{children}</span>
}

/** StatTile is one dashboard number (ADR 0029): a value, a short caption
 *  naming what it counts, and the page that manages it. The caption is a
 *  label, not a sentence; a tone only underlines what it already says, so it
 *  shows only on a non-zero count. "—" while the value is still loading. A
 *  value already written out (a size: "31.2 MB") is shown as it is. */
export function StatTile({ value, label, detail, icon, meter, trend, to, tone }: {
  value: number | string | null
  label: string
  detail?: ReactNode
  /** A decorative identity mark in the corner; the caption carries the meaning. */
  icon?: ReactNode
  /** A ratio against a limit, drawn under the caption. */
  meter?: { fraction: number; tone?: 'warn' | 'danger' }
  /** Counts per calendar day, oldest first and today last, drawn under the caption. */
  trend?: Trend
  to: string
  tone?: 'warn' | 'danger'
}) {
  const pct = meter ? Math.round(Math.max(0, Math.min(1, meter.fraction)) * 100) : 0
  return (
    <Link className={'stat-tile' + (tone && value ? ' ' + tone : '')} to={to}>
      {icon && <span className="ticon">{icon}</span>}
      <div className="value">{value ?? '—'}</div>
      <div className="label">{label}</div>
      {detail && <div className="detail">{detail}</div>}
      {meter && (
        <div className={'meter' + (meter.tone ? ' ' + meter.tone : '')} role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct}>
          <i style={{ width: `${pct}%` }} />
        </div>
      )}
      {trend && trend.values.length > 0 && <Sparkline {...trend} />}
    </Link>
  )
}

export interface Trend {
  /** Days as YYYY-MM-DD, already in the console's zone; values matched by index. */
  days: string[]
  values: number[]
  /** What is counted, singular: "session" reads "3 sessions". */
  noun: string
}

// trendDay names a calendar day the server already cut in the console's
// zone; read at noon UTC and shown in UTC, it is that day wherever the
// browser is.
function trendDay(day: string): string {
  return new Date(day + 'T12:00:00Z').toLocaleDateString(undefined, { weekday: 'short', day: 'numeric', month: 'short', timeZone: 'UTC' })
}

/**
 * Sparkline is a stat tile's last days as columns (2026-10-31): past days
 * in the faint ink, today in the accent, a day with none a stub on the
 * baseline. Hovering a column shows its day and count; the same, with what
 * is counted, is in the link's text for a screen reader, and the tile opens
 * the list behind every count.
 */
function Sparkline({ days, values, noun }: Trend) {
  const max = Math.max(1, ...values)
  const last = values.length - 1
  const day = (i: number) => (i === last ? 'Today so far' : trendDay(days[i]))
  const says = (i: number) => `${day(i)}: ${values[i]} ${values[i] === 1 ? noun : noun + 's'}`
  return (
    <>
      <span className="spark" aria-hidden="true">
        {values.map((v, i) => (
          // The hover says the day and the count alone: the caption already
          // names what is counted, and a short tip stays within the tile.
          <span key={days[i] ?? i} className={'spark-col' + (i === last ? ' now' : '') + (v === 0 ? ' none' : '')} data-tip={`${day(i)}: ${v}`}>
            {/* A day with any counts stands at least an eighth high, so one is not mistaken for none. */}
            <i style={v > 0 ? { height: `${Math.max(12.5, (v / max) * 100)}%` } : undefined} />
          </span>
        ))}
      </span>
      <span className="sr-only">Last {values.length} days: {values.map((_, i) => says(i)).join('; ')}</span>
    </>
  )
}

/**
 * Alert is a notice: what an action did, or what needs attention. Every one
 * has an x that dismisses it (2026-11-01: "Keycloak: 1 listed" stayed until
 * the page was left). With onDismiss the caller clears the notice it holds,
 * so the next one shows; without, the alert hides itself, and a different
 * message (a string) shows again.
 *
 * An alert showing state that an action sets (an error, a "saved", a test's
 * result) passes onDismiss: the same message set again does not render, so a
 * self-hidden alert would stay hidden when a retry fails the same way. Only
 * a fixed warning, or a load error, hides itself.
 */
export function Alert({ tone, children, onDismiss }: { tone?: 'ok' | 'warn' | 'danger'; children: ReactNode; onDismiss?: () => void }) {
  const text = typeof children === 'string' ? children : null
  const [dismissed, setDismissed] = useState<{ text: string | null } | null>(null)
  if (dismissed && (dismissed.text === null || dismissed.text === text)) return null
  return (
    <div className={'alert' + (tone ? ' ' + tone : '')} role={tone === 'danger' ? 'alert' : 'status'}>
      <div className="alert-body">{children}</div>
      <button type="button" className="alert-close" aria-label="Dismiss" title="Dismiss" onClick={() => (onDismiss ? onDismiss() : setDismissed({ text }))}>
        <CloseIcon size={18} />
      </button>
    </div>
  )
}

/** TabLink opens a page in a tab of its own (ADR 0038): a recording or a
 *  live session, so that several can be open at once and the list stays
 *  where it was. Its visible text stays terse; the name says where it goes. */
export function TabLink({ to, label, className, title, children }: { to: string; label: string; className?: string; title?: string; children?: ReactNode }) {
  return (
    <Link to={to} target="_blank" rel="noopener noreferrer" className={className} title={title} aria-label={`${label}, opens in a new tab`}>
      {children ?? label}
    </Link>
  )
}

/** RemoveButton takes a row out of a list being edited (a tag, a group
 *  mapping, a time window): an x large enough to see and hit (2026-11-01;
 *  the "×" glyph was a few pixels wide). */
export function RemoveButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button type="button" className="btn sm ghost remove-btn" aria-label={label} title={label} onClick={onClick}>
      <CloseIcon size={18} />
    </button>
  )
}

// Dialogs nest: a detail dialog opens edit, IAM and confirm dialogs on top of
// itself. Only the topmost one may answer Escape, so each registers on a shared
// stack; the stack also decides when the page behind can scroll again.
const openModals: symbol[] = []
// The page's own overflow, saved when the first dialog opens and put back
// when the last one closes. Each dialog used to save what it found, so one
// opened over another saved the first one's `hidden`; when it was the last
// to close (a delete closing the delete dialog and the detail dialog under
// it in one render) it put `hidden` back and the page never scrolled again
// (the live 1.9.0 console, 2026-10-31).
let pageOverflow = ''

// focusable lists what Tab can reach inside el, in order.
function focusable(el: HTMLElement): HTMLElement[] {
  return Array.from(
    el.querySelectorAll<HTMLElement>('a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'),
  ).filter((n) => !n.closest('[hidden], [inert]'))
}

export function Modal({ title, onClose, children, width }: { title: string; onClose: () => void; children: ReactNode; width?: number }) {
  const me = useRef(Symbol('modal'))
  const box = useRef<HTMLDivElement>(null)
  const titleId = useId()

  // Mount-only: register, lock the page behind the dialog, and move focus into
  // it unless a child already claimed focus (autoFocus on the first field).
  // On unmount, return focus to whatever opened the dialog.
  useEffect(() => {
    const id = me.current
    if (openModals.length === 0) pageOverflow = document.body.style.overflow
    openModals.push(id)
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null
    document.body.style.overflow = 'hidden'
    if (box.current && !box.current.contains(document.activeElement)) box.current.focus()
    return () => {
      const i = openModals.lastIndexOf(id)
      if (i >= 0) openModals.splice(i, 1)
      if (openModals.length === 0) document.body.style.overflow = pageOverflow
      opener?.focus()
    }
  }, [])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (openModals[openModals.length - 1] !== me.current) return
      if (e.key === 'Escape') {
        e.stopPropagation()
        onClose()
        return
      }
      // Tab stays inside the topmost dialog: past its last control it wraps
      // to the first, and back again, so the keyboard never reaches the page
      // behind it, which aria-modal hides from screen readers only.
      if (e.key === 'Tab' && box.current) {
        const items = focusable(box.current)
        if (items.length === 0) {
          e.preventDefault()
          box.current.focus()
          return
        }
        const first = items[0]
        const last = items[items.length - 1]
        const at = document.activeElement
        const inside = at instanceof Node && box.current.contains(at)
        if (e.shiftKey && (at === first || at === box.current || !inside)) {
          e.preventDefault()
          last.focus()
        } else if (!e.shiftKey && (at === last || !inside)) {
          e.preventDefault()
          first.focus()
        }
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
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
  const { busy, err, submit } = useSubmit()
  return (
    <Modal title={title} onClose={onClose}>
      <div>{body}</div>
      {err && <Alert tone="danger">{err}</Alert>}
      <div className="actions">
        <button className="btn" onClick={onClose} disabled={busy}>Cancel</button>
        <button
          className={'btn ' + (danger ? 'danger' : 'primary')}
          disabled={busy}
          onClick={() =>
            void submit(async () => {
              await onConfirm()
              onClose()
            })
          }
        >
          {confirmLabel ?? 'Confirm'}
        </button>
      </div>
    </Modal>
  )
}

/**
 * FormModal is a dialog that holds one form: the error from its last
 * attempt above the fields, and below them Cancel and the submit button,
 * which is held off while the form is busy. Enter submits, as in any form.
 */
export function FormModal({ title, width, err, busy, submitLabel, onSubmit, onClose, children }: {
  title: string
  width?: number
  err: string
  busy: boolean
  submitLabel: string
  onSubmit: () => void
  onClose: () => void
  children: ReactNode
}) {
  return (
    <Modal title={title} onClose={onClose} width={width}>
      {err && <Alert tone="danger">{err}</Alert>}
      <form
        onSubmit={(e) => {
          e.preventDefault()
          onSubmit()
        }}
      >
        {children}
        <div className="actions">
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn primary" disabled={busy}>{submitLabel}</button>
        </div>
      </form>
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
export function Field({ label, hint, info, children }: { label: string; hint?: string; info?: string; children: ReactNode }) {
  const auto = useId()
  const hintId = hint ? auto + '-hint' : undefined
  const parts = Children.toArray(children)
  const at = parts.filter(isControl).length === 1 ? parts.findIndex(isControl) : -1
  const control = at >= 0 ? (parts[at] as ReactElement<ControlProps>) : null
  if (!control) {
    return (
      <div className="field" role="group" aria-labelledby={auto + '-label'} aria-describedby={hintId}>
        {info ? (
          <span className="field-head">
            <label id={auto + '-label'}>{label}</label>
            <StateIcon state="info" label={info} />
          </span>
        ) : (
          <label id={auto + '-label'}>{label}</label>
        )}
        {children}
        {hint && <span className="hint" id={hintId}>{hint}</span>}
      </div>
    )
  }
  const id = control.props.id ?? auto
  const describedBy = [control.props['aria-describedby'], hintId].filter(Boolean).join(' ') || undefined
  return (
    <div className="field">
      {info ? (
        <span className="field-head">
          <label htmlFor={id}>{label}</label>
          <StateIcon state="info" label={info} />
        </span>
      ) : (
        <label htmlFor={id}>{label}</label>
      )}
      {parts.map((c, i) => (i === at ? cloneElement(control, { id, 'aria-describedby': describedBy }) : c))}
      {hint && <span className="hint" id={hintId}>{hint}</span>}
    </div>
  )
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>
}

/** LoadMore is the button under a list read a page at a time; it is shown only while there is a next page. */
export function LoadMore({ next, busy, onMore }: { next: string; busy?: boolean; onMore: () => void }) {
  if (!next) return null
  return (
    <div className="actions" style={{ padding: 12 }}>
      <button className="btn sm" disabled={busy} onClick={onMore}>Load more</button>
    </div>
  )
}

export function Tags({ tags }: { tags?: Record<string, string> }) {
  const entries = Object.entries(tags ?? {})
  if (entries.length === 0) return <span className="muted">none</span>
  return (
    <>
      {entries.map(([k, v]) => (
        <span className="tag" key={k}>
          <span className="tag-k">{k}</span>
          {v && <><span className="sr-only">: </span><span className="tag-v">{v}</span></>}
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
