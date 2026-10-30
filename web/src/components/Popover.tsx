import { useEffect, useId, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from 'react'

/**
 * CornerPopover is a panel that drops from a corner button and stays
 * attached to it, as the AWS consoles' Actions menus do (2026-10-30: the
 * gear and the bell opened dialogs in the middle of the page). It closes on
 * Escape, on a click outside, and when focus leaves it, and Escape gives
 * focus back to the button. kind 'menu' holds MenuItems moved through with
 * the arrow keys; kind 'dialog' holds a small panel of its own content.
 */
export function CornerPopover({ label, icon, dot, kind, children, width }: {
  /** The button's name, and the panel's. */
  label: string
  icon: ReactNode
  /** A dot on the button: something waits behind it. */
  dot?: boolean
  kind: 'menu' | 'dialog'
  /** The panel's content; close shuts the panel. */
  children: (close: () => void) => ReactNode
  width?: number
}) {
  const [open, setOpen] = useState(false)
  const wrap = useRef<HTMLDivElement>(null)
  const panel = useRef<HTMLDivElement>(null)
  const id = useId()
  const buttonId = useId()

  useEffect(() => {
    const el = wrap.current
    if (!open || !el) return
    const outside = (e: PointerEvent) => {
      if (!el.contains(e.target as Node)) setOpen(false)
    }
    // Focus moved somewhere outside the button and its panel (Tab past the
    // end): close quietly, without pulling focus back.
    const left = (e: FocusEvent) => {
      if (e.relatedTarget && !el.contains(e.relatedTarget as Node)) setOpen(false)
    }
    // Escape inside the panel closes it and returns to the button; the menu
    // handles its own keys, the dialog panel has only this one.
    const escape = (e: KeyboardEvent) => {
      if (e.key !== 'Escape' || !el.contains(document.activeElement)) return
      e.stopPropagation()
      setOpen(false)
      document.getElementById(buttonId)?.focus()
    }
    document.addEventListener('pointerdown', outside)
    document.addEventListener('keydown', escape)
    el.addEventListener('focusout', left)
    if (panel.current) {
      const first = kind === 'menu' ? menuItems(panel.current)[0] : undefined
      ;(first ?? panel.current).focus()
    }
    return () => {
      document.removeEventListener('pointerdown', outside)
      document.removeEventListener('keydown', escape)
      el.removeEventListener('focusout', left)
    }
  }, [open, kind, buttonId])

  // By id, not the ref: close is handed to the panel's content during render.
  const close = () => {
    setOpen(false)
    document.getElementById(buttonId)?.focus()
  }
  const onKeyDown = (e: ReactKeyboardEvent<HTMLDivElement>) => {
    if (!panel.current) return
    const list = menuItems(panel.current)
    if (list.length === 0) return
    const at = list.indexOf(document.activeElement as HTMLElement)
    const next = { ArrowDown: (at + 1) % list.length, ArrowUp: (at - 1 + list.length) % list.length, Home: 0, End: list.length - 1 }[e.key]
    if (next !== undefined) {
      e.preventDefault()
      list[next].focus()
    }
  }
  return (
    <div className="corner-pop" ref={wrap}>
      <button
        id={buttonId}
        type="button"
        className={'corner-btn' + (open ? ' on' : '')}
        aria-label={label}
        title={label}
        aria-haspopup={kind}
        aria-expanded={open}
        aria-controls={open ? id : undefined}
        onClick={() => setOpen((o) => !o)}
      >
        {icon}
        {dot && <span className="corner-dot" aria-hidden="true" />}
      </button>
      {open && kind === 'menu' && (
        <div id={id} ref={panel} className="corner-panel menu" role="menu" aria-label={label} tabIndex={-1} style={width ? { width } : undefined} onKeyDown={onKeyDown}>
          {children(close)}
        </div>
      )}
      {open && kind === 'dialog' && (
        <div id={id} ref={panel} className="corner-panel dialog" role="dialog" aria-label={label} tabIndex={-1} style={width ? { width } : undefined}>
          {children(close)}
        </div>
      )}
    </div>
  )
}

function menuItems(el: HTMLElement): HTMLElement[] {
  return Array.from(el.querySelectorAll<HTMLElement>('[role^="menuitem"]:not([aria-disabled="true"])'))
}

/** MenuItem is one choice in a CornerPopover menu; checked makes it a radio choice. */
export function MenuItem({ children, onSelect, disabled, danger, checked }: {
  children: ReactNode
  onSelect: () => void
  disabled?: boolean
  danger?: boolean
  checked?: boolean
}) {
  return (
    <button
      type="button"
      role={checked === undefined ? 'menuitem' : 'menuitemradio'}
      aria-checked={checked}
      aria-disabled={disabled || undefined}
      tabIndex={-1}
      className={'menu-item' + (danger ? ' danger' : '')}
      onClick={() => {
        if (!disabled) onSelect()
      }}
    >
      {checked !== undefined && (
        <span className="menu-check" aria-hidden="true">
          {checked ? '✓' : ''}
        </span>
      )}
      {children}
    </button>
  )
}

/** MenuSeparator sets a destructive choice apart. */
export function MenuSeparator() {
  return <hr className="menu-sep" />
}
