import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from 'react'
import { browserZone, browserZones, canonicalZone, describeZone, searchZones, zoneOptions, zoneText, type ZoneOption } from '../api/timeZones'

/**
 * TimeZonePicker chooses a time zone from every one the browser knows
 * (Settings › Display, 2026-10-31). Closed, the field reads the chosen zone
 * in words; opened, by a click, the arrow or typing, it lists them all,
 * offset first, west to east, and what is typed searches city, region,
 * name, offset and older names. A <datalist> did this before and offered
 * only the entries matching the text already in the field, which was the
 * saved zone, so it looked empty.
 *
 * It is a combobox with a listbox (ARIA 1.2): the arrow keys move through
 * the list, Enter takes the highlighted zone, Escape and Tab close it
 * leaving the choice as it was.
 */
export function TimeZonePicker({ id, value, onChange }: { id: string; value: string; onChange: (zone: string) => void }) {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const wrap = useRef<HTMLDivElement>(null)
  const input = useRef<HTMLInputElement>(null)
  const list = useRef<HTMLDivElement>(null)
  const listId = useId()
  const current = canonicalZone(value)
  // Closed, only the chosen zone is described: the full list is built on
  // first opening, not with the page.
  const chosen = useMemo(() => (value ? describeZone(value) : null), [value])
  const all = useMemo(() => (open ? zoneOptions(value) : []), [open, value])
  const shown = useMemo(() => searchZones(all, query), [all, query])
  const here = browserZone()

  const show = () => {
    setQuery('')
    setActive(Math.max(0, zoneOptions(value).findIndex((o) => o.id === current)))
    setOpen(true)
  }
  const close = () => {
    setOpen(false)
    setQuery('')
  }
  const choose = (o: ZoneOption) => {
    onChange(o.id)
    close()
  }

  useEffect(() => {
    const el = wrap.current
    if (!open || !el) return
    const outside = (e: PointerEvent) => {
      if (!el.contains(e.target as Node)) close()
    }
    // Focus moved past the field and its list (Tab): close, choice unchanged.
    const left = (e: FocusEvent) => {
      if (e.relatedTarget && !el.contains(e.relatedTarget as Node)) close()
    }
    document.addEventListener('pointerdown', outside)
    el.addEventListener('focusout', left)
    return () => {
      document.removeEventListener('pointerdown', outside)
      el.removeEventListener('focusout', left)
    }
  }, [open])

  // The highlighted zone stays in view as the arrow keys move it.
  useEffect(() => {
    if (open) list.current?.querySelector<HTMLElement>(`[data-index="${active}"]`)?.scrollIntoView?.({ block: 'nearest' })
  }, [open, active])

  const onKey = (e: ReactKeyboardEvent<HTMLInputElement>) => {
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault()
        if (!open) show()
        else setActive((i) => Math.min(i + 1, shown.length - 1))
        break
      case 'ArrowUp':
        e.preventDefault()
        if (open) setActive((i) => Math.max(i - 1, 0))
        break
      case 'PageDown':
        if (open) {
          e.preventDefault()
          setActive((i) => Math.min(i + 10, shown.length - 1))
        }
        break
      case 'PageUp':
        if (open) {
          e.preventDefault()
          setActive((i) => Math.max(i - 10, 0))
        }
        break
      case 'Enter':
        if (open) {
          e.preventDefault()
          if (shown[active]) choose(shown[active])
        }
        break
      case 'Escape':
        if (open) {
          e.preventDefault()
          e.stopPropagation()
          close()
        }
        break
      case 'Tab':
        if (open) close()
        break
    }
  }

  const optionId = (i: number) => `${listId}-${i}`
  const noList = open && browserZones().length === 0

  return (
    <div className="tzpick" ref={wrap}>
      <input
        id={id}
        ref={input}
        role="combobox"
        aria-expanded={open}
        aria-controls={listId}
        aria-autocomplete="list"
        aria-activedescendant={open && shown[active] ? optionId(active) : undefined}
        value={open ? query : chosen ? zoneText(chosen) : value}
        placeholder={open ? 'Search a city, region, zone name or offset' : 'Choose a time zone'}
        onChange={(e) => {
          setQuery(e.target.value)
          setActive(0)
          if (!open) setOpen(true)
        }}
        onClick={() => {
          if (!open) show()
        }}
        // Typing into the closed field replaces the zone's words with a
        // search, rather than adding to them.
        onFocus={(e) => e.target.select()}
        onKeyDown={onKey}
        autoComplete="off"
        spellCheck={false}
      />
      <button
        type="button"
        className="tzpick-toggle"
        tabIndex={-1}
        aria-label={open ? 'Hide the time zones' : 'Show every time zone'}
        onMouseDown={(e) => {
          e.preventDefault()
          if (open) close()
          else show()
          input.current?.focus()
        }}
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <polyline points={open ? '6 15 12 9 18 15' : '6 9 12 15 18 9'} />
        </svg>
      </button>
      {open && (
        <div className="tzpick-panel">
          <div className="tzpick-list" role="listbox" id={listId} aria-label="Time zones" ref={list}>
            {shown.map((o, i) => (
              <div
                key={o.id}
                id={optionId(i)}
                data-index={i}
                role="option"
                tabIndex={-1}
                aria-selected={o.id === current}
                className={'tzpick-opt' + (i === active ? ' active' : '')}
                onMouseDown={(e) => {
                  e.preventDefault()
                  choose(o)
                }}
                onMouseMove={() => {
                  if (i !== active) setActive(i)
                }}
              >
                <span className="tz-off">{o.offset}</span>
                <span className="tz-city">
                  {o.city}
                  {o.region && <span className="muted"> · {o.region}</span>}
                  {o.id === here && <span className="tz-here">this browser</span>}
                </span>
                <span className="tz-name">{o.name}</span>
              </div>
            ))}
          </div>
          {shown.length === 0 && <p className="tzpick-note">No zone matches “{query}”.</p>}
          {noList && <p className="tzpick-note">This browser offers no list of zones: UTC, its own and the saved one are shown.</p>}
        </div>
      )}
    </div>
  )
}
