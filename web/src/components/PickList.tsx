import { useState, type ReactNode } from 'react'

export interface PickOption {
  id: string
  label: string
  /** Beside the label, in a box of its own so it does not read as part of
   * the name: a display name, an OS, an engine, a member count. */
  detail?: string
  /** What the detail is, on hover: "Display name". */
  detailTitle?: string
  /** Disabled, or no longer found: shown, and removable, but never picked by Select all. */
  inactive?: boolean
  /** Why this row cannot be picked at all; it shows greyed with the reason. */
  locked?: string
}

/**
 * PickList picks many from a list: a search box over a checklist, the
 * chosen ones first. A chosen row may grow controls of its own (a target's
 * protocol chips). Groups, users and targets in the policy editor share it.
 */
export function PickList({ label, options, selected, onToggle, onSelect, extra, empty, idPrefix }: {
  /** What is picked, plural, for the search box and the empty line: "groups". */
  label: string
  options: PickOption[]
  selected: string[]
  onToggle: (id: string) => void
  /**
   * Picks or drops many at once, for Select all (2026-10-30: with 20 hosts
   * each was ticked by hand). It acts on the rows shown, so a search
   * narrows it; inactive rows are left alone. Absent, there is no Select all.
   */
  onSelect?: (ids: string[], on: boolean) => void
  /** Controls shown beside a chosen row. */
  extra?: (id: string) => ReactNode
  /** Said when there is nothing to pick at all. */
  empty?: string
  idPrefix: string
}) {
  const [q, setQ] = useState('')
  const needle = q.trim().toLowerCase()
  const shown = options
    .filter((o) => !needle || o.label.toLowerCase().includes(needle) || (o.detail ?? '').toLowerCase().includes(needle))
    .sort((a, b) => Number(selected.includes(b.id)) - Number(selected.includes(a.id)))
  const pickable = shown.filter((o) => !o.inactive && !o.locked)
  const chosenShown = pickable.filter((o) => selected.includes(o.id)).length
  const all = pickable.length > 0 && chosenShown === pickable.length
  const some = chosenShown > 0 && !all
  return (
    <div className="picklist">
      {options.length > 6 && (
        <input type="search" className="picklist-search" placeholder={`Search ${label}`} aria-label={`Search ${label}`} value={q} onChange={(e) => setQ(e.target.value)} />
      )}
      {onSelect && pickable.length > 1 && (
        <div className="pick-row pick-all">
          <input
            id={`${idPrefix}-all`}
            type="checkbox"
            checked={all}
            ref={(el) => {
              if (el) el.indeterminate = some
            }}
            onChange={() => onSelect(all ? pickable.map((o) => o.id) : pickable.filter((o) => !selected.includes(o.id)).map((o) => o.id), !all)}
          />
          <label htmlFor={`${idPrefix}-all`}>{needle ? `Select all ${pickable.length} shown` : `Select all ${label}`}</label>
        </div>
      )}
      <div className="picklist-rows">
        {options.length === 0 && <div className="muted picklist-empty">{empty ?? `No ${label} yet`}</div>}
        {options.length > 0 && shown.length === 0 && <div className="muted picklist-empty">No {label} match</div>}
        {shown.map((o) => {
          const on = selected.includes(o.id)
          const id = `${idPrefix}-${o.id}`
          return (
            <div key={o.id} className={'pick-row' + (on ? ' on' : '') + (o.locked ? ' locked' : '')} title={o.locked}>
              <input id={id} type="checkbox" checked={on} disabled={!!o.locked && !on} onChange={() => onToggle(o.id)} />
              <label htmlFor={id}>{o.label}</label>
              {o.detail && (
                <span className="pick-detail" title={o.detailTitle}>
                  {o.detail}
                </span>
              )}
              {o.locked && <span className="muted">{o.locked}</span>}
              {on && extra && <span className="pick-extra">{extra(o.id)}</span>}
            </div>
          )
        })}
      </div>
      {selected.length > 0 && (
        <div className="muted picklist-count">
          {selected.length} of {options.length} chosen
        </div>
      )}
    </div>
  )
}
