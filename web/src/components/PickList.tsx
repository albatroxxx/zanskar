import { useState, type ReactNode } from 'react'

export interface PickOption {
  id: string
  label: string
  /** A muted word beside the label: an OS, an engine, a member count. */
  detail?: string
}

/**
 * PickList picks many from a list: a search box over a checklist, the
 * chosen ones first. A chosen row may grow controls of its own (a target's
 * protocol chips). Groups, users and targets in the policy editor share it.
 */
export function PickList({ label, options, selected, onToggle, extra, empty, idPrefix }: {
  /** What is picked, plural, for the search box and the empty line: "groups". */
  label: string
  options: PickOption[]
  selected: string[]
  onToggle: (id: string) => void
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
  return (
    <div className="picklist">
      {options.length > 6 && (
        <input type="search" className="picklist-search" placeholder={`Search ${label}`} aria-label={`Search ${label}`} value={q} onChange={(e) => setQ(e.target.value)} />
      )}
      <div className="picklist-rows">
        {options.length === 0 && <div className="muted picklist-empty">{empty ?? `No ${label} yet`}</div>}
        {options.length > 0 && shown.length === 0 && <div className="muted picklist-empty">No {label} match</div>}
        {shown.map((o) => {
          const on = selected.includes(o.id)
          const id = `${idPrefix}-${o.id}`
          return (
            <div key={o.id} className={on ? 'pick-row on' : 'pick-row'}>
              <input id={id} type="checkbox" checked={on} onChange={() => onToggle(o.id)} />
              <label htmlFor={id}>{o.label}</label>
              {o.detail && <span className="muted">{o.detail}</span>}
              {on && extra && <span className="pick-extra">{extra(o.id)}</span>}
            </div>
          )
        })}
      </div>
      {selected.length > 0 && <div className="muted picklist-count">{selected.length} chosen</div>}
    </div>
  )
}
