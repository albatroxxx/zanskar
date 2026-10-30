/** The filters a list was opened with that have no control of their own on
 *  the page (a dashboard's "needing attention", say), each a chip that drops
 *  it, so a narrowed list says why it is narrow. */
export function FilterChips({ chips }: { chips: { label: string; onClear: () => void }[] }) {
  if (chips.length === 0) return null
  return (
    <div className="filter-chips" role="group" aria-label="Filters">
      {chips.map((c) => (
        <button key={c.label} type="button" className="chip" onClick={c.onClear} aria-label={`${c.label}: remove filter`}>
          {c.label}
          <span aria-hidden="true">✕</span>
        </button>
      ))}
    </div>
  )
}
