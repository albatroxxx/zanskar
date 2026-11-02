import { useState } from 'react'

/** A filter a reviewer named, kept as the page's own query string. */
export interface SavedView {
  name: string
  query: string
}

const maxViews = 20

function read(key: string): SavedView[] {
  try {
    const v = JSON.parse(localStorage.getItem(key) ?? '[]')
    return Array.isArray(v) ? v.filter((x) => typeof x?.name === 'string' && typeof x?.query === 'string').slice(0, maxViews) : []
  } catch {
    return []
  }
}

/**
 * SavedViews keeps a list page's filters under names, in this browser only
 * (2026-11-03, idea 12): an auditor's "failed sign-ins this week" is one
 * pick away. A view is the page's query string, so opening one is following
 * a link; nothing about it reaches the gateway.
 */
export function SavedViews({ page, current, onOpen }: { page: string; current: string; onOpen: (query: string) => void }) {
  const key = `zanskar.views.${page}`
  const [views, setViews] = useState<SavedView[]>(() => read(key))
  const [naming, setNaming] = useState(false)
  const [name, setName] = useState('')
  const store = (next: SavedView[]) => {
    setViews(next)
    try {
      localStorage.setItem(key, JSON.stringify(next))
    } catch {
      // A browser that keeps nothing keeps the list for this visit only.
    }
  }
  const save = () => {
    const n = name.trim()
    if (!n) return
    store([{ name: n, query: current }, ...views.filter((v) => v.name !== n)].slice(0, maxViews))
    setName('')
    setNaming(false)
  }
  const chosen = views.find((v) => v.query === current)?.name ?? ''
  return (
    <span className="saved-views">
      {views.length > 0 && (
        <select
          aria-label="Saved views"
          value={chosen}
          onChange={(e) => {
            const v = views.find((x) => x.name === e.target.value)
            if (v) onOpen(v.query)
          }}
        >
          <option value="">Saved views</option>
          {views.map((v) => (
            <option key={v.name} value={v.name}>{v.name}</option>
          ))}
        </select>
      )}
      {chosen && (
        <button type="button" className="btn sm ghost" onClick={() => store(views.filter((v) => v.name !== chosen))} aria-label={`Forget the view ${chosen}`}>
          Forget
        </button>
      )}
      {naming ? (
        <>
          <input
            aria-label="Name this view"
            placeholder="name this view"
            value={name}
            maxLength={60}
            autoFocus
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') save()
              if (e.key === 'Escape') setNaming(false)
            }}
          />
          <button type="button" className="btn sm" onClick={save} disabled={!name.trim()}>Save</button>
        </>
      ) : (
        current && !chosen && <button type="button" className="btn sm" onClick={() => setNaming(true)}>Save view</button>
      )}
    </span>
  )
}
