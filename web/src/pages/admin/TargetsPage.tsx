import { useEffect, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../../api/client'
import type { AppsReadiness, Credential, Target } from '../../api/types'
import { StateIcon } from '../../components/icons'
import { Alert, Badge, Empty, PageHead } from '../../components/ui'
import { useDebounced, useList } from './lib'
import { TargetDetail } from './TargetDetail'
import { TargetForm, type TargetKind } from './TargetForm'

/**
 * TargetsPage is the page for one kind of target: the list with an Add
 * button, the form that adds one of that kind, and the drawer that opens
 * one. Hosts and databases differ only in their words and in the columns
 * between a target's name and its Open button.
 */
export function TargetsPage({ kind, title, lead, addLabel, empty, columns, cells }: {
  kind: TargetKind
  title: string
  lead: string
  addLabel: string
  /** What the list says while it has no target of this kind. */
  empty: string
  /** Headers of the columns between Name and the Open button. */
  columns: string[]
  /** One target's cells for those columns. The credentials are there to name what it is bound to. */
  cells: (t: Target, credentials: Credential[]) => ReactNode
}) {
  // The server does the matching (name or address, case-insensitive, wildcard
  // characters escaped — internal/target/repo.go), so search covers the whole
  // fleet, not just the first page held here. Debounced so a fetch fires once
  // typing pauses rather than on every keystroke.
  const [q, setQ] = useState('')
  const dq = useDebounced(q.trim())
  const { items, err, setErr, reload } = useList<Target>('/targets', { kind, q: dq })
  const noun = title.toLowerCase()
  const creds = useList<Credential>('/credentials')
  const [adding, setAdding] = useState(false)
  const [open, setOpen] = useState<Target | null>(null)
  // Applications open only once the gateway can run the browser beside it
  // (ADR 0034); the page shows the three prerequisites with their state, so
  // an operator sees what is left instead of one refusal at a time.
  const [readiness, setReadiness] = useState<AppsReadiness | null>(null)
  useEffect(() => {
    if (kind !== 'application') return
    api
      .get<AppsReadiness>('/admin/applications/readiness')
      .then((r) => setReadiness(r && Array.isArray(r.checks) ? r : null))
      .catch(() => setReadiness(null))
  }, [kind, adding])

  return (
    <>
      <PageHead title={title} lead={lead}>
        <button className="btn primary" onClick={() => setAdding(true)}>{addLabel}</button>
      </PageHead>
      {err && <Alert tone="danger">{err}</Alert>}
      {readiness && !readiness.ready && (
        <div className="card" aria-labelledby="apps-readiness">
          <h2 id="apps-readiness">Before the first application</h2>
          <ul className="checks">
            {readiness.checks.map((c) => (
              <li key={c.key}>
                <StateIcon state={c.ok ? 'ok' : 'warn'} label={c.ok ? 'done' : 'to do'} /> <strong>{c.title}</strong>
                <span className="muted"> {c.detail}</span>
                {!c.ok && c.key === 'guacd' && <> <Link to="/admin/settings#settings-desktops">Settings, Desktops</Link></>}
                {!c.ok && c.key === 'image' && <> <Link to="/admin/settings#settings-applications">Settings, Applications</Link></>}
              </li>
            ))}
          </ul>
        </div>
      )}
      <div className="card table-wrap">
        <div className="list-search">
          <input
            type="search"
            placeholder={`Search ${noun} by name or address`}
            aria-label={`Search ${noun}`}
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        {items === null ? (
          err ? null : <Empty>Loading…</Empty>
        ) : items.length === 0 ? (
          <Empty>{dq ? `No ${noun} match ‘${dq}’.` : empty}</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                {columns.map((c) => (
                  <th key={c}>{c}</th>
                ))}
                <th><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {items.map((t) => (
                <tr key={t.id}>
                  <td>
                    <strong>{t.name}</strong> {t.status === 'disabled' && <Badge>disabled</Badge>}
                  </td>
                  {cells(t, creds.items ?? [])}
                  <td>
                    <button className="btn sm" onClick={() => setOpen(t)}>Open</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {adding && (
        <TargetForm
          kind={kind}
          onClose={() => setAdding(false)}
          onSaved={() => {
            setAdding(false)
            void reload()
          }}
        />
      )}
      {open && (
        <TargetDetail
          target={open}
          credentials={creds.items ?? []}
          onClose={() => setOpen(null)}
          onChanged={(t) => {
            setOpen(t)
            void reload()
          }}
          onDeleted={() => {
            setOpen(null)
            void reload()
          }}
          onError={setErr}
        />
      )}
    </>
  )
}
