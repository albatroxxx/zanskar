import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../../api/client'
import type { AppsReadiness, Credential, Target } from '../../api/types'
import { FilterChips } from '../../components/FilterChips'
import { StateIcon } from '../../components/icons'
import { Alert, Badge, Empty, PageHead } from '../../components/ui'
import { useDebounced, useList } from './lib'
import { TargetDetail } from './TargetDetail'
import { TargetForm, type TargetKind } from './TargetForm'

/**
 * TargetsPage is the page for one kind of target: the list with an Add
 * button, the form that adds one of that kind, and the drawer that opens
 * one. Hosts and databases differ only in their words and in the columns
 * between a target's name and its Manage button.
 */
export function TargetsPage({ kind, title, addLabel, empty, columns, cells }: {
  kind: TargetKind
  title: string
  addLabel: string
  /** What the list says while it has no target of this kind. */
  empty: string
  /** Headers of the columns between Name and the Manage button. */
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
  // A dashboard number opens this list narrowed to what it counted
  // (2026-10-30): attention=1 the hosts waiting on a decision, status=active
  // the active ones the inventory counts. Each shows as a chip that drops it.
  const [sp, setSp] = useSearchParams()
  const attention = kind === 'host' && sp.get('attention') === '1'
  const activeOnly = sp.get('status') === 'active'
  const drop = (key: string) => {
    const next = new URLSearchParams(sp)
    next.delete(key)
    setSp(next, { replace: true })
  }
  const { items, err, setErr, reload } = useList<Target>('/targets', {
    kind, q: dq, attention: attention ? 'true' : undefined, status: activeOnly ? 'active' : undefined,
  })
  const noun = title.toLowerCase()
  const creds = useList<Credential>('/credentials')
  const [adding, setAdding] = useState(false)
  const [open, setOpen] = useState<Target | null>(null)
  // Applications open only once the gateway can run the browser beside it
  // (ADR 0034). Until the prerequisites pass, the page is the checklist and
  // Check again; Add application appears once they do (2026-10-30). A
  // check that cannot be read does not hold the page back.
  const [readiness, setReadiness] = useState<AppsReadiness | 'unknown' | null>(kind === 'application' ? null : 'unknown')
  const [checking, setChecking] = useState(false)
  const check = useCallback((fresh: boolean) => {
    setChecking(true)
    api
      .get<AppsReadiness>('/admin/applications/readiness' + (fresh ? '?fresh=1' : ''))
      .then((r) => setReadiness(r && Array.isArray(r.checks) ? r : 'unknown'))
      .catch(() => setReadiness('unknown'))
      .finally(() => setChecking(false))
  }, [])
  useEffect(() => {
    if (kind === 'application') check(false)
  }, [kind, check])
  const blocked = readiness !== 'unknown' && !readiness?.ready

  return (
    <>
      <PageHead title={title}>
        {!blocked && <button className="btn primary" onClick={() => setAdding(true)}>{addLabel}</button>}
      </PageHead>
      {err && <Alert tone="danger">{err}</Alert>}
      {readiness && readiness !== 'unknown' && !readiness.ready && (
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
          <div className="actions">
            <button className="btn" disabled={checking} onClick={() => check(true)}>{checking ? 'Checking…' : 'Check again'}</button>
          </div>
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
        <FilterChips chips={[
          ...(attention ? [{ label: 'Needing attention', onClear: () => drop('attention') }] : []),
          ...(activeOnly ? [{ label: 'Active only', onClear: () => drop('status') }] : []),
        ]} />
        {items === null ? (
          err ? null : <Empty>Loading…</Empty>
        ) : items.length === 0 ? (
          <Empty>{dq || attention || activeOnly ? `No ${noun} match.` : empty}</Empty>
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
                    {/* Manage, not Open: in the console it opens the record (details,
                        edit, disable, delete), never a session to the target, which is what
                        Open means in the access portal (2026-10-30). */}
                    <button className="btn sm" onClick={() => setOpen(t)}>Manage</button>
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
