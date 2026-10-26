import { useState, type ReactNode } from 'react'
import type { Credential, Target } from '../../api/types'
import { Alert, Badge, Empty, PageHead } from '../../components/ui'
import { useList } from './lib'
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
  const { items, err, setErr, reload } = useList<Target>('/targets', { kind })
  const creds = useList<Credential>('/credentials')
  const [adding, setAdding] = useState(false)
  const [open, setOpen] = useState<Target | null>(null)

  return (
    <>
      <PageHead title={title} lead={lead}>
        <button className="btn primary" onClick={() => setAdding(true)}>{addLabel}</button>
      </PageHead>
      {err && <Alert tone="danger">{err}</Alert>}
      <div className="card table-wrap">
        {items === null ? (
          <Empty>Loading…</Empty>
        ) : items.length === 0 ? (
          <Empty>{empty}</Empty>
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
