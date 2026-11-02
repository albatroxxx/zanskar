import type { AppEndpoint } from '../../api/types'
import { RemoveButton } from '../../components/ui'
import { maxAppEndpoints } from './endpoints'

/**
 * EndpointEditor edits an application's further origins (ADR 0037, amended
 * 2026-11-02) as rows of Name and Address, as the tag editor edits tags:
 * an API on another host, the application's sign-in page. Each becomes a
 * bookmark in the session's browser; the name is optional (the host stands
 * in for it).
 */
export function EndpointEditor({ rows, onChange }: { rows: AppEndpoint[]; onChange: (rows: AppEndpoint[]) => void }) {
  const set = (i: number, patch: Partial<AppEndpoint>) => onChange(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)))
  return (
    <div className="tag-editor">
      {rows.length > 0 && (
        <div className="tag-row endpoint-row tag-head" aria-hidden="true">
          <span>Name</span>
          <span>Address</span>
        </div>
      )}
      {rows.map((r, i) => (
        <div className="tag-row endpoint-row" key={i}>
          <input id={`t-endpoint-name-${i}`} aria-label={`Endpoint ${i + 1} name`} value={r.name} maxLength={64} autoComplete="off" placeholder="Host" onChange={(e) => set(i, { name: e.target.value })} />
          <input id={`t-endpoint-url-${i}`} aria-label={`Endpoint ${i + 1} address`} value={r.url} autoComplete="off" placeholder="https://api.internal" onChange={(e) => set(i, { url: e.target.value })} />
          <RemoveButton label={`Remove endpoint ${r.name.trim() || r.url.trim() || i + 1}`} onClick={() => onChange(rows.filter((_, j) => j !== i))} />
        </div>
      ))}
      <div>
        <button type="button" className="btn sm" disabled={rows.length >= maxAppEndpoints} onClick={() => onChange([...rows, { name: '', url: '' }])}>
          Add endpoint
        </button>
      </div>
    </div>
  )
}
