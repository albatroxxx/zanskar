import { maxTagLen, maxTags, type TagRow } from './tags'

/**
 * TagEditor edits tags as rows of two boxes, Key and Value, the way cloud
 * consoles do, instead of key=value text. With suggestions it offers the keys
 * already in use and, once a key is chosen, the values seen under it.
 */
export function TagEditor({ rows, onChange, idPrefix, suggest, valuePlaceholder }: {
  rows: TagRow[]
  onChange: (rows: TagRow[]) => void
  /** Prefix for the boxes' ids; unique on the page. */
  idPrefix: string
  suggest?: Record<string, string[]>
  valuePlaceholder?: string
}) {
  const set = (i: number, patch: Partial<TagRow>) => onChange(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)))
  const keysId = `${idPrefix}-keys`
  return (
    <div className="tag-editor">
      {rows.length > 0 && (
        <div className="tag-row tag-head" aria-hidden="true">
          <span>Key</span>
          <span>Value</span>
        </div>
      )}
      {rows.map((r, i) => {
        const values = suggest?.[r.key.trim()] ?? []
        const valuesId = `${idPrefix}-v${i}-values`
        return (
          <div className="tag-row" key={i}>
            <input
              id={`${idPrefix}-k${i}`}
              aria-label={`Tag ${i + 1} key`}
              value={r.key}
              maxLength={maxTagLen}
              autoComplete="off"
              list={suggest ? keysId : undefined}
              onChange={(e) => set(i, { key: e.target.value })}
            />
            <input
              id={`${idPrefix}-v${i}`}
              aria-label={`Tag ${i + 1} value`}
              value={r.value}
              maxLength={maxTagLen}
              autoComplete="off"
              placeholder={valuePlaceholder}
              list={values.length ? valuesId : undefined}
              onChange={(e) => set(i, { value: e.target.value })}
            />
            <button type="button" className="btn sm ghost" aria-label={`Remove tag ${r.key.trim() || i + 1}`} onClick={() => onChange(rows.filter((_, j) => j !== i))}>
              ×
            </button>
            {values.length > 0 && (
              <datalist id={valuesId}>
                {values.map((v) => <option key={v} value={v}>{v}</option>)}
              </datalist>
            )}
          </div>
        )
      })}
      {suggest && (
        <datalist id={keysId}>
          {Object.keys(suggest).sort().map((k) => <option key={k} value={k}>{k}</option>)}
        </datalist>
      )}
      <div>
        <button type="button" className="btn sm" disabled={rows.length >= maxTags} onClick={() => onChange([...rows, { key: '', value: '' }])}>
          Add tag
        </button>
      </div>
    </div>
  )
}
