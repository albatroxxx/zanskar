import { useState } from 'react'
import type { Credential, Protocol } from '../../api/types'
import { Field } from '../../components/ui'

export interface BindingSlot { protocol: Protocol; label: string }
export interface BindingChange { protocol: Protocol; credential_id: string }

/**
 * CredentialBindings edits which vaulted credential a target or autoscaling
 * group uses per protocol. Choices are held as a draft and applied only on
 * Save; Discard (or closing the drawer) throws the draft away. The previous
 * version wrote every change to the API the moment a select moved, which is
 * the one drawer in the admin app where a slip of the mouse changed
 * production wiring with no confirmation (manual QA finding R7).
 */
interface Props {
  slots: BindingSlot[]
  current: Partial<Record<Protocol, string>>
  credentials: Credential[]
  /** Applies the changed slots; throws on failure, in which case the draft stays. */
  onSave: (changes: BindingChange[]) => Promise<void>
  onError: (message: string) => void
}

export function CredentialBindings(props: Props) {
  // A save (or an external refresh) hands down new bindings; the editor is
  // remounted on them so its draft starts from what is actually stored,
  // rather than being patched in an effect.
  return <BindingsEditor key={JSON.stringify(props.current)} {...props} />
}

function BindingsEditor({ slots, current, credentials, onSave, onError }: Props) {
  const [draft, setDraft] = useState<Partial<Record<Protocol, string>>>(current)
  const [busy, setBusy] = useState(false)

  const changes: BindingChange[] = slots
    .filter((s) => (draft[s.protocol] ?? '') !== (current[s.protocol] ?? ''))
    .map((s) => ({ protocol: s.protocol, credential_id: draft[s.protocol] ?? '' }))
  const dirty = changes.length > 0

  const save = async () => {
    setBusy(true)
    try {
      await onSave(changes)
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <div className="form-grid">
        {slots.map((s) => (
          <Field key={s.protocol} label={s.label}>
            <select id={`cred-${s.protocol}`} value={draft[s.protocol] ?? ''} disabled={busy} onChange={(e) => setDraft({ ...draft, [s.protocol]: e.target.value })}>
              <option value="">— none —</option>
              {credentials.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name} ({c.type}, {c.mode})
                </option>
              ))}
            </select>
          </Field>
        ))}
      </div>
      {dirty && (
        <div className="actions" style={{ marginTop: 4 }}>
          <button className="btn primary sm" disabled={busy} onClick={() => void save()}>{busy ? 'Saving…' : `Save ${changes.length === 1 ? 'binding' : 'bindings'}`}</button>
          <button className="btn sm" disabled={busy} onClick={() => setDraft(current)}>Discard</button>
          <span className="muted">Unsaved changes; closing the panel discards them.</span>
        </div>
      )}
    </>
  )
}
