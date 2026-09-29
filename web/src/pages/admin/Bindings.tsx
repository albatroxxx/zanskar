import { useState } from 'react'
import type { Credential, CredentialType, Protocol } from '../../api/types'
import { Field } from '../../components/ui'

export interface BindingSlot { protocol: Protocol; label: string }
export interface BindingChange { protocol: Protocol; credential_id: string }

/** The credential_id that means "prompt the user for their own login at connect time". */
export const USER_SUPPLIED = 'user_supplied'

/** Credential types that make sense for each protocol. */
const suitable: Record<Protocol, CredentialType[]> = {
  ssh: ['ssh_key', 'ssh_ca', 'password', 'ec2_instance_connect'],
  rdp: ['password', 'domain'],
  vnc: ['password'],
  winrm: ['password', 'domain'],
  database: ['password'],
}

/**
 * CredentialBindings edits what a target or autoscaling group presents per
 * protocol: nothing, the user's own login asked for at connect time, or a
 * vaulted credential. The choice is one control with three states (manual
 * QA finding R35); "user supplied" is stored as a shared credential row the
 * server keeps, so the editor shows any such row as that state.
 *
 * Choices are held as a draft and applied only on Save; Discard (or closing
 * the drawer) throws the draft away (manual QA finding R7).
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

/** CredentialSelect is the tri-state control, shared with the autoscaling form. */
export function CredentialSelect({ id, protocol, value, credentials, disabled, onChange }: { id: string; protocol: Protocol; value: string; credentials: Credential[]; disabled?: boolean; onChange: (v: string) => void }) {
  const vaulted = credentials.filter((c) => c.mode === 'vaulted' && suitable[protocol].includes(c.type))
  return (
    <select id={id} value={value} disabled={disabled} onChange={(e) => onChange(e.target.value)}>
      <option value="">— none —</option>
      <option value={USER_SUPPLIED}>User supplied: ask the user for their own login</option>
      {vaulted.map((c) => (
        <option key={c.id} value={c.id}>
          {c.name} ({c.type.replace(/_/g, ' ')}{c.username ? `, ${c.username}` : ''})
        </option>
      ))}
    </select>
  )
}

/** shown maps a stored credential id to the control's value: a user_supplied row reads as the sentinel. */
export function shownValue(id: string | undefined, credentials: Credential[]) {
  if (!id) return ''
  const c = credentials.find((x) => x.id === id)
  return c?.mode === 'user_supplied' ? USER_SUPPLIED : id
}

function BindingsEditor({ slots, current, credentials, onSave, onError }: Props) {
  const shown: Partial<Record<Protocol, string>> = {}
  for (const s of slots) shown[s.protocol] = shownValue(current[s.protocol], credentials)
  const [draft, setDraft] = useState<Partial<Record<Protocol, string>>>(shown)
  const [busy, setBusy] = useState(false)

  const changes: BindingChange[] = slots
    .filter((s) => (draft[s.protocol] ?? '') !== (shown[s.protocol] ?? ''))
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
          <Field key={s.protocol} label={s.label} hint={draft[s.protocol] === USER_SUPPLIED ? 'Zanskar forwards what the user types and stores nothing' : undefined}>
            <CredentialSelect id={`cred-${s.protocol}`} protocol={s.protocol} value={draft[s.protocol] ?? ''} credentials={credentials} disabled={busy} onChange={(v) => setDraft({ ...draft, [s.protocol]: v })} />
          </Field>
        ))}
      </div>
      {dirty && (
        <div className="actions" style={{ marginTop: 4 }}>
          <button className="btn primary sm" disabled={busy} onClick={() => void save()}>{busy ? 'Saving…' : `Save ${changes.length === 1 ? 'binding' : 'bindings'}`}</button>
          <button className="btn sm" disabled={busy} onClick={() => setDraft(shown)}>Discard</button>
          <span className="muted">Unsaved changes; closing the panel discards them.</span>
        </div>
      )}
    </>
  )
}
