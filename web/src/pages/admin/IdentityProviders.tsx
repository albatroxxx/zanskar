import { useEffect, useState, type FormEvent } from 'react'
import { api, errorMessage } from '../../api/client'
import { fmtTime } from '../../api/format'
import type { Group, Page, Role } from '../../api/types'
import { useSubmit } from '../../components/submit'
import { Alert, Badge, Confirm, Empty, Field, Modal, PageHead } from '../../components/ui'
import { useList } from './lib'
import { mappingToText, textToMapping } from './groupMapping'
import { StateIcon } from '../../components/icons'
import { CopyButton } from '../../components/CopyButton'

// Shapes mirror internal/idp: the API returns the provider row plus its
// config with secrets blanked and a single has_secret flag. Secrets are
// write-only: sent on save, never returned.
type IdPType = 'oidc' | 'ldap'

interface OIDCConfig {
  issuer?: string
  client_id?: string
  client_secret?: string
  scopes?: string[]
  groups_claim?: string
  username_claim?: string
  allowed_domains?: string[]
  /** Accept the email claim when the provider never says it is verified (Entra ID). */
  trust_email?: boolean
  /** The provider does no MFA: ask for a Zanskar authenticator after it. */
  zanskar_mfa?: boolean
  /** Signing out of Zanskar leaves the provider's session alone. */
  keep_provider_session?: boolean
}
interface LDAPConfig {
  url?: string
  start_tls?: boolean
  ca_cert_pem?: string
  insecure_skip_verify?: boolean
  bind_dn?: string
  bind_password?: string
  base_dn?: string
  user_filter?: string
  username_attr?: string
  display_name_attr?: string
  email_attr?: string
  group_attr?: string
  group_base_dn?: string
  group_filter?: string
  group_name_attr?: string
  username_suffix?: string
}
interface IdPConfig {
  oidc?: OIDCConfig
  ldap?: LDAPConfig
  default_roles?: Role[]
  group_mapping?: Record<string, string>
  auto_provision?: boolean
  /** List the directory on a schedule: joiners get accounts, leavers are disabled (ADR 0035). */
  sync_users?: boolean
  sync_minutes?: number
  /** The provider pushes its people over SCIM 2.0 instead (ADR 0035). */
  scim?: boolean
}
/** One run of the directory user sync, as internal/idp.SyncStatus. */
interface SyncRun {
  at: string
  ok: boolean
  error?: string
  listed: number
  created: number
  linked: number
  updated: number
  enabled: number
  disabled: number
  not_created: number
  conflicts?: string[]
  held: number
  held_reason?: string
}
interface SyncState {
  enabled: boolean
  interval_minutes: number
  running: boolean
  last: SyncRun | null
}
interface Provider {
  id: string
  name: string
  type: IdPType
  enabled: boolean
  created_at: string
  updated_at: string
  config: IdPConfig
  has_secret: boolean
  sync?: SyncState
  /** When the SCIM token was made; absent when there is none. */
  scim_token_created_at?: string
}

/** How a provider's people get accounts in Zanskar. */
type Arrival = 'signin' | 'scim' | 'list'

function arrivalOf(c?: IdPConfig): Arrival {
  return c?.scim ? 'scim' : c?.sync_users ? 'list' : 'signin'
}

const roleOptions: Role[] = ['user', 'auditor', 'admin']

function csv(v?: string[]): string {
  return (v ?? []).join(', ')
}
function fromCsv(s: string): string[] {
  return s.split(',').map((x) => x.trim()).filter(Boolean)
}

export function IdentityProviders() {
  const { items, err, reload } = useList<Provider>('/identity-providers')
  const [editing, setEditing] = useState<Provider | 'new' | null>(null)
  const [deleting, setDeleting] = useState<Provider | null>(null)
  const [syncing, setSyncing] = useState<string | null>(null)
  const [notice, setNotice] = useState<{ tone: 'ok' | 'warn' | 'danger'; text: string } | null>(null)
  // A run that held back removals offers to apply them, after a confirmation.
  const [held, setHeld] = useState<{ provider: Provider; run: SyncRun } | null>(null)

  const runSync = async (p: Provider, applyRemovals = false) => {
    setSyncing(p.id)
    setNotice(null)
    try {
      const st = await api.post<SyncState>(`/identity-providers/${p.id}/sync`, applyRemovals ? { apply_removals: true } : undefined)
      const run = st.last
      if (!run) return
      if (!run.ok) setNotice({ tone: 'danger', text: `${p.name}: ${run.error ?? 'sync failed'}` })
      else setNotice({ tone: run.held > 0 ? 'warn' : 'ok', text: `${p.name}: ${syncSummary(run)}` })
      if (run.ok && run.held > 0 && !applyRemovals) setHeld({ provider: p, run })
    } catch (e) {
      setNotice({ tone: 'danger', text: `${p.name}: ${errorMessage(e)}` })
    } finally {
      setSyncing(null)
      void reload()
    }
  }

  return (
    <>
      <PageHead title="Identity providers" lead="Secrets are sealed on save and never shown again.">
        <button className="btn primary" onClick={() => setEditing('new')}>Add provider</button>
      </PageHead>
      {err && <Alert tone="danger">{err}</Alert>}
      {notice && <Alert tone={notice.tone}>{notice.text}</Alert>}
      <div className="card table-wrap">
        {items === null ? (
          err ? null : <Empty>Loading…</Empty>
        ) : items.length === 0 ? (
          <Empty>No identity providers yet. Add one to let users sign in with your directory.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Status</th>
                <th>Secret</th>
                <th>People</th>
                <th>Created</th>
                <th><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {items.map((p) => (
                <tr key={p.id}>
                  <td><strong>{p.name}</strong></td>
                  <td><Badge tone="accent">{p.type.toUpperCase()}</Badge></td>
                  <td>{p.enabled ? <StateIcon state="ok" label="Enabled" /> : <StateIcon state="unknown" label="Disabled" />}</td>
                  <td>{p.has_secret ? <StateIcon state="ok" label="Secret stored" /> : <StateIcon state="warn" label="No secret stored" />}</td>
                  <td><ArrivalCell provider={p} /></td>
                  <td>{fmtTime(p.created_at)}</td>
                  <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                    {p.sync && p.enabled && (
                      <>
                        <button className="btn sm" disabled={syncing !== null || p.sync.running} onClick={() => void runSync(p)}>{syncing === p.id ? 'Syncing…' : 'Sync now'}</button>{' '}
                      </>
                    )}
                    <button className="btn sm" onClick={() => setEditing(p)}>Edit</button>{' '}
                    <button className="btn sm danger" onClick={() => setDeleting(p)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {editing && (
        <ProviderModal
          existing={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null)
            void reload()
          }}
        />
      )}
      {held && (
        <Confirm
          title="Apply held removals"
          danger
          confirmLabel={`Disable ${held.run.held}`}
          body={<p>{held.run.held_reason}. Disable those {held.run.held} accounts of <strong>{held.provider.name}</strong> and end their sessions?</p>}
          onConfirm={() => runSync(held.provider, true)}
          onClose={() => setHeld(null)}
        />
      )}
      {deleting && (
        <Confirm
          title="Delete provider"
          danger
          confirmLabel="Delete"
          body={<p>Delete <strong>{deleting.name}</strong>? Users provisioned through it keep their accounts but can no longer sign in with it.</p>}
          onConfirm={async () => {
            await api.del(`/identity-providers/${deleting.id}`)
            void reload()
          }}
          onClose={() => setDeleting(null)}
        />
      )}
    </>
  )
}

/** What a sync run did, in a line: only the counts that are not zero. */
function syncSummary(run: SyncRun): string {
  const parts = [`${run.listed} listed`]
  const add = (n: number, what: string) => {
    if (n > 0) parts.push(`${n} ${what}`)
  }
  add(run.created, 'created')
  add(run.linked, 'linked')
  add(run.updated, 'updated')
  add(run.enabled, 'enabled again')
  add(run.disabled, 'disabled')
  add(run.not_created, 'without an account')
  add(run.conflicts?.length ?? 0, `in conflict (${(run.conflicts ?? []).join(', ')})`)
  if (run.held > 0) parts.push(`${run.held} held: ${run.held_reason ?? ''}`)
  return parts.join(' · ')
}

/** How the provider's people arrive, and how the last of it went. */
function ArrivalCell({ provider: p }: { provider: Provider }) {
  if (p.config?.scim) {
    return p.scim_token_created_at
      ? <StateIcon state="ok" label={`Pushed over SCIM · token made ${fmtTime(p.scim_token_created_at)}`} />
      : <StateIcon state="warn" label="Pushed over SCIM · no token yet" />
  }
  return <SyncCell sync={p.sync} />
}

function SyncCell({ sync }: { sync?: SyncState }) {
  if (!sync) return <span className="muted">At sign-in</span>
  if (sync.running) return <StateIcon state="unknown" label="Running" />
  const run = sync.last
  if (!run) return <StateIcon state="unknown" label={`Every ${sync.interval_minutes} min; not run yet`} />
  if (!run.ok) return <StateIcon state="danger" label={`Failed ${fmtTime(run.at)}: ${run.error ?? ''}`} />
  return <StateIcon state={run.held > 0 ? 'warn' : 'ok'} label={`${fmtTime(run.at)} · ${syncSummary(run)}`} />
}

function arrivalHint(a: Arrival, type: IdPType): string {
  switch (a) {
    case 'scim':
      return 'Okta, Entra ID, OneLogin, JumpCloud, PingOne, Authentik… People deactivated or removed there are disabled here.'
    case 'list':
      return type === 'oidc'
        ? 'Keycloak realms: the client needs a service account with realm-management › view-users. People who leave are disabled.'
        : 'Everyone the user filter matches. People who leave are disabled.'
  }
  return ''
}

/** The SCIM base URL and token to give the provider. The token is shown
 *  once, when it is made; making another stops the first. */
function SCIMSetup({ provider }: { provider: Provider }) {
  const [madeAt, setMadeAt] = useState(provider.scim_token_created_at)
  const [token, setToken] = useState('')
  const [confirm, setConfirm] = useState<'replace' | 'revoke' | null>(null)
  const { busy, err, submit } = useSubmit()
  const baseURL = `${window.location.origin}/api/v1/scim/${provider.id}`
  const make = () =>
    submit(async () => {
      const r = await api.post<{ token: string; created_at: string }>(`/identity-providers/${provider.id}/scim-token`)
      setToken(r.token)
      setMadeAt(r.created_at)
    })
  return (
    <div className="register-uris">
      {err && <Alert tone="danger">{err}</Alert>}
      <div className="field">
        <label htmlFor="scim-base">SCIM base URL</label>
        <div className="copy-row">
          <input id="scim-base" readOnly value={baseURL} onFocus={(e) => e.target.select()} />
          <CopyButton text={baseURL} name="SCIM base URL" />
        </div>
      </div>
      {token ? (
        <div className="field">
          <label htmlFor="scim-token">SCIM token</label>
          <div className="copy-row">
            <input id="scim-token" readOnly value={token} onFocus={(e) => e.target.select()} />
            <CopyButton text={token} name="SCIM token" />
          </div>
          <span className="hint">Shown once. Paste it at the provider as the bearer token.</span>
        </div>
      ) : (
        <div className="actions" style={{ alignItems: 'center' }}>
          <span className="muted">{madeAt ? `Token made ${fmtTime(madeAt)}` : 'No token yet'}</span>
          <button type="button" className="btn sm" disabled={busy} onClick={() => (madeAt ? setConfirm('replace') : void make())}>
            {madeAt ? 'Replace token' : 'Make token'}
          </button>
          {madeAt && <button type="button" className="btn sm danger" disabled={busy} onClick={() => setConfirm('revoke')}>Revoke</button>}
        </div>
      )}
      {confirm === 'replace' && (
        <Confirm title="Replace the SCIM token" confirmLabel="Replace" body={<p>The current token stops working at once. Give the provider the new one.</p>}
          onConfirm={make} onClose={() => setConfirm(null)} />
      )}
      {confirm === 'revoke' && (
        <Confirm title="Revoke the SCIM token" danger confirmLabel="Revoke" body={<p>The provider can no longer push changes until you make a new token.</p>}
          onConfirm={async () => {
            await api.del(`/identity-providers/${provider.id}/scim-token`)
            setMadeAt(undefined)
          }}
          onClose={() => setConfirm(null)} />
      )}
    </div>
  )
}

/** The address an OIDC provider must have registered for this gateway. The
 *  provider sends the browser back there after sign-in, and after sign-out
 *  too (ADR 0035), so one registration covers both. */
function RegisterURI({ id }: { id: string }) {
  const value = `${window.location.origin}/api/v1/auth/oidc/${id}/callback`
  return (
    <div className="field">
      <label htmlFor="oidc-uri-redirect">Redirect URI</label>
      <div className="copy-row">
        <input id="oidc-uri-redirect" aria-describedby="oidc-uri-hint" readOnly value={value} onFocus={(e) => e.target.select()} />
        <CopyButton text={value} name="Redirect URI" />
      </div>
      <span className="hint" id="oidc-uri-hint">Register it at the provider; it is also the post-logout redirect URI.</span>
    </div>
  )
}

function ProviderModal({ existing, onClose, onSaved }: { existing: Provider | null; onClose: () => void; onSaved: () => void }) {
  const [loaded, setLoaded] = useState<Provider | null>(existing && !existing.config ? null : existing)
  const [type, setType] = useState<IdPType>(existing?.type ?? 'oidc')
  const [name, setName] = useState(existing?.name ?? '')
  const [enabled, setEnabled] = useState(existing?.enabled ?? true)
  const [autoProvision, setAutoProvision] = useState(existing?.config?.auto_provision ?? true)
  const [arrival, setArrival] = useState<Arrival>(arrivalOf(existing?.config))
  const [syncMinutes, setSyncMinutes] = useState(String(existing?.config?.sync_minutes || 15))
  const [roles, setRoles] = useState<Role[]>(existing?.config?.default_roles ?? ['user'])
  const [mapping, setMapping] = useState(mappingToText(existing?.config?.group_mapping))
  const [oidc, setOidc] = useState<OIDCConfig>(existing?.config?.oidc ?? {})
  const [ldap, setLdap] = useState<LDAPConfig>(existing?.config?.ldap ?? {})
  const [scopes, setScopes] = useState(csv(existing?.config?.oidc?.scopes))
  const [domains, setDomains] = useState(csv(existing?.config?.oidc?.allowed_domains))
  const [groups, setGroups] = useState<Group[]>([])
  const { busy, err: localErr, setErr: setLocalErr, submit } = useSubmit()
  const [test, setTest] = useState<{ tone: 'ok' | 'warn' | 'danger'; msg: string } | null>(null)

  // Editing: fetch the full (redacted) config, which the list may not carry.
  useEffect(() => {
    if (existing) {
      api.get<Provider>(`/identity-providers/${existing.id}`).then((p) => {
        setLoaded(p)
        setType(p.type)
        setName(p.name)
        setEnabled(p.enabled)
        setAutoProvision(p.config?.auto_provision ?? true)
        setArrival(arrivalOf(p.config))
        setSyncMinutes(String(p.config?.sync_minutes || 15))
        setRoles(p.config?.default_roles ?? ['user'])
        setMapping(mappingToText(p.config?.group_mapping))
        setOidc(p.config?.oidc ?? {})
        setLdap(p.config?.ldap ?? {})
        setScopes(csv(p.config?.oidc?.scopes))
        setDomains(csv(p.config?.oidc?.allowed_domains))
      }).catch((e) => setLocalErr(errorMessage(e)))
    }
    api.get<Page<Group>>('/groups').then((g) => setGroups(g.items ?? [])).catch(() => {})
  }, [existing, setLocalErr])

  const toggleRole = (r: Role) => setRoles((cur) => (cur.includes(r) ? cur.filter((x) => x !== r) : [...cur, r]))

  const build = (): { body?: Record<string, unknown>; error?: string } => {
    if (!name.trim()) return { error: 'name is required' }
    const { mapping: gm, error } = textToMapping(mapping)
    if (error) return { error }
    const config: IdPConfig = { default_roles: roles, group_mapping: gm, auto_provision: autoProvision }
    if (arrival === 'scim') config.scim = true
    if (arrival === 'list') {
      const minutes = Number(syncMinutes)
      if (!Number.isInteger(minutes) || minutes < 5 || minutes > 1440) return { error: 'sync every 5 to 1440 minutes' }
      config.sync_users = true
      config.sync_minutes = minutes
    }
    if (type === 'oidc') {
      config.oidc = { ...oidc, scopes: fromCsv(scopes), allowed_domains: fromCsv(domains) }
    } else {
      config.ldap = { ...ldap }
    }
    return { body: { name: name.trim(), type, enabled, config } }
  }

  const save = (e: FormEvent) => {
    e.preventDefault()
    const { body, error } = build()
    if (error) {
      setLocalErr(error)
      return
    }
    void submit(async () => {
      if (existing) await api.put(`/identity-providers/${existing.id}`, body)
      else await api.post('/identity-providers', body)
      onSaved()
    })
  }

  const runTest = async () => {
    if (!existing) return
    setTest(null)
    try {
      const r = await api.post<{ status: string; message?: string; provider_sign_out?: boolean }>(`/identity-providers/${existing.id}/test`)
      if (r.status === 'ok' && r.provider_sign_out === false) setTest({ tone: 'warn', msg: 'Connection succeeded. The provider offers no sign-out, so signing out ends the Zanskar session only.' })
      else if (r.status === 'ok') setTest({ tone: 'ok', msg: 'Connection succeeded.' })
      else if (r.status === 'skipped') setTest({ tone: 'warn', msg: r.message ?? 'Test not available.' })
      else setTest({ tone: 'danger', msg: r.message ?? 'Connection failed.' })
    } catch (err) {
      setTest({ tone: 'danger', msg: errorMessage(err) })
    }
  }

  const secretStored = !!loaded?.has_secret
  const secretPlaceholder = secretStored ? 'leave blank to keep the stored secret' : ''

  return (
    <Modal title={existing ? `Edit ${existing.name}` : 'Add identity provider'} onClose={onClose} width={620}>
      {localErr && <Alert tone="danger">{localErr}</Alert>}
      {test && <Alert tone={test.tone}>{test.msg}</Alert>}
      <form onSubmit={save}>
        <div className="form-grid">
          <Field label="Name"><input id="idp-name" value={name} onChange={(e) => setName(e.target.value)} required /></Field>
          <Field label="Type" hint={existing ? 'type cannot be changed after creation' : ''}>
            <select id="idp-type" value={type} onChange={(e) => setType(e.target.value as IdPType)} disabled={!!existing}>
              <option value="oidc">OpenID Connect</option>
              <option value="ldap">LDAP / Active Directory</option>
            </select>
          </Field>
        </div>

        {type === 'oidc' && (
          <>
            <Field label="Issuer URL" hint="e.g. https://login.example.com — discovery is automatic">
              <input id="oidc-issuer" value={oidc.issuer ?? ''} onChange={(e) => setOidc({ ...oidc, issuer: e.target.value })} placeholder="https://..." />
            </Field>
            <div className="form-grid">
              <Field label="Client ID"><input id="oidc-cid" value={oidc.client_id ?? ''} onChange={(e) => setOidc({ ...oidc, client_id: e.target.value })} /></Field>
              <Field label="Client secret" hint={secretPlaceholder}>
                <input id="oidc-secret" type="password" autoComplete="new-password" value={oidc.client_secret ?? ''} onChange={(e) => setOidc({ ...oidc, client_secret: e.target.value })} placeholder={secretStored ? '••••••••' : ''} />
              </Field>
              <Field label="Scopes" hint="comma separated; default openid, profile, email"><input id="oidc-scopes" value={scopes} onChange={(e) => setScopes(e.target.value)} /></Field>
              <Field label="Username claim" hint="default preferred_username"><input id="oidc-uclaim" value={oidc.username_claim ?? ''} onChange={(e) => setOidc({ ...oidc, username_claim: e.target.value })} /></Field>
              <Field label="Groups claim" hint="e.g. groups; empty turns group mapping off"><input id="oidc-gclaim" value={oidc.groups_claim ?? ''} onChange={(e) => setOidc({ ...oidc, groups_claim: e.target.value })} /></Field>
              <Field label="Allowed email domains" hint="comma separated; empty allows all; the provider must have verified the address"><input id="oidc-domains" value={domains} onChange={(e) => setDomains(e.target.value)} /></Field>
            </div>
            <div className="field inline"><input id="oidc-trustemail" type="checkbox" checked={!!oidc.trust_email} onChange={(e) => setOidc({ ...oidc, trust_email: e.target.checked })} /><label htmlFor="oidc-trustemail">Trust email addresses the provider does not mark as verified (for one that never says, such as Entra ID, when your directory assigns the addresses)</label></div>
            <div className="field inline"><input id="oidc-zanskarmfa" type="checkbox" checked={!!oidc.zanskar_mfa} onChange={(e) => setOidc({ ...oidc, zanskar_mfa: e.target.checked })} /><label htmlFor="oidc-zanskarmfa">Also ask for a Zanskar authenticator (only for a provider with no MFA of its own)</label></div>
            <div className="field inline"><input id="oidc-endsession" type="checkbox" checked={!oidc.keep_provider_session} onChange={(e) => setOidc({ ...oidc, keep_provider_session: !e.target.checked })} /><label htmlFor="oidc-endsession">Signing out ends the provider session too</label></div>
            {existing && <RegisterURI id={existing.id} />}
          </>
        )}

        {type === 'ldap' && (
          <>
            <Field label="URL" hint="ldaps://host:636 or ldap://host:389 with StartTLS"><input id="ldap-url" value={ldap.url ?? ''} onChange={(e) => setLdap({ ...ldap, url: e.target.value })} placeholder="ldaps://..." /></Field>
            <div className="field inline"><input id="ldap-starttls" type="checkbox" checked={!!ldap.start_tls} onChange={(e) => setLdap({ ...ldap, start_tls: e.target.checked })} /><label htmlFor="ldap-starttls">Use StartTLS (for ldap://)</label></div>
            <Field label="CA certificate (PEM)" hint="pins the directory's certificate; required unless skipping verification"><textarea id="ldap-ca" value={ldap.ca_cert_pem ?? ''} onChange={(e) => setLdap({ ...ldap, ca_cert_pem: e.target.value })} /></Field>
            <div className="field inline"><input id="ldap-insecure" type="checkbox" checked={!!ldap.insecure_skip_verify} onChange={(e) => setLdap({ ...ldap, insecure_skip_verify: e.target.checked })} /><label htmlFor="ldap-insecure">Skip certificate verification (development only)</label></div>
            <div className="form-grid">
              <Field label="Bind DN"><input id="ldap-binddn" value={ldap.bind_dn ?? ''} onChange={(e) => setLdap({ ...ldap, bind_dn: e.target.value })} /></Field>
              <Field label="Bind password" hint={secretPlaceholder}><input id="ldap-bindpw" type="password" autoComplete="new-password" value={ldap.bind_password ?? ''} onChange={(e) => setLdap({ ...ldap, bind_password: e.target.value })} placeholder={secretStored ? '••••••••' : ''} /></Field>
              <Field label="Base DN"><input id="ldap-basedn" value={ldap.base_dn ?? ''} onChange={(e) => setLdap({ ...ldap, base_dn: e.target.value })} /></Field>
              <Field label="User filter" hint="%s is the login name, e.g. (&(objectClass=user)(sAMAccountName=%s))"><input id="ldap-filter" value={ldap.user_filter ?? ''} onChange={(e) => setLdap({ ...ldap, user_filter: e.target.value })} /></Field>
              <Field label="Username attribute" hint="sAMAccountName / uid"><input id="ldap-uattr" value={ldap.username_attr ?? ''} onChange={(e) => setLdap({ ...ldap, username_attr: e.target.value })} /></Field>
              <Field label="Display name attribute" hint="displayName / cn"><input id="ldap-dattr" value={ldap.display_name_attr ?? ''} onChange={(e) => setLdap({ ...ldap, display_name_attr: e.target.value })} /></Field>
              <Field label="Email attribute" hint="mail"><input id="ldap-eattr" value={ldap.email_attr ?? ''} onChange={(e) => setLdap({ ...ldap, email_attr: e.target.value })} /></Field>
              <Field label="Username suffix" hint="optional, e.g. @corp.example"><input id="ldap-suffix" value={ldap.username_suffix ?? ''} onChange={(e) => setLdap({ ...ldap, username_suffix: e.target.value })} /></Field>
              <Field label="Group attribute" hint="memberOf; leave blank to search groups instead"><input id="ldap-gattr" value={ldap.group_attr ?? ''} onChange={(e) => setLdap({ ...ldap, group_attr: e.target.value })} /></Field>
              <Field label="Group base DN"><input id="ldap-gbase" value={ldap.group_base_dn ?? ''} onChange={(e) => setLdap({ ...ldap, group_base_dn: e.target.value })} /></Field>
              <Field label="Group filter" hint="%s is the user DN"><input id="ldap-gfilter" value={ldap.group_filter ?? ''} onChange={(e) => setLdap({ ...ldap, group_filter: e.target.value })} /></Field>
              <Field label="Group name attribute" hint="cn"><input id="ldap-gname" value={ldap.group_name_attr ?? ''} onChange={(e) => setLdap({ ...ldap, group_name_attr: e.target.value })} /></Field>
            </div>
          </>
        )}

        <hr style={{ border: 0, borderTop: '1px solid var(--line)', margin: '16px 0' }} />
        <div className="field inline"><input id="idp-enabled" type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /><label htmlFor="idp-enabled">Enabled</label></div>
        <div className="field inline"><input id="idp-auto" type="checkbox" checked={autoProvision} onChange={(e) => setAutoProvision(e.target.checked)} /><label htmlFor="idp-auto">Create an account for each new person</label></div>
        <Field label="People arrive" hint={arrivalHint(arrival, type)}>
          <select id="idp-arrival" value={arrival} onChange={(e) => setArrival(e.target.value as Arrival)}>
            <option value="signin">At their first sign-in</option>
            <option value="scim">Pushed by the provider (SCIM)</option>
            <option value="list">Listed by Zanskar on a schedule</option>
          </select>
        </Field>
        {arrival === 'list' && (
          <Field label="Sync every (minutes)">
            <input id="idp-sync-minutes" type="number" min={5} max={1440} step={1} value={syncMinutes} onChange={(e) => setSyncMinutes(e.target.value)} />
          </Field>
        )}
        {arrival === 'scim' && (existing ? <SCIMSetup provider={loaded ?? existing} /> : <p className="hint">Save the provider, then make its SCIM token here.</p>)}
        <Field label="Default roles for provisioned users">
          <div className="actions">
            {roleOptions.map((r) => (
              <label key={r} style={{ display: 'inline-flex', gap: 4, alignItems: 'center' }}>
                <input type="checkbox" checked={roles.includes(r)} onChange={() => toggleRole(r)} /> {r}
              </label>
            ))}
          </div>
        </Field>
        <Field label="Group mapping" hint="One per line: externalGroup=zanskarGroupId. For LDAP use the group's full DN (cn=ops,ou=groups,dc=…): a plain name matches every group of that name in any OU.">
          <textarea id="idp-mapping" value={mapping} onChange={(e) => setMapping(e.target.value)} placeholder="ops-team=abc123..." />
        </Field>
        {groups.length > 0 && (
          <div className="hint" style={{ marginTop: -8, marginBottom: 12 }}>
            Groups: {groups.map((g) => <span key={g.id} className="tag">{g.name}={g.id}</span>)}
          </div>
        )}

        <div className="actions" style={{ justifyContent: 'space-between' }}>
          <span>{existing && <button type="button" className="btn" onClick={runTest}>Test connection</button>}</span>
          <span>
            <button type="button" className="btn" onClick={onClose} disabled={busy}>Cancel</button>{' '}
            <button type="submit" className="btn primary" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>
          </span>
        </div>
      </form>
    </Modal>
  )
}
