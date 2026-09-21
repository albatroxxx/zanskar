import { useEffect, useState, type FormEvent } from 'react'
import { api, errorMessage } from '../../api/client'
import { fmtTime } from '../../api/format'
import type { Group, Page, Role } from '../../api/types'
import { Alert, Badge, Confirm, Empty, Field, Modal, PageHead } from '../../components/ui'
import { useList } from './lib'

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
  skip_mfa?: boolean
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
}

const roleOptions: Role[] = ['user', 'auditor', 'admin']

function mappingToText(m?: Record<string, string>): string {
  return Object.entries(m ?? {}).map(([k, v]) => `${k}=${v}`).join('\n')
}
function textToMapping(text: string): { mapping: Record<string, string>; error?: string } {
  const mapping: Record<string, string> = {}
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (!line) continue
    const i = line.indexOf('=')
    if (i <= 0) return { mapping, error: `line "${line}" must be externalName=groupId` }
    mapping[line.slice(0, i).trim()] = line.slice(i + 1).trim()
  }
  return { mapping }
}
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

  return (
    <>
      <PageHead title="Identity providers" lead="Sign users in through OpenID Connect or LDAP / Active Directory. Client secrets and bind passwords are sealed on save and never shown again.">
        <button className="btn primary" onClick={() => setEditing('new')}>Add provider</button>
      </PageHead>
      {err && <Alert tone="danger">{err}</Alert>}
      <div className="card table-wrap">
        {items === null ? (
          <Empty>Loading…</Empty>
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
                <th>Created</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {items.map((p) => (
                <tr key={p.id}>
                  <td><strong>{p.name}</strong></td>
                  <td><Badge tone="accent">{p.type.toUpperCase()}</Badge></td>
                  <td>{p.enabled ? <Badge tone="ok">enabled</Badge> : <Badge>disabled</Badge>}</td>
                  <td>{p.has_secret ? <Badge tone="ok">stored</Badge> : <span className="muted">none</span>}</td>
                  <td>{fmtTime(p.created_at)}</td>
                  <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
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

function ProviderModal({ existing, onClose, onSaved }: { existing: Provider | null; onClose: () => void; onSaved: () => void }) {
  const [loaded, setLoaded] = useState<Provider | null>(existing && !existing.config ? null : existing)
  const [type, setType] = useState<IdPType>(existing?.type ?? 'oidc')
  const [name, setName] = useState(existing?.name ?? '')
  const [enabled, setEnabled] = useState(existing?.enabled ?? true)
  const [autoProvision, setAutoProvision] = useState(existing?.config?.auto_provision ?? true)
  const [roles, setRoles] = useState<Role[]>(existing?.config?.default_roles ?? ['user'])
  const [mapping, setMapping] = useState(mappingToText(existing?.config?.group_mapping))
  const [oidc, setOidc] = useState<OIDCConfig>(existing?.config?.oidc ?? {})
  const [ldap, setLdap] = useState<LDAPConfig>(existing?.config?.ldap ?? {})
  const [scopes, setScopes] = useState(csv(existing?.config?.oidc?.scopes))
  const [domains, setDomains] = useState(csv(existing?.config?.oidc?.allowed_domains))
  const [groups, setGroups] = useState<Group[]>([])
  const [busy, setBusy] = useState(false)
  const [test, setTest] = useState<{ tone: 'ok' | 'warn' | 'danger'; msg: string } | null>(null)
  const [localErr, setLocalErr] = useState('')

  // Editing: fetch the full (redacted) config, which the list may not carry.
  useEffect(() => {
    if (existing) {
      api.get<Provider>(`/identity-providers/${existing.id}`).then((p) => {
        setLoaded(p)
        setType(p.type)
        setName(p.name)
        setEnabled(p.enabled)
        setAutoProvision(p.config?.auto_provision ?? true)
        setRoles(p.config?.default_roles ?? ['user'])
        setMapping(mappingToText(p.config?.group_mapping))
        setOidc(p.config?.oidc ?? {})
        setLdap(p.config?.ldap ?? {})
        setScopes(csv(p.config?.oidc?.scopes))
        setDomains(csv(p.config?.oidc?.allowed_domains))
      }).catch((e) => setLocalErr(errorMessage(e)))
    }
    api.get<Page<Group>>('/groups').then((g) => setGroups(g.items ?? [])).catch(() => {})
  }, [existing])

  const toggleRole = (r: Role) => setRoles((cur) => (cur.includes(r) ? cur.filter((x) => x !== r) : [...cur, r]))

  const build = (): { body?: Record<string, unknown>; error?: string } => {
    if (!name.trim()) return { error: 'name is required' }
    const { mapping: gm, error } = textToMapping(mapping)
    if (error) return { error }
    const config: IdPConfig = { default_roles: roles, group_mapping: gm, auto_provision: autoProvision }
    if (type === 'oidc') {
      config.oidc = { ...oidc, scopes: fromCsv(scopes), allowed_domains: fromCsv(domains) }
    } else {
      config.ldap = { ...ldap }
    }
    return { body: { name: name.trim(), type, enabled, config } }
  }

  const save = async (e: FormEvent) => {
    e.preventDefault()
    const { body, error } = build()
    if (error) {
      setLocalErr(error)
      return
    }
    setBusy(true)
    setLocalErr('')
    try {
      if (existing) await api.put(`/identity-providers/${existing.id}`, body)
      else await api.post('/identity-providers', body)
      onSaved()
    } catch (err) {
      setLocalErr(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const runTest = async () => {
    if (!existing) return
    setTest(null)
    try {
      const r = await api.post<{ status: string; message?: string }>(`/identity-providers/${existing.id}/test`)
      if (r.status === 'ok') setTest({ tone: 'ok', msg: 'Connection succeeded.' })
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
              <Field label="Groups claim" hint="e.g. groups; empty disables group sync"><input id="oidc-gclaim" value={oidc.groups_claim ?? ''} onChange={(e) => setOidc({ ...oidc, groups_claim: e.target.value })} /></Field>
              <Field label="Allowed email domains" hint="comma separated; empty allows all"><input id="oidc-domains" value={domains} onChange={(e) => setDomains(e.target.value)} /></Field>
            </div>
            <div className="field inline"><input id="oidc-skipmfa" type="checkbox" checked={!!oidc.skip_mfa} onChange={(e) => setOidc({ ...oidc, skip_mfa: e.target.checked })} /><label htmlFor="oidc-skipmfa">Trust the provider's MFA (do not require a Zanskar authenticator)</label></div>
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
        <div className="field inline"><input id="idp-auto" type="checkbox" checked={autoProvision} onChange={(e) => setAutoProvision(e.target.checked)} /><label htmlFor="idp-auto">Create a Zanskar user on first sign-in</label></div>
        <Field label="Default roles for provisioned users">
          <div className="actions">
            {roleOptions.map((r) => (
              <label key={r} style={{ display: 'inline-flex', gap: 4, alignItems: 'center' }}>
                <input type="checkbox" checked={roles.includes(r)} onChange={() => toggleRole(r)} /> {r}
              </label>
            ))}
          </div>
        </Field>
        <Field label="Group mapping" hint='one per line: externalGroupName=zanskarGroupId'>
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
            <button className="btn primary" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>
          </span>
        </div>
      </form>
    </Modal>
  )
}
