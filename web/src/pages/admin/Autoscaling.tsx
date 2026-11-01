import { useEffect, useState, type FormEvent } from 'react'
import { api, errorMessage } from '../../api/client'
import { fmtTime, protocolName } from '../../api/format'
import type { AsgAccessTest, AsgIAMDocs, AsgInstance, AutoscalingGroup, AwsIdentity, Credential, OSFamily, Protocol } from '../../api/types'
import { Alert, Badge, Confirm, Empty, Field, Modal, PageHead, Tags } from '../../components/ui'
import { DeleteAsset } from './DeleteAsset'
import { protocols, useList, type PortProtocol } from './lib'
import { TagEditor } from '../../components/TagEditor'
import { rowsToTags, tagRows, type TagRow } from '../../components/tags'
import { CredentialBindings, CredentialSelect, shownValue, type BindingChange } from './Bindings'
import { StateIcon } from '../../components/icons'

interface SyncSummary { Seen: number; Healthy: number; Joined: number; Left: number; Retired: number; HostKeyMismatches: number }
interface SyncResponse { summary: SyncSummary; group: AutoscalingGroup; error?: string }

const defaultPorts: Record<PortProtocol, number> = { ssh: 22, rdp: 3389, vnc: 5900, winrm: 5986 }

export function Autoscaling() {
  const { items, err, setErr, reload } = useList<AutoscalingGroup>('/autoscaling-groups')
  const creds = useList<Credential>('/credentials')
  const [adding, setAdding] = useState(false)
  const [open, setOpen] = useState<AutoscalingGroup | null>(null)
  const [created, setCreated] = useState<AutoscalingGroup | null>(null)

  return (
    <>
      <PageHead title="Autoscaling groups">
        <button className="btn primary" onClick={() => setAdding(true)}>Enroll group</button>
      </PageHead>
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      <IdentityCard />
      <div className="card table-wrap">
        {items === null ? (
          err ? null : <Empty>Loading…</Empty>
        ) : items.length === 0 ? (
          <Empty>No autoscaling groups enrolled yet.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Region</th>
                <th>Cloud group</th>
                <th>OS</th>
                <th>Healthy</th>
                <th>Last synced</th>
                <th>Status</th>
                <th><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {items.map((g) => (
                <tr key={g.id}>
                  <td><strong>{g.name}</strong></td>
                  <td className="mono">{g.region}</td>
                  <td className="mono">{g.external_name}</td>
                  <td>{g.os_family}</td>
                  <td>
                    <Badge tone={(g.healthy_count ?? 0) > 0 ? 'ok' : (g.instance_count ?? 0) > 0 ? 'warn' : undefined}>
                      {g.healthy_count ?? 0} / {g.instance_count ?? 0}
                    </Badge>
                  </td>
                  <td className="muted">
                    {g.last_synced_at ? fmtTime(g.last_synced_at) : 'never'}{' '}
                    {g.last_error && <Badge tone="danger">{g.last_error.length > 40 ? g.last_error.slice(0, 40) + '…' : g.last_error}</Badge>}
                  </td>
                  <td>{g.status === 'disabled' ? <StateIcon state="unknown" label="Disabled" /> : <StateIcon state="ok" label="Active" />}</td>
                  <td><button className="btn sm" onClick={() => setOpen(g)}>Manage</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {adding && (
        <GroupForm
          credentials={creds.items ?? []}
          onClose={() => setAdding(false)}
          onSaved={(g) => {
            setAdding(false)
            setCreated(g)
            void reload()
          }}
        />
      )}
      {created && <IAMPanel group={created} onClose={() => setCreated(null)} />}
      {open && (
        <GroupDetail
          group={open}
          credentials={creds.items ?? []}
          onClose={() => setOpen(null)}
          onChanged={(g) => {
            setOpen(g)
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

interface FormState {
  name: string
  region: string
  external_name: string
  role_arn: string
  os_family: OSFamily
  caps: Record<Protocol, boolean>
  ports: Record<Protocol, string>
  address_preference: 'private' | 'public'
  poll: string
  tags: TagRow[]
  credentials: Record<Protocol, string>
}

/** initialForm is a group as the form edits it. Given the credential list,
 *  a binding to the shared user-supplied row reads as that choice. */
function initialForm(g?: AutoscalingGroup, all: Credential[] = []): FormState {
  const caps = { ssh: false, rdp: false, vnc: false, winrm: false } as Record<Protocol, boolean>
  for (const c of g?.capabilities ?? ['ssh']) caps[c] = true
  const ports = { ssh: '', rdp: '', vnc: '', winrm: '' } as Record<Protocol, string>
  for (const p of protocols) if (g?.ports[p]) ports[p] = String(g.ports[p])
  const credentials = { ssh: '', rdp: '', vnc: '', winrm: '' } as Record<Protocol, string>
  for (const p of protocols) credentials[p] = shownValue(g?.credentials[p], all)
  return {
    name: g?.name ?? '',
    region: g?.region ?? '',
    external_name: g?.external_name ?? '',
    role_arn: g?.role_arn ?? '',
    os_family: g?.os_family ?? 'linux',
    caps,
    ports,
    address_preference: g?.address_preference ?? 'private',
    poll: String(g?.poll_interval_seconds ?? 30),
    tags: tagRows(g?.tags),
    credentials,
  }
}

function toBody(f: FormState, status: string, extra: Record<string, unknown> = {}) {
  const { tags, error } = rowsToTags(f.tags)
  if (error) throw new Error(error)
  const capabilities = protocols.filter((p) => f.caps[p])
  const ports: Partial<Record<Protocol, number>> = {}
  for (const p of protocols) if (f.ports[p].trim()) ports[p] = Number(f.ports[p])
  const credentials: Partial<Record<Protocol, string>> = {}
  for (const p of protocols) if (f.credentials[p]) credentials[p] = f.credentials[p]
  return {
    name: f.name.trim(),
    region: f.region.trim(),
    external_name: f.external_name.trim(),
    role_arn: f.role_arn.trim(),
    os_family: f.os_family,
    ports,
    capabilities,
    address_preference: f.address_preference,
    poll_interval_seconds: Number(f.poll),
    tags,
    status,
    credentials,
    ...extra,
  }
}

function GroupForm({ initial, credentials, onClose, onSaved }: { initial?: AutoscalingGroup; credentials: Credential[]; onClose: () => void; onSaved: (g: AutoscalingGroup) => void }) {
  const [f, setF] = useState<FormState>(() => initialForm(initial, credentials))
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const up = (patch: Partial<FormState>) => setF((s) => ({ ...s, ...patch }))
  // Guided enrolment (ADR 0023): the IAM documents are previewed before the
  // group exists, with an ExternalId minted for it; the role the customer
  // creates from them is tested before saving; the saved group carries that
  // same ExternalId.
  const [docs, setDocs] = useState<AsgIAMDocs | null>(null)
  const [docsBusy, setDocsBusy] = useState(false)
  const [test, setTest] = useState<AsgAccessTest | null>(null)
  const [testing, setTesting] = useState(false)
  const canPreview = !initial && f.region.trim() !== '' && f.external_name.trim() !== ''
  const preview = async () => {
    setErr('')
    setDocsBusy(true)
    try {
      setDocs(await api.post<AsgIAMDocs>('/autoscaling-groups/iam-preview', { region: f.region.trim(), external_name: f.external_name.trim(), external_id: docs?.external_id ?? '' }))
    } catch (ex) {
      setErr(errorMessage(ex))
    } finally {
      setDocsBusy(false)
    }
  }
  const runTest = async () => {
    setErr('')
    setTesting(true)
    setTest(null)
    try {
      setTest(await api.post<AsgAccessTest>('/autoscaling-groups/test', { region: f.region.trim(), external_name: f.external_name.trim(), role_arn: f.role_arn.trim(), external_id: docs?.external_id ?? '' }))
    } catch (ex) {
      setErr(errorMessage(ex))
    } finally {
      setTesting(false)
    }
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setErr('')
    let body: Record<string, unknown>
    try {
      body = toBody(f, initial?.status ?? 'active', docs && !initial ? { external_id: docs.external_id } : {})
    } catch (ex) {
      setErr(errorMessage(ex))
      return
    }
    if (!protocols.some((p) => f.caps[p])) return setErr('pick at least one capability')
    setBusy(true)
    try {
      const g = initial ? await api.put<AutoscalingGroup>(`/autoscaling-groups/${initial.id}`, body) : await api.post<AutoscalingGroup>('/autoscaling-groups', body)
      onSaved(g)
    } catch (ex) {
      setErr(errorMessage(ex))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal title={initial ? `Edit ${initial.name}` : 'Enroll autoscaling group'} onClose={onClose} width={680}>
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      <form onSubmit={submit}>
        <div className="form-grid">
          <Field label="Name">
            <input id="asg-name" value={f.name} onChange={(e) => up({ name: e.target.value })} required autoFocus />
          </Field>
          <Field label="Region">
            <input id="asg-region" value={f.region} onChange={(e) => up({ region: e.target.value })} placeholder="ap-south-1" required />
          </Field>
          <Field label="Auto Scaling group name">
            <input id="asg-external" value={f.external_name} onChange={(e) => up({ external_name: e.target.value })} required />
          </Field>
          {initial && (
            <Field label="Role ARN" hint="Cross-account role Zanskar assumes">
              <input id="asg-role" className="mono" value={f.role_arn} onChange={(e) => up({ role_arn: e.target.value })} placeholder="arn:aws:iam::123456789012:role/zanskar" required />
            </Field>
          )}
          <Field label="Operating system">
            <select id="asg-os" value={f.os_family} onChange={(e) => up({ os_family: e.target.value as OSFamily })}>
              <option value="linux">Linux</option>
              <option value="windows">Windows</option>
              <option value="other">Other</option>
            </select>
          </Field>
          <Field label="Connect to" hint="Which address the gateway dials">
            <select id="asg-addr" value={f.address_preference} onChange={(e) => up({ address_preference: e.target.value as 'private' | 'public' })}>
              <option value="private">Private IP</option>
              <option value="public">Public IP</option>
            </select>
          </Field>
          <Field label="Poll interval (seconds)" hint="10 to 3600">
            <input id="asg-poll" type="number" min={10} max={3600} value={f.poll} onChange={(e) => up({ poll: e.target.value })} />
          </Field>
        </div>
        <h2>Capabilities</h2>
        {f.os_family === 'windows' && (
          <Alert tone="warn">
            Bake the HTTPS WinRM listener (5986) and the domain join into the image. The WinRM credential must be a local administrator.
          </Alert>
        )}
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Protocol</th>
                <th>Port</th>
                <th>Credential</th>
              </tr>
            </thead>
            <tbody>
              {protocols.map((p) => (
                <tr key={p}>
                  <td>
                    <div className="field inline" style={{ margin: 0 }}>
                      <input id={`asg-cap-${p}`} aria-label={protocolName(p)} type="checkbox" checked={f.caps[p]} onChange={(e) => up({ caps: { ...f.caps, [p]: e.target.checked } })} />
                      <label htmlFor={`asg-cap-${p}`}>{protocolName(p)}</label>
                    </div>
                  </td>
                  <td>
                    <input id={`asg-port-${p}`} aria-label={protocolName(p) + ' port'} type="number" min={1} max={65535} placeholder={String(defaultPorts[p])} value={f.ports[p]} disabled={!f.caps[p]} onChange={(e) => up({ ports: { ...f.ports, [p]: e.target.value } })} style={{ width: 110 }} />
                  </td>
                  <td>
                    <CredentialSelect id={`asg-cred-${p}`} protocol={p} value={f.credentials[p]} credentials={credentials} disabled={!f.caps[p]} onChange={(v) => up({ credentials: { ...f.credentials, [p]: v } })} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <Field label="Tags">
          <TagEditor idPrefix="asg-tag" rows={f.tags} onChange={(tags) => up({ tags })} />
        </Field>
        {!initial && (
          <>
            <h2>Access from this gateway</h2>
            {!docs ? (
              <div className="actions">
                <button type="button" className="btn" disabled={!canPreview || docsBusy} onClick={() => void preview()} title={canPreview ? '' : 'fill in the region and the group name first'}>{docsBusy ? 'Preparing…' : '1. Show IAM setup'}</button>
              </div>
            ) : (
              <IAMDocsView docs={docs} onRefresh={() => void preview()} />
            )}
            <div className="form-grid" style={{ marginTop: 12 }}>
              <Field label="2. Role ARN">
                <input id="asg-role" className="mono" value={f.role_arn} onChange={(e) => up({ role_arn: e.target.value })} placeholder="arn:aws:iam::123456789012:role/zanskar-web" required />
              </Field>
            </div>
            <div className="actions">
              <button type="button" className="btn" disabled={testing || !docs || !f.role_arn.trim()} onClick={() => void runTest()} title={docs ? '' : 'show the IAM setup first: the test needs its ExternalId'}>{testing ? 'Testing…' : '3. Test access'}</button>
              {test && <AccessTestResult result={test} />}
            </div>
          </>
        )}
        <div className="actions">
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn primary" disabled={busy}>{initial ? 'Save' : test?.ok ? 'Enroll' : 'Enroll without a passing test'}</button>
        </div>
      </form>
    </Modal>
  )
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [done, setDone] = useState(false)
  return (
    <button
      type="button"
      className="btn sm"
      onClick={() => {
        void navigator.clipboard?.writeText(text).then(() => {
          setDone(true)
          setTimeout(() => setDone(false), 1500)
        })
      }}
    >
      {done ? 'Copied' : label}
    </button>
  )
}

function sourceLabel(source: AwsIdentity['source']) {
  return source === 'environment' ? 'from ZANSKAR_AWS_GATEWAY_PRINCIPAL' : source === 'detected' ? 'detected from the role this gateway runs as' : 'unknown'
}

/**
 * IdentityCard says which AWS principal this gateway is, since every trust
 * policy must name it (ADR 0023). Detection happens once at start; Refresh
 * repeats it, for a gateway that was given a role after it started.
 */
function IdentityCard() {
  const [id, setId] = useState<AwsIdentity | null>(null)
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    api.get<AwsIdentity>('/admin/aws/identity').then(setId).catch(() => setId(null))
  }, [])
  if (!id) return null
  // A gateway that simply does not live on AWS has nothing to warn about:
  // the card appears only with an identity to show, or on AWS compute where
  // a missing role is a real misconfiguration. The enroll flow still says
  // what to set when a trust policy actually needs a principal (ADR 0023).
  if (!id.principal && id.platform !== 'aws') return null
  const refresh = async () => {
    setBusy(true)
    try {
      setId(await api.post<AwsIdentity>('/admin/aws/identity/refresh'))
    } catch {
      /* the card keeps what it had */
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="card" style={{ marginBottom: 12 }}>
      {id.principal ? (
        <p style={{ margin: 0 }}>
          This gateway is <span className="mono">{id.principal}</span> <span className="muted">({sourceLabel(id.source)})</span>. Roles you create for autoscaling groups trust that principal.
          {id.source === 'detected' && <button type="button" className="btn sm" style={{ marginLeft: 8 }} disabled={busy} onClick={() => void refresh()}>{busy ? 'Checking…' : 'Refresh'}</button>}
        </p>
      ) : (
        <>
          <p style={{ margin: 0 }}>
            <Badge tone="warn">AWS identity unknown</Badge> Give the gateway an instance profile (or IRSA), or set <code>ZANSKAR_AWS_GATEWAY_PRINCIPAL</code>, then restart.
            <button type="button" className="btn sm" style={{ marginLeft: 8 }} disabled={busy} onClick={() => void refresh()}>{busy ? 'Checking…' : 'Check again'}</button>
          </p>
          {id.error && <p className="muted" style={{ margin: '6px 0 0' }}>{id.error}</p>}
        </>
      )}
    </div>
  )
}

/** IAMDocsView renders the documents for one group: the real principal or an explanation, never a placeholder. */
function IAMDocsView({ docs, onRefresh }: { docs: AsgIAMDocs; onRefresh?: () => void }) {
  return (
    <>
      <Field label="ExternalId">
        <div className="actions">
          <code style={{ wordBreak: 'break-all' }}>{docs.external_id}</code>
          <CopyButton text={docs.external_id} label="Copy" />
        </div>
      </Field>
      {docs.trust_policy ? (
        <>
          <p className="muted" style={{ marginTop: 0 }}>
            The role trusts <span className="mono">{docs.gateway_principal}</span> ({sourceLabel(docs.principal_source)}). Create it with the script or the template, or paste the two policies by hand.
          </p>
          <details open>
            <summary>Create the role with the AWS CLI</summary>
            <textarea id="iam-cli" readOnly value={docs.cli ?? ''} className="mono" style={{ minHeight: 220, marginTop: 6 }} />
            <div className="actions"><CopyButton text={docs.cli ?? ''} label="Copy script" /></div>
          </details>
          <details>
            <summary>…or as a CloudFormation template</summary>
            <textarea id="iam-cfn" readOnly value={docs.cloudformation ?? ''} className="mono" style={{ minHeight: 220, marginTop: 6 }} />
            <div className="actions"><CopyButton text={docs.cloudformation ?? ''} label="Copy template" /></div>
          </details>
          <details>
            <summary>…or the two policy documents</summary>
            <Field label="Trust policy (on the role)">
              <textarea id="iam-trust" readOnly value={docs.trust_policy} style={{ minHeight: 160 }} />
              <div className="actions"><CopyButton text={docs.trust_policy} label="Copy trust policy" /></div>
            </Field>
            <Field label="Permissions policy (attach to the role)">
              <textarea id="iam-perms" readOnly value={docs.permissions_policy} style={{ minHeight: 200 }} />
              <div className="actions"><CopyButton text={docs.permissions_policy} label="Copy permissions policy" /></div>
            </Field>
          </details>
        </>
      ) : (
        <>
          <Alert tone="warn">
            Gateway principal unknown. Give the gateway an AWS role (instance profile or IRSA), or set <code>ZANSKAR_AWS_GATEWAY_PRINCIPAL</code>, then restart.
            {docs.principal_error && <div className="muted" style={{ marginTop: 6 }}>{docs.principal_error}</div>}
            {onRefresh && <div style={{ marginTop: 6 }}><button type="button" className="btn sm" onClick={onRefresh}>Check again</button></div>}
          </Alert>
          <Field label="Permissions policy (attach to the role once it exists)">
            <textarea id="iam-perms" readOnly value={docs.permissions_policy} style={{ minHeight: 200 }} />
            <div className="actions"><CopyButton text={docs.permissions_policy} label="Copy permissions policy" /></div>
          </Field>
        </>
      )}
    </>
  )
}

/** AccessTestResult names the stage that failed so the fix is obvious. */
function AccessTestResult({ result }: { result: AsgAccessTest }) {
  if (result.ok) return <Badge tone="ok">role works: group found, {result.instance_count} instance{result.instance_count === 1 ? '' : 's'}</Badge>
  const what = result.stage === 'assume' ? "the role could not be assumed: check the trust policy names this gateway and carries this ExternalId, and that the gateway's own role may call sts:AssumeRole on it" : result.stage === 'describe' ? 'the role was assumed but cannot describe the group: attach the permissions policy' : result.stage === 'group' ? 'the role works, but no group by that name exists in that region' : 'test failed'
  return <span><Badge tone="danger">{what}</Badge>{result.error && <span className="muted" style={{ marginLeft: 6 }}>{result.error}</span>}</span>
}

function IAMPanel({ group, onClose }: { group: AutoscalingGroup; onClose: () => void }) {
  const [docs, setDocs] = useState<AsgIAMDocs | null>(null)
  const [err, setErr] = useState('')
  const load = () => {
    api
      .get<AsgIAMDocs>(`/autoscaling-groups/${group.id}/iam`)
      .then(setDocs)
      .catch((e) => setErr(errorMessage(e)))
  }
  useEffect(load, [group.id])
  return (
    <Modal title={`IAM setup for ${group.name}`} onClose={onClose} width={760}>
      <p className="muted" style={{ marginTop: 0 }}>
        For the role <span className="mono">{group.role_arn}</span>. After changing anything here, use <strong>Test access</strong> on the group.
      </p>
      {err && <Alert tone="danger">{err}</Alert>}
      {docs ? <IAMDocsView docs={docs} onRefresh={load} /> : !err && <Empty>Loading…</Empty>}
      <div className="actions">
        <button className="btn primary" onClick={onClose}>Done</button>
      </div>
    </Modal>
  )
}

function healthBadge(v: string | undefined, good: string) {
  if (!v) return <span className="muted">—</span>
  return <Badge tone={v === good ? 'ok' : v === 'unknown' ? undefined : 'warn'}>{v}</Badge>
}

function GroupDetail({ group, credentials, onClose, onChanged, onDeleted }: { group: AutoscalingGroup; credentials: Credential[]; onClose: () => void; onChanged: (g: AutoscalingGroup) => void; onDeleted: () => void; onError: (m: string) => void }) {
  const [g, setG] = useState(group)
  const [instances, setInstances] = useState<AsgInstance[] | null>(null)
  const [showAll, setShowAll] = useState(false)
  const [editing, setEditing] = useState(false)
  const [iam, setIam] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [confirmRotate, setConfirmRotate] = useState(false)
  const [syncing, setSyncing] = useState(false)
  const [testing, setTesting] = useState(false)
  const [toggling, setToggling] = useState(false)
  const [accessTest, setAccessTest] = useState<AsgAccessTest | null>(null)
  const [summary, setSummary] = useState<SyncResponse | null>(null)
  const [err, setErr] = useState('')

  const loadInstances = (all: boolean) =>
    api
      .get<{ items: AsgInstance[] }>(`/autoscaling-groups/${g.id}/instances${all ? '?all=true' : ''}`)
      .then((p) => setInstances(p.items ?? []))
      .catch((e) => setErr(errorMessage(e)))

  useEffect(() => {
    void loadInstances(showAll)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [g.id, showAll])

  const update = (next: AutoscalingGroup) => {
    setG(next)
    onChanged(next)
  }

  const testAccess = async () => {
    setErr('')
    setTesting(true)
    setAccessTest(null)
    try {
      setAccessTest(await api.post<AsgAccessTest>(`/autoscaling-groups/${g.id}/test`))
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setTesting(false)
    }
  }
  const sync = async () => {
    setSyncing(true)
    setErr('')
    try {
      const res = await api.post<SyncResponse>(`/autoscaling-groups/${g.id}/sync`)
      setSummary(res)
      if (res.group) update(res.group)
      await loadInstances(showAll)
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setSyncing(false)
    }
  }

  // Disable and Enable are one button, so a second click undoes the first.
  // It is off while the change is in flight, and the second click of a
  // double-click is ignored: on a quick network the first change has
  // already answered when it lands, and the button reads Enable by then.
  const toggleStatus = async (click: { detail: number }) => {
    if (click.detail > 1) return
    setToggling(true)
    try {
      const f = initialForm(g)
      const body = toBody(f, g.status === 'active' ? 'disabled' : 'active')
      update(await api.put<AutoscalingGroup>(`/autoscaling-groups/${g.id}`, body))
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setToggling(false)
    }
  }

  // Applied on Save only, one protocol at a time so each change leaves its
  // own audit event; the drawer shows the group as the API last returned it.
  const saveBindings = async (changes: BindingChange[]) => {
    setErr('')
    let latest = g
    for (const { protocol, credential_id } of changes) {
      if (credential_id) {
        latest = await api.put<AutoscalingGroup>(`/autoscaling-groups/${g.id}/credentials/${protocol}`, { credential_id })
      } else {
        await api.del(`/autoscaling-groups/${g.id}/credentials/${protocol}`)
        latest = await api.get<AutoscalingGroup>(`/autoscaling-groups/${g.id}`)
      }
    }
    update(latest)
  }

  return (
    <Modal title={g.name} onClose={onClose} width={900}>
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      <div className="actions" style={{ marginBottom: 12 }}>
        <button className="btn primary" disabled={syncing} onClick={() => void sync()}>{syncing ? 'Syncing…' : 'Sync now'}</button>
        <button className="btn" disabled={testing} onClick={() => void testAccess()}>{testing ? 'Testing…' : 'Test access'}</button>
        <button className="btn" onClick={() => setEditing(true)}>Edit</button>
        <button className="btn" onClick={() => setIam(true)}>IAM setup</button>
        <button className="btn" onClick={() => setConfirmRotate(true)}>Rotate ExternalId</button>
        <button className="btn" disabled={toggling} onClick={(e) => void toggleStatus(e)}>{g.status === 'active' ? (toggling ? 'Disabling…' : 'Disable') : toggling ? 'Enabling…' : 'Enable'}</button>
        <button className="btn ghost" onClick={onClose}>Close</button>
        <button className="btn danger" onClick={() => setConfirmDelete(true)}>Delete</button>
      </div>
      {accessTest && (
        <Alert tone={accessTest.ok ? 'ok' : 'danger'} onDismiss={() => setAccessTest(null)}>
          <AccessTestResult result={accessTest} />
        </Alert>
      )}
      {summary && (
        <Alert tone={summary.error ? 'danger' : 'ok'} onDismiss={() => setSummary(null)}>
          {summary.error
            ? `Sync failed: ${summary.error}`
            : `Sync complete: ${summary.summary.Seen} seen, ${summary.summary.Healthy} healthy, ${summary.summary.Joined} joined, ${summary.summary.Left} left, ${summary.summary.Retired} retired${summary.summary.HostKeyMismatches ? `, ${summary.summary.HostKeyMismatches} host key mismatch` : ''}`}
        </Alert>
      )}
      <dl className="kv">
        <dt>Region</dt><dd className="mono">{g.region}</dd>
        <dt>Cloud group</dt><dd className="mono">{g.external_name}</dd>
        <dt>Role</dt><dd className="mono">{g.role_arn}</dd>
        <dt>ExternalId</dt><dd className="mono">{g.external_id}</dd>
        <dt>OS</dt><dd>{g.os_family}</dd>
        <dt>Connect to</dt><dd>{g.address_preference} IP</dd>
        <dt>Poll</dt><dd>every {g.poll_interval_seconds}s</dd>
        <dt>Tags</dt><dd><Tags tags={g.tags} /></dd>
        <dt>Last synced</dt><dd>{g.last_synced_at ? fmtTime(g.last_synced_at) : 'never'}{g.last_error && <> · <Badge tone="danger">{g.last_error}</Badge></>}</dd>
      </dl>
      <h2 style={{ marginTop: 18 }}>Credentials per protocol</h2>
      <CredentialBindings
        slots={g.capabilities.map((p) => ({ protocol: p, label: protocolName(p) }))}
        current={g.credentials}
        credentials={credentials}
        onSave={saveBindings}
        onError={setErr}
      />
      <div className="page-head" style={{ marginTop: 18, marginBottom: 8 }}>
        <h2>Instances</h2>
        <div className="field inline" style={{ margin: 0 }}>
          <input id="asg-show-all" type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} />
          <label htmlFor="asg-show-all">Show terminated</label>
        </div>
      </div>
      <div className="table-wrap">
        {instances === null ? (
          <Empty>Loading…</Empty>
        ) : instances.length === 0 ? (
          <Empty>No instances seen yet. Sync to poll the cloud.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Instance</th>
                <th>AZ</th>
                <th>Private / public IP</th>
                <th>Lifecycle</th>
                <th>LB</th>
                <th>Probe</th>
                <th>Host key</th>
                <th>Launched</th>
                <th>Healthy</th>
              </tr>
            </thead>
            <tbody>
              {instances.map((i) => (
                <tr key={i.id}>
                  <td className="mono">{i.instance_id}</td>
                  <td className="mono">{i.availability_zone ?? '—'}</td>
                  <td className="mono">{i.private_ip ?? '—'}{i.public_ip ? ` / ${i.public_ip}` : ''}</td>
                  <td>{healthBadge(i.lifecycle_state, 'InService')}</td>
                  <td>{healthBadge(i.lb_health, 'healthy')}</td>
                  <td>{healthBadge(i.probe_health, 'healthy')}</td>
                  <td>
                    {i.host_key_source === 'console' ? <StateIcon state="ok" label="Host key pinned from the console" /> : i.host_key_source === 'tofu' ? <StateIcon state="warn" label="Trust on first use — not pinned yet" /> : <StateIcon state="unknown" label="No host key" />}
                  </td>
                  <td className="muted">{i.launched_at ? fmtTime(i.launched_at) : '—'}</td>
                  <td>{i.terminated_at ? <StateIcon state="unknown" label="Terminated" /> : i.healthy ? <StateIcon state="ok" label="Healthy" /> : <StateIcon state="danger" label="Unhealthy" />}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {editing && (
        <GroupForm
          initial={g}
          credentials={credentials}
          onClose={() => setEditing(false)}
          onSaved={(next) => {
            setEditing(false)
            update(next)
          }}
        />
      )}
      {iam && <IAMPanel group={g} onClose={() => setIam(false)} />}
      {confirmRotate && (
        <Confirm
          title="Rotate ExternalId?"
          body={<p>Update the role's trust policy before the next sync.</p>}
          confirmLabel="Rotate"
          danger
          onClose={() => setConfirmRotate(false)}
          onConfirm={async () => {
            const body = toBody(initialForm(g), g.status, { rotate_external_id: true })
            update(await api.put<AutoscalingGroup>(`/autoscaling-groups/${g.id}`, body))
            setIam(true)
          }}
        />
      )}
      {confirmDelete && <DeleteAsset name={g.name} path={`/autoscaling-groups/${g.id}`} onClose={() => setConfirmDelete(false)} onDeleted={onDeleted} />}
    </Modal>
  )
}
