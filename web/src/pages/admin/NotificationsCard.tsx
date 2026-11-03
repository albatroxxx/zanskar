import { useCallback, useEffect, useState } from 'react'
import { api, errorMessage } from '../../api/client'
import { fmtTime } from '../../api/format'
import { CopyButton } from '../../components/CopyButton'
import { Alert, Badge, Confirm, Field, FormModal } from '../../components/ui'
import { useSubmit } from '../../components/submit'

/** A notification channel as GET /admin/notifications lists it (ADR 0039). */
export interface NotificationChannel {
  id: string
  name: string
  kind: 'webhook' | 'email'
  events: string[]
  config: { webhook_host?: string; smtp_host?: string; smtp_port?: number; smtp_username?: string; from?: string; to?: string[] }
  enabled: boolean
  has_secret: boolean
  status?: { last_sent_at?: string; last_error?: string; last_error_at?: string }
}

/** The mail server every email channel sends through, as GET /admin/notifications/email-server gives it; never its password. */
export interface EmailServer {
  host: string
  port: number
  username: string
  from: string
  has_password: boolean
  updated_at?: string
}

/** The words for each kind of event a channel can ask for. */
const eventWords: Record<string, string> = {
  access_requested: 'Access requested',
  access_decided: 'Access approved, denied or revoked',
  session_terminated: 'Session ended by an administrator',
  provider_failing: 'Sign-in provider failing its sync',
  recording_lost: 'Recording lost',
  disk_full: 'New sessions refused: disk full',
}

interface Draft {
  name: string
  kind: 'webhook' | 'email'
  events: string[]
  enabled: boolean
  webhook_url: string
  to: string
}

const blank: Draft = { name: '', kind: 'webhook', events: ['access_requested', 'provider_failing'], enabled: true, webhook_url: '', to: '' }

function toDraft(c: NotificationChannel): Draft {
  return { ...blank, name: c.name, kind: c.kind, events: c.events, enabled: c.enabled, to: (c.config.to ?? []).join(', ') }
}

/**
 * NotificationsCard, in Settings, is where an administrator says who hears
 * of what (2026-11-03, idea 3): a signed webhook (Slack's and Mattermost's
 * incoming webhooks show it as it is) or email, each asking for kinds of
 * event. A channel hears what happens from its creation on. Email goes
 * through one mail server, set here once (2026-11-03, later); an email
 * channel names its recipients alone.
 */
export function NotificationsCard() {
  const [items, setItems] = useState<NotificationChannel[] | null>(null)
  // undefined while loading, null when none is set.
  const [server, setServer] = useState<EmailServer | null | undefined>(undefined)
  const [serverForm, setServerForm] = useState(false)
  const [serverTest, setServerTest] = useState<string | null>(null)
  const [removingServer, setRemovingServer] = useState(false)
  const [events, setEvents] = useState<string[]>(Object.keys(eventWords))
  const [err, setErr] = useState('')
  const [notice, setNotice] = useState<{ tone: 'ok' | 'danger'; text: string } | null>(null)
  const [editing, setEditing] = useState<NotificationChannel | 'new' | null>(null)
  const [removing, setRemoving] = useState<NotificationChannel | null>(null)
  const [key, setKey] = useState<{ name: string; key: string } | null>(null)
  const [testing, setTesting] = useState('')

  const load = useCallback(() => {
    api
      .get<{ items: NotificationChannel[]; events: string[] }>('/admin/notifications')
      .then((r) => {
        setItems(r.items ?? [])
        if (r.events?.length) setEvents(r.events)
      })
      .catch((e) => setErr(errorMessage(e)))
    api
      .get<EmailServer | null>('/admin/notifications/email-server')
      .then((s) => setServer(s))
      .catch((e) => setErr(errorMessage(e)))
  }, [])
  useEffect(load, [load])

  const testServer = async (to: string) => {
    setNotice(null)
    try {
      await api.post('/admin/notifications/email-server/test', { to })
      setNotice({ tone: 'ok', text: `Email server: test sent to ${to}.` })
    } catch (e) {
      setNotice({ tone: 'danger', text: `Email server: ${errorMessage(e)}` })
    }
  }

  const test = async (c: NotificationChannel) => {
    setTesting(c.id)
    setNotice(null)
    try {
      await api.post(`/admin/notifications/${c.id}/test`)
      setNotice({ tone: 'ok', text: `${c.name}: test sent.` })
    } catch (e) {
      setNotice({ tone: 'danger', text: `${c.name}: ${errorMessage(e)}` })
    } finally {
      setTesting('')
    }
  }

  return (
    <div className="card" id="settings-notifications">
      <h2>Notifications</h2>
      <p className="muted">Who hears of what, without the console open. Each channel hears what happens from when it is added.</p>
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      {notice && <Alert tone={notice.tone} onDismiss={() => setNotice(null)}>{notice.text}</Alert>}
      {key && (
        <Alert tone="warn" onDismiss={() => setKey(null)}>
          Signing key for {key.name}, shown once: <code className="mono">{key.key}</code> <CopyButton text={key.key} /> The receiver checks X-Zanskar-Signature with it.
        </Alert>
      )}
      <div className="email-server" data-testid="email-server">
        <h3>Email server</h3>
        {server === undefined ? null : server ? (
          <>
            <dl className="kv">
              <dt>Server</dt>
              <dd><span className="mono">{server.host}:{server.port || 587}</span></dd>
              <dt>From</dt>
              <dd>{server.from}</dd>
              <dt>Account</dt>
              <dd>{server.username ? <>{server.username}{server.has_password && <span className="muted"> · password stored</span>}</> : <span className="muted">none</span>}</dd>
            </dl>
            <div className="actions">
              <button type="button" className="btn sm" onClick={() => setServerTest('')}>Test</button>
              <button type="button" className="btn sm" onClick={() => setServerForm(true)}>Edit</button>
              <button type="button" className="btn sm danger" onClick={() => setRemovingServer(true)}>Remove</button>
              {server.updated_at && <span className="muted">Changed {fmtTime(server.updated_at)}</span>}
            </div>
          </>
        ) : (
          <>
            <p className="muted">None: email channels send nothing until one is set.</p>
            <div className="actions">
              <button type="button" className="btn sm" onClick={() => setServerForm(true)}>Set the email server</button>
            </div>
          </>
        )}
      </div>
      <h3>Channels</h3>
      {items === null ? (
        !err && <p className="muted">Loading…</p>
      ) : items.length === 0 ? (
        <p className="muted">No channels yet.</p>
      ) : (
        <table className="notify-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Where</th>
              <th>Tells</th>
              <th>Last</th>
              <th><span className="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            {items.map((c) => (
              <tr key={c.id} className={c.enabled ? undefined : 'off'}>
                <td><strong>{c.name}</strong>{!c.enabled && <> <Badge>off</Badge></>}</td>
                <td>{c.kind === 'webhook' ? <>Webhook · <span className="mono">{c.config.webhook_host}</span></> : <>Email · {(c.config.to ?? []).join(', ')}</>}</td>
                <td>{c.events.length === 0 ? <span className="muted">nothing</span> : c.events.map((e) => eventWords[e] ?? e).join('; ')}</td>
                <td>
                  {c.status?.last_error ? (
                    <span className="sync-error" title={c.status.last_error_at ? fmtTime(c.status.last_error_at) : undefined}>{c.status.last_error}</span>
                  ) : c.status?.last_sent_at ? (
                    fmtTime(c.status.last_sent_at)
                  ) : (
                    <span className="muted">—</span>
                  )}
                </td>
                <td className="actions">
                  <button type="button" className="btn sm" disabled={testing === c.id} onClick={() => void test(c)}>{testing === c.id ? 'Sending…' : 'Test'}</button>
                  <button type="button" className="btn sm" onClick={() => setEditing(c)}>Edit</button>
                  <button type="button" className="btn sm danger" onClick={() => setRemoving(c)}>Remove</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="actions" style={{ marginTop: 12 }}>
        <button type="button" className="btn" onClick={() => setEditing('new')}>Add channel</button>
      </div>
      {serverForm && (
        <EmailServerForm
          existing={server ?? null}
          onClose={() => setServerForm(false)}
          onSaved={(s) => {
            setServer(s)
            setServerForm(false)
          }}
        />
      )}
      {serverTest !== null && (
        <Confirm
          title="Send a test message"
          body={
            <Field label="To">
              <input id="email-server-test-to" type="email" value={serverTest} onChange={(e) => setServerTest(e.target.value)} placeholder="you@example.com" autoFocus />
            </Field>
          }
          confirmLabel="Send"
          onClose={() => setServerTest(null)}
          onConfirm={async () => {
            const to = serverTest
            setServerTest(null)
            await testServer(to)
          }}
        />
      )}
      {removingServer && (
        <Confirm
          title="Remove the email server?"
          body="Email channels send nothing until one is set again."
          confirmLabel="Remove"
          danger
          onClose={() => setRemovingServer(false)}
          onConfirm={async () => {
            await api.del('/admin/notifications/email-server')
            setServer(null)
            setRemovingServer(false)
          }}
        />
      )}
      {editing && (
        <ChannelForm
          existing={editing === 'new' ? null : editing}
          events={events}
          hasServer={!!server}
          onClose={() => setEditing(null)}
          onSaved={(signingKey, name) => {
            setEditing(null)
            if (signingKey) setKey({ name, key: signingKey })
            load()
          }}
          onNewKey={(name, k) => setKey({ name, key: k })}
        />
      )}
      {removing && (
        <Confirm
          title={`Remove ${removing.name}?`}
          body="It is told nothing more."
          confirmLabel="Remove"
          danger
          onClose={() => setRemoving(null)}
          onConfirm={async () => {
            await api.del(`/admin/notifications/${removing.id}`)
            setRemoving(null)
            load()
          }}
        />
      )}
    </div>
  )
}

function ChannelForm({ existing, events, hasServer, onClose, onSaved, onNewKey }: {
  existing: NotificationChannel | null
  events: string[]
  hasServer: boolean
  onClose: () => void
  onSaved: (signingKey: string | undefined, name: string) => void
  onNewKey: (name: string, key: string) => void
}) {
  const [d, setD] = useState<Draft>(existing ? toDraft(existing) : blank)
  const { busy, err, submit } = useSubmit()
  const set = (k: keyof Draft) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setD({ ...d, [k]: e.target.value })
  const toggle = (ev: string) => setD({ ...d, events: d.events.includes(ev) ? d.events.filter((x) => x !== ev) : [...d.events, ev] })
  const save = () =>
    submit(async () => {
      const body = {
        name: d.name, kind: d.kind, events: d.events, enabled: d.enabled,
        webhook_url: d.webhook_url || undefined,
        to: d.to.split(/[,\s]+/).filter(Boolean),
      }
      if (existing) {
        await api.put(`/admin/notifications/${existing.id}`, body)
        onSaved(undefined, d.name)
      } else {
        const r = await api.post<{ signing_key?: string }>('/admin/notifications', body)
        onSaved(r.signing_key, d.name)
      }
    })
  return (
    <FormModal title={existing ? `Edit ${existing.name}` : 'Add channel'} err={err} busy={busy} submitLabel={existing ? 'Save' : 'Add'} onSubmit={() => void save()} onClose={onClose} width={560}>
      <Field label="Name">
        <input value={d.name} onChange={set('name')} required maxLength={64} autoFocus />
      </Field>
      {!existing && (
        <Field label="Kind">
          <select value={d.kind} onChange={set('kind')}>
            <option value="webhook">Webhook (signed JSON; Slack, Mattermost)</option>
            <option value="email">Email</option>
          </select>
        </Field>
      )}
      {d.kind === 'webhook' ? (
        <Field label="Webhook URL" hint={existing?.has_secret ? 'Stored; type a new one to replace it' : 'https only'}>
          <input type="url" value={d.webhook_url} onChange={set('webhook_url')} placeholder={existing?.has_secret ? '••••••••' : 'https://hooks.slack.com/services/…'} required={!existing} />
        </Field>
      ) : (
        <>
          <Field label="To" hint="Addresses, separated by commas; sent through the email server">
            <input value={d.to} onChange={set('to')} placeholder="ops@example.com, security@example.com" required />
          </Field>
          {!hasServer && <p className="muted">No email server is set yet: this channel sends nothing until one is.</p>}
        </>
      )}
      <fieldset className="notify-events">
        <legend>Tell it about</legend>
        {events.map((ev) => (
          <label key={ev} className="field inline">
            <input type="checkbox" checked={d.events.includes(ev)} onChange={() => toggle(ev)} /> {eventWords[ev] ?? ev}
          </label>
        ))}
      </fieldset>
      <label className="field inline">
        <input type="checkbox" checked={d.enabled} onChange={(e) => setD({ ...d, enabled: e.target.checked })} /> On
      </label>
      {existing?.kind === 'webhook' && (
        <p className="muted">
          <button
            type="button"
            className="btn sm ghost"
            onClick={() =>
              void api.post<{ signing_key: string }>(`/admin/notifications/${existing.id}/signing-key`).then((r) => onNewKey(existing.name, r.signing_key))
            }
          >
            New signing key
          </button>{' '}
          The old one stops verifying at once.
        </p>
      )}
    </FormModal>
  )
}

/** EmailServerForm sets the mail server: the host and port, an account (its password kept when the field is left empty), and the sender. */
function EmailServerForm({ existing, onClose, onSaved }: { existing: EmailServer | null; onClose: () => void; onSaved: (s: EmailServer) => void }) {
  const [d, setD] = useState({ host: existing?.host ?? '', port: existing?.port ? String(existing.port) : '', username: existing?.username ?? '', password: '', from: existing?.from ?? '' })
  const { busy, err, submit } = useSubmit()
  const set = (k: keyof typeof d) => (e: React.ChangeEvent<HTMLInputElement>) => setD({ ...d, [k]: e.target.value })
  const save = () =>
    submit(async () => {
      const s = await api.put<EmailServer>('/admin/notifications/email-server', {
        host: d.host, port: d.port ? Number(d.port) : 0, username: d.username, password: d.password || undefined, from: d.from,
      })
      onSaved(s)
    })
  return (
    <FormModal title="Email server" err={err} busy={busy} submitLabel="Save" onSubmit={() => void save()} onClose={onClose} width={560}>
      <div className="form-grid">
        <Field label="Server">
          <input id="email-server-host" value={d.host} onChange={set('host')} placeholder="smtp.example.com" required autoFocus />
        </Field>
        <Field label="Port" hint="587 STARTTLS, 465 TLS">
          <input id="email-server-port" inputMode="numeric" value={d.port} onChange={set('port')} placeholder="587" />
        </Field>
        <Field label="Username" hint="empty for none">
          <input id="email-server-username" value={d.username} onChange={set('username')} autoComplete="off" />
        </Field>
        <Field label="Password" hint={existing?.has_password ? 'Stored; type to replace' : undefined}>
          <input id="email-server-password" type="password" value={d.password} onChange={set('password')} autoComplete="new-password" />
        </Field>
      </div>
      <Field label="From">
        <input id="email-server-from" type="email" value={d.from} onChange={set('from')} placeholder="zanskar@example.com" required />
      </Field>
    </FormModal>
  )
}
