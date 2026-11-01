// A session in a tab of its own (ADR 0038): the links the access portal
// starts sessions from, the record that says one of them was just clicked,
// and the page in the new tab that connects.

import { useEffect, useRef, useState, type ChangeEvent, type CSSProperties, type ReactNode } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { api, ApiError, errorMessage } from '../../api/client'
import { protocolName } from '../../api/format'
import type { ConnectResponse, Page, Protocol, ReachableTarget } from '../../api/types'
import { useTitle } from '../../components/title'
import { Alert, Empty, Field, Modal, PageHead } from '../../components/ui'
import { connectHref, parseIntent, recordIntent, takeIntent, type ConnectIntent } from './intent'

/** Body of POST /connect: exactly one of target_id, asg_id, asg_instance_id. */
export interface ConnectBody {
  target_id?: string
  asg_id?: string
  asg_instance_id?: string
  protocol: Protocol
  /** The user's own login, for a slot that asks for it: a password, or over
   *  SSH their own private key with its passphrase when it has one. */
  credential?: { username: string; password?: string; private_key?: string; private_key_passphrase?: string }
}

// What each page load at /connect found, by history entry: React may run a
// state initialiser twice (StrictMode), and the second run must not find the
// record gone and decide nobody clicked.
const taken = new Map<string, boolean>()

function takeOnce(entry: string, href: string): boolean {
  let found = taken.get(entry)
  if (found === undefined) {
    found = takeIntent(href)
    taken.set(entry, found)
  }
  return found
}

/** SessionLink starts a session in a tab of its own: a plain link, so a
 *  click, a Ctrl or ⌘ click and a middle click all open one. The click (or
 *  the middle button's auxclick) leaves the record the new tab looks for. */
export function SessionLink({ intent, className, label, title, style, children }: { intent: ConnectIntent; className: string; label: string; title?: string; style?: CSSProperties; children: ReactNode }) {
  const href = connectHref(intent)
  const record = () => recordIntent(href)
  return (
    <a
      className={className}
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      aria-label={`${label}, opens in a new tab`}
      title={title}
      style={style}
      onClick={record}
      onAuxClick={(e) => {
        if (e.button === 1) record()
      }}
    >
      {children}
    </a>
  )
}

/** The largest key file the prompt reads; the gateway refuses more. */
const maxKeyBytes = 16 << 10

const noCred = { username: '', password: '', method: 'password' as 'password' | 'key', key: '', passphrase: '' }

/** bodyFor is the connect request an intent makes. */
function bodyFor(i: ConnectIntent): ConnectBody {
  if (i.instance) return { asg_instance_id: i.instance, protocol: i.protocol }
  if (i.asg) return { asg_id: i.asg, protocol: i.protocol }
  return { target_id: i.target, protocol: i.protocol }
}

/** findTarget is the reachable entry an intent names, which is also the
 *  check that the user may reach it at all. */
function findTarget(items: ReachableTarget[], i: ConnectIntent): ReachableTarget | null {
  const t = items.find((x) => (i.asg ? x.kind === 'asg' && x.id === i.asg : x.kind !== 'asg' && x.id === i.target))
  return t && t.allowed_protocols.includes(i.protocol) ? t : null
}

/**
 * ConnectPage is /connect, in the tab a session link opened (ADR 0038). It
 * finds the target among the user's, connects (asking for the user's own
 * login when the slot wants it), and opens the terminal or desktop in this
 * tab, the ticket kept in this tab's history state as before. Opened by our
 * own link a moment ago, it connects at once; otherwise it asks first.
 */
export function ConnectPage() {
  const loc = useLocation()
  const nav = useNavigate()
  const intent = parseIntent(new URLSearchParams(loc.search))
  const href = intent ? connectHref(intent) : ''
  const [auto] = useState(() => (intent ? takeOnce(loc.key, href) : false))
  const [target, setTarget] = useState<ReachableTarget | null | undefined>(undefined)
  const [err, setErr] = useState('')
  const [needsApproval, setNeedsApproval] = useState(false)
  const [busy, setBusy] = useState(false)
  const [prompt, setPrompt] = useState(false)
  const [promptErr, setPromptErr] = useState('')
  const [cred, setCred] = useState(noCred)
  const started = useRef(false)
  const protocol = intent ? protocolName(intent.protocol) : ''
  useTitle(target ? `${target.name} · ${protocol}` : 'Connect')

  const connect = async (t: ReachableTarget, body: ConnectBody, inPrompt: boolean) => {
    if (!intent) return
    setBusy(true)
    setErr('')
    setNeedsApproval(false)
    try {
      const res = await api.post<ConnectResponse>('/connect', body)
      nav(res.ws_path === '/ws/desktop' ? '/desktop' : '/terminal', {
        replace: true,
        state: {
          ticket: res.ticket,
          ws_path: res.ws_path,
          target: t.name,
          protocol: intent.protocol,
          asg_id: res.asg_id,
          asg_instance_id: res.asg_instance_id,
          instance_label: res.instance_label,
          again: href,
        },
      })
    } catch (e) {
      if (inPrompt && e instanceof ApiError && (e.code === 'credential_required' || e.code === 'credential_invalid')) {
        // Said inside the open prompt, where the user is looking.
        setPromptErr(e.message)
      } else if (e instanceof ApiError && e.code === 'credential_required') {
        setPromptErr('')
        setPrompt(true)
      } else if (e instanceof ApiError && e.code === 'approval_required') {
        // The grant lapsed between the list and this tab.
        setNeedsApproval(true)
      } else {
        setErr(errorMessage(e))
      }
    } finally {
      setBusy(false)
    }
  }

  const begin = (t: ReachableTarget) => {
    if (!intent) return
    if (intent.own) {
      setPromptErr('')
      setPrompt(true)
    } else void connect(t, bodyFor(intent), false)
  }

  useEffect(() => {
    // Once per page, StrictMode's second run included.
    if (!intent || started.current) return
    started.current = true
    api
      .get<Page<ReachableTarget>>('/me/targets')
      .then((p) => {
        const t = findTarget(p.items, intent)
        setTarget(t)
        if (t && auto) begin(t)
      })
      .catch((e) => {
        setErr(errorMessage(e))
        setTarget(null)
      })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Closing the prompt forgets what was typed in it, the username excepted.
  const closePrompt = () => {
    setPrompt(false)
    setPromptErr('')
    setCred((c) => ({ ...noCred, username: c.username, method: c.method }))
  }
  const readKeyFile = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    if (file.size > maxKeyBytes) {
      setPromptErr('that file is too large to be a private key')
      return
    }
    void file.text().then((key) => setCred((c) => ({ ...c, key })))
  }

  const back = <Link className="btn" to="/">Back to targets</Link>
  if (!intent) {
    return (
      <>
        <PageHead title="Connect" />
        <Empty>This link does not name a machine to connect to.</Empty>
        <div className="actions">{back}</div>
      </>
    )
  }
  const what = intent.instance ? `an instance of ${target?.name ?? 'the group'}` : target?.name ?? ''
  return (
    <>
      <PageHead title={target ? target.name : 'Connect'} lead={target ? `${protocol}${intent.own ? ', with your own login' : ''}` : undefined} />
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      {needsApproval && (
        <Alert tone="warn">
          {protocol} access to {target?.name} needs an approved request. <Link to="/">Request it from Targets</Link>.
        </Alert>
      )}
      {target === undefined && !err && <Empty>Loading…</Empty>}
      {target === null && (
        <>
          <Empty>{err ? 'The targets could not be listed.' : `${protocol} to that machine is not among your targets.`}</Empty>
          <div className="actions">{back}</div>
        </>
      )}
      {target && (
        <div className="card">
          <p style={{ marginTop: 0 }}>
            {busy ? `Connecting to ${what}…` : `Connect to ${intent.asg && !intent.instance ? `the newest healthy instance of ${target.name}` : what} over ${protocol}?`}
          </p>
          <div className="actions">
            <button type="button" className="btn primary" disabled={busy} onClick={() => begin(target)}>
              Connect
            </button>
            {back}
          </div>
        </div>
      )}

      {prompt && target && (
        <Modal title={`Credentials for ${target.name}`} onClose={closePrompt}>
          <p className="muted">Sent to the machine; not stored.</p>
          {promptErr && <Alert tone="danger" onDismiss={() => setPromptErr('')}>{promptErr}</Alert>}
          <form
            onSubmit={(e) => {
              e.preventDefault()
              const withKey = intent.protocol === 'ssh' && cred.method === 'key'
              void connect(target, {
                ...bodyFor(intent),
                credential: withKey
                  ? { username: cred.username, private_key: cred.key, ...(cred.passphrase ? { private_key_passphrase: cred.passphrase } : {}) }
                  : { username: cred.username, password: cred.password },
              }, true)
            }}
          >
            <Field label="Username">
              <input id="cred-user" autoFocus value={cred.username} onChange={(e) => setCred({ ...cred, username: e.target.value })} required />
            </Field>
            {intent.protocol === 'ssh' && (
              <div className="actions" role="radiogroup" aria-label="Sign in with" style={{ marginBottom: 8 }}>
                {(
                  [
                    ['password', 'Password'],
                    ['key', 'Private key'],
                  ] as const
                ).map(([m, label]) => (
                  <span key={m} className="field inline" style={{ margin: 0 }}>
                    <input id={`cred-method-${m}`} type="radio" name="cred-method" checked={cred.method === m} onChange={() => setCred({ ...cred, method: m })} />
                    <label htmlFor={`cred-method-${m}`}>{label}</label>
                  </span>
                ))}
              </div>
            )}
            {intent.protocol === 'ssh' && cred.method === 'key' ? (
              <>
                <Field label="Private key" hint="OpenSSH, PKCS#8 or PKCS#1">
                  <textarea id="cred-key" className="mono" value={cred.key} onChange={(e) => setCred({ ...cred, key: e.target.value })} required spellCheck={false} autoComplete="off" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" />
                </Field>
                <div className="actions" style={{ marginTop: -6, marginBottom: 10 }}>
                  <input id="cred-key-file" type="file" hidden onChange={readKeyFile} />
                  <button type="button" className="btn sm" onClick={() => document.getElementById('cred-key-file')?.click()}>Choose key file…</button>
                </div>
                <Field label="Passphrase" hint="If the key has one">
                  <input id="cred-passphrase" type="password" autoComplete="off" value={cred.passphrase} onChange={(e) => setCred({ ...cred, passphrase: e.target.value })} />
                </Field>
              </>
            ) : (
              <Field label="Password">
                <input id="cred-pass" type="password" value={cred.password} onChange={(e) => setCred({ ...cred, password: e.target.value })} required />
              </Field>
            )}
            <div className="actions">
              <button type="button" className="btn" onClick={closePrompt}>Cancel</button>
              <button type="submit" className="btn primary" disabled={busy}>Connect</button>
            </div>
          </form>
        </Modal>
      )}
    </>
  )
}
