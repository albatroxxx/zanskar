import { Fragment, useEffect, useState, type FormEvent } from 'react'
import { ApiError, api, errorMessage } from '../../api/client'
import { accessDrill, expiresSoon, expiringSoonMs } from '../../api/drilldown'
import type { AccessRequest, CloudConsole, ConnectResponse, Page, Protocol, ReachableInstance, ReachableTarget, Session } from '../../api/types'
import { DatabaseIcon, OSIcon, StateIcon } from '../../components/icons'
import { Alert, Badge, Empty, Field, Loading, Modal, PageHead, StatTile, Tabs, Tags } from '../../components/ui'
import { badgesChanged } from '../../components/badges'
import { engineName, fmtTime, platformName, protocolName } from '../../api/format'
import { fmtAgo } from './Failover'
import { SessionLink } from './connect'

const terminalProtocols: Protocol[] = ['ssh', 'winrm']
const desktopProtocols: Protocol[] = ['rdp', 'vnc']
const databaseProtocols: Protocol[] = ['database']

function pick(t: ReachableTarget, family: Protocol[]): Protocol | null {
  // database is brokered, never probed, so it is not a capability.
  for (const p of family) if (t.allowed_protocols.includes(p) && (p === 'database' || t.capabilities.length === 0 || t.capabilities.includes(p))) return p
  return null
}

/** NotOffered fills a protocol cell the target has nothing for. */
function NotOffered() {
  return <span className="muted" title="not offered" aria-label="not offered">—</span>
}

/** cloudAccount reads a role's account as "alias · id", or the id alone (ADR 0050). */
function cloudAccount(t: ReachableTarget): string {
  const c = t.cloud
  if (!c) return ''
  return c.account_alias ? `${c.account_alias} · ${c.account_id}` : c.account_id
}

/** stillRuns says a remembered cloud session has not reached its end. */
function stillRuns(res?: ConnectResponse): boolean {
  return !!res?.cloud && new Date(res.cloud.expires_at).getTime() > Date.now()
}

/** federationAction is the one address a console sign-in is posted to (ADR
 *  0038: the console navigates to no address an API returned; the gateway's
 *  answer is checked against it, never followed). */
export const federationAction = 'https://signin.aws.amazon.com/federation'

/** openTab opens the tab a console sign-in will land in, on the click itself:
 *  opened after the gateway has answered, the browser holds it back as a pop-up.
 *  The tab gets no opener: the AWS page must not reach this one. */
function openTab(name: string): Window | null {
  try {
    const w = window.open('', name) ?? null
    if (w) w.opener = null
    return w
  } catch {
    return null
  }
}

/** postInto submits the sign-in form the gateway built into the tab: a POST,
 *  so the sign-in token is never a URL the browser keeps (ADR 0050). */
function postInto(name: string, c: CloudConsole) {
  const form = document.createElement('form')
  form.method = 'post'
  form.action = c.action
  form.target = name
  for (const [k, v] of Object.entries(c.fields)) {
    const i = document.createElement('input')
    i.type = 'hidden'
    i.name = k
    i.value = v
    form.appendChild(i)
  }
  document.body.appendChild(form)
  form.submit()
  form.remove()
}

export function Targets() {
  const [items, setItems] = useState<ReachableTarget[] | null>(null)
  const [err, setErr] = useState('')
  const [notice, setNotice] = useState('')
  const [tab, setTab] = useState<'static' | 'database' | 'application' | 'cluster' | 'cloud' | 'asg'>('static')
  const [chooser, setChooser] = useState<{ group: ReachableTarget; protocol: Protocol; instances: ReachableInstance[] | null } | null>(null)
  // Active grants, as a set of "targetId:protocol", so a gated protocol the user
  // already holds a grant for shows Connect rather than Request.
  const [grants, setGrants] = useState<Set<string>>(new Set())
  const [reqModal, setReqModal] = useState<{ target: ReachableTarget; protocol: Protocol } | null>(null)
  // A cluster session's kubeconfig (ADR 0045), shown once.
  const [kubeconfig, setKubeconfig] = useState<{ target: ReachableTarget; res: ConnectResponse } | null>(null)
  // A cloud role's session (ADR 0050), one per role while this page lives: both doors open on it.
  const [cloudSessions, setCloudSessions] = useState<Record<string, ConnectResponse>>({})
  const [cli, setCli] = useState<{ target: ReachableTarget; res: ConnectResponse } | null>(null)
  const [reqForm, setReqForm] = useState({ reason: '', minutes: 60 })
  const [busy, setBusy] = useState('')
  // Live filter over the already-loaded reachable list: matching is instant, no
  // refetch. Only name and the private IP are searchable because the portal is
  // the only place a public address is deliberately withheld (see
  // ReachableTarget.private_ip); searching cannot reveal what the list hides.
  const [search, setSearch] = useState('')

  // The overview strip (ADR 0029): the three things worth a glance before the
  // list — a session left open, a request still waiting, a grant about to run
  // out. All scoped to the account; it fails silently because the page's real
  // content reports its own errors.
  const [strip, setStrip] = useState({ open: 0, pending: 0, expiring: 0 })

  // When the grants next change by themselves: the soonest grant's end, or the
  // moment one starts to count as expiring soon (ms since the epoch).
  const [nextChange, setNextChange] = useState<number | null>(null)

  const loadGrants = () =>
    api
      .get<Page<AccessRequest>>('/me/access')
      .then((p) => {
        setGrants(new Set(p.items.map((g) => `${g.target_id ?? g.asg_id}:${g.protocol}`)))
        setStrip((s) => ({ ...s, expiring: p.items.filter((g) => expiresSoon(g.expires_at)).length }))
        const now = Date.now()
        const ends = p.items.flatMap((g) => (g.expires_at ? [new Date(g.expires_at).getTime()] : []))
        const moments = ends.flatMap((t) => [t, t - expiringSoonMs]).filter((t) => t > now)
        // A grant the gateway still lists but this browser's clock has seen
        // end: the clocks differ, so look again shortly rather than never.
        if (ends.some((t) => t <= now)) moments.push(now + 30_000)
        setNextChange(moments.length ? Math.min(...moments) : null)
      })
      .catch(() => {})

  const countOpen = () =>
    api
      .get<Page<Session>>('/me/sessions?open=true&limit=50')
      .then((p) => setStrip((s) => ({ ...s, open: p.items.length })))
      .catch(() => {})

  const countPending = () =>
    api
      .get<Page<AccessRequest>>('/me/access-requests')
      .then((p) => setStrip((s) => ({ ...s, pending: p.items.filter((r) => r.status === 'pending').length })))
      .catch(() => {})

  // What a person may open changes while this page stays open: a session
  // started from here runs and ends in a tab of its own (ADR 0038), an
  // administrator revokes a grant or decides a request, a grant runs out. So
  // the grants, the open sessions and the pending requests are read again
  // whenever this page is looked at again, from another tab or another window
  // (live, 2026-11-04: a revoked grant still showed RDP and "1 grant expiring
  // soon" until a reload). Switching tabs fires both events; one read serves.
  useEffect(() => {
    let last = 0
    const look = () => {
      if (document.visibilityState !== 'visible' || Date.now() - last < 2000) return
      last = Date.now()
      void loadGrants()
      void countOpen()
      void countPending()
    }
    document.addEventListener('visibilitychange', look)
    window.addEventListener('focus', look)
    return () => {
      document.removeEventListener('visibilitychange', look)
      window.removeEventListener('focus', look)
    }
  }, [])

  // ...and when a grant runs out, or starts to count as expiring soon, with the
  // page in view: its button goes back to Request at its end, not at a reload.
  // An hour at most between looks, so a sleeping laptop's clock catches up.
  useEffect(() => {
    if (nextChange === null) return
    const t = window.setTimeout(() => void loadGrants(), Math.min(Math.max(nextChange - Date.now(), 0) + 1000, 60 * 60_000))
    return () => window.clearTimeout(t)
  }, [nextChange])

  useEffect(() => {
    api
      .get<Page<ReachableTarget>>('/me/targets')
      .then((p) => {
        setItems(p.items)
        // Land on a tab that has something in it. Opening on an empty Hosts
        // tab while Databases holds entries reads as "you have no access"
        // (manual QA finding 2).
        const kind = (t: ReachableTarget) => (t.kind === 'asg' ? 'asg' : t.kind === 'application' ? 'application' : t.kind === 'cluster' ? 'cluster' : t.kind === 'cloud' ? 'cloud' : t.engine ? 'database' : 'static')
        if (!p.items.some((t) => kind(t) === 'static')) {
          const first = (['database', 'application', 'cluster', 'cloud', 'asg'] as const).find((k) => p.items.some((t) => kind(t) === k))
          if (first) setTab(first)
        }
      })
      .catch((e) => setErr(errorMessage(e)))
    void loadGrants()
    void countOpen()
    void countPending()
  }, [])

  // A protocol is gated when the policy requires approval and the user holds no
  // active grant for it yet.
  const gated = (t: ReachableTarget, p: Protocol) => (t.requires_approval ?? []).includes(p) && !grants.has(`${t.id}:${p}`)

  const submitRequest = async (e: FormEvent) => {
    e.preventDefault()
    if (!reqModal) return
    setBusy('request')
    setErr('')
    try {
      await api.post<AccessRequest>('/me/access-requests', {
        ...(reqModal.target.kind === 'asg' ? { asg_id: reqModal.target.id } : { target_id: reqModal.target.id }),
        protocol: reqModal.protocol,
        reason: reqForm.reason,
        minutes: Number(reqForm.minutes),
      })
      badgesChanged()
      setNotice(`Requested ${protocolName(reqModal.protocol)} access to ${reqModal.target.name}.`)
      setReqModal(null)
      setReqForm({ reason: '', minutes: 60 })
      void loadGrants()
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy('')
    }
  }

  const loadInstances = async (group: ReachableTarget, protocol: Protocol) => {
    setChooser({ group, protocol, instances: null })
    try {
      const p = await api.get<Page<ReachableInstance>>(`/me/autoscaling-groups/${encodeURIComponent(group.id)}/instances`)
      setChooser({ group, protocol, instances: p.items })
    } catch (e) {
      setErr(errorMessage(e))
      setChooser({ group, protocol, instances: [] })
    }
  }

  // A cluster session (ADR 0045) has no socket: it starts here, and the
  // kubeconfig is shown once, to copy or download; the open-sessions count
  // moves with it.
  const openKubeconfig = async (t: ReachableTarget) => {
    setBusy('kube:' + t.id)
    setErr('')
    try {
      const res = await api.post<ConnectResponse>('/connect', { target_id: t.id, protocol: 'kube' })
      setKubeconfig({ target: t, res })
      void countOpen()
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy('')
    }
  }
  const download = (name: string, text: string) => downloadFile(`${name}.kubeconfig`, text, 'application/yaml')
  const downloadFile = (filename: string, text: string, type: string) => {
    const url = URL.createObjectURL(new Blob([text], { type }))
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }

  // A cloud session (ADR 0050) has no socket either: it starts here, once per
  // role while this page lives, and is reused while it runs; the open-sessions
  // count moves with it. The console asks the gateway for a sign-in form each
  // time, posted into a tab opened on the click.
  const cloudSession = async (t: ReachableTarget, fresh = false): Promise<ConnectResponse> => {
    const have = cloudSessions[t.id]
    if (!fresh && stillRuns(have)) return have
    const res = await api.post<ConnectResponse>('/connect', { target_id: t.id, protocol: 'cloud' })
    setCloudSessions((s) => ({ ...s, [t.id]: res }))
    void countOpen()
    return res
  }
  const openConsole = async (t: ReachableTarget) => {
    setErr('')
    const name = `zanskar-console-${t.id}`
    const win = openTab(name)
    if (!win) {
      // Nothing to land in: no session is started for a sign-in nobody would see.
      setErr('Pop-up blocked.')
      return
    }
    setBusy('console:' + t.id)
    try {
      let res = await cloudSession(t)
      let form: CloudConsole
      try {
        form = await api.post<CloudConsole>(`/cloud/${res.session_id}/console`, {})
      } catch (e) {
        // The session this page remembers has ended (a terminate, a policy change): start another, once.
        if (!(e instanceof ApiError && e.status === 410)) throw e
        res = await cloudSession(t, true)
        form = await api.post<CloudConsole>(`/cloud/${res.session_id}/console`, {})
      }
      if (form.action !== federationAction) throw new Error('Refused: the sign-in address is not AWS’s.')
      postInto(name, form)
    } catch (e) {
      win.close()
      setErr(errorMessage(e))
    } finally {
      setBusy('')
    }
  }
  const openCli = async (t: ReachableTarget) => {
    setBusy('cli:' + t.id)
    setErr('')
    try {
      setCli({ target: t, res: await cloudSession(t) })
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy('')
    }
  }

  const kindOf = (t: ReachableTarget) => (t.kind === 'asg' ? 'asg' : t.kind === 'application' ? 'application' : t.kind === 'cluster' ? 'cluster' : t.kind === 'cloud' ? 'cloud' : t.engine ? 'database' : 'target')
  const term = search.trim().toLowerCase()
  const matches = (t: ReachableTarget) => term === '' || t.name.toLowerCase().includes(term) || (t.private_ip?.toLowerCase().includes(term) ?? false)
  const shown = items?.filter(matches) ?? null
  const statics = shown?.filter((t) => kindOf(t) === 'target') ?? null
  const databases = shown?.filter((t) => kindOf(t) === 'database') ?? null
  const applications = shown?.filter((t) => kindOf(t) === 'application') ?? null
  const groups = shown?.filter((t) => kindOf(t) === 'asg') ?? null
  const clusters = shown?.filter((t) => kindOf(t) === 'cluster') ?? null
  const clouds = shown?.filter((t) => kindOf(t) === 'cloud') ?? null
  // Roles under their account, accounts and roles each by name.
  const cloudGroups = clouds
    ? [...new Set(clouds.map(cloudAccount))].sort().map((label) => [label, clouds.filter((t) => cloudAccount(t) === label).sort((a, b) => a.name.localeCompare(b.name))] as const)
    : null
  // Every tab says how many it holds, the same way, once there are any; a
  // search narrows the counts with the lists.
  const counted = (label: string, list: ReachableTarget[] | null) => (list && list.length > 0 ? `${label} (${list.length})` : label)
  // Empty-state text for a tab: the search message while filtering, else the tab's own "nothing assigned" line.
  const emptyFor = (noun: string, assigned: string) => (term ? `No ${noun} match ‘${search.trim()}’.` : assigned)

  // protoButtons renders one cell per protocol family. A machine's protocol is
  // a link that opens the session in a tab of its own (ADR 0038); an
  // autoscaling group's opens the instance chooser here (onPick). onRequest,
  // when given, turns a gated protocol into a Request button. Colour says who
  // signs the person in (2026-11-02, in place of an "as me" button): green
  // where Zanskar does, with a credential it holds (managed_login), the
  // protocol's own colour where the person gives their own login; each
  // button's tooltip and name say it in words (no legend, the owner,
  // 2026-11-03). own, when set, offers the person's own login beside a green
  // one where a grant lets them (ADR 0036), and in its place where the
  // target's slot would not sign them in anyway. A protocol the target does
  // not offer is a quiet dash, not a disabled button (2026-11-03 live audit).
  const protoButtons = (t: ReachableTarget, open: { link: true } | { onPick: (p: Protocol) => void }, onRequest?: (p: Protocol) => void, own?: boolean) => {
    const term = pick(t, terminalProtocols)
    const desk = pick(t, desktopProtocols)
    const notReady = !t.host_key_ready && term === 'ssh'
    const cell = (p: Protocol | null, colorClass: string, label: string, blocked: boolean) => {
      if (p && onRequest && gated(t, p)) {
        return (
          <button className="btn sm" onClick={() => onRequest(p)} title={`request ${label.toLowerCase()} access`}>
            Request
          </button>
        )
      }
      const managed = !!p && (t.managed_login ?? []).includes(p)
      const ownToo = !!p && !!own && (t.own_login ?? []).includes(p)
      const ownButton = (
        blocked ? (
          <button className={'btn sm' + colorClass} disabled aria-label={`${label} with my own login`} title={`${label}: your own login`}>{label}</button>
        ) : (
          <SessionLink intent={{ target: t.id, protocol: p as Protocol, own: true }} className={'btn sm' + colorClass} label={`${label} with my own login`} title={`${label}: your own login`}>
            {label}
          </SessionLink>
        )
      )
      // The target's slot would ask for the person's login anyway: one
      // button, their own login, which needs nothing bound to the slot.
      if (ownToo && !managed) return ownButton
      const cls = 'btn sm' + (managed ? ' proto-managed' : colorClass)
      const says = managed ? `${label}: Zanskar signs you in` : `${label}: your own login`
      if (!p) return <NotOffered />
      const main =
        !blocked && 'link' in open ? (
          <SessionLink intent={{ target: t.id, protocol: p }} className={cls} label={label} title={says}>
            {label}
          </SessionLink>
        ) : (
          <button className={cls} disabled={blocked} onClick={() => 'onPick' in open && open.onPick(p)} title={says}>
            {label}
          </button>
        )
      if (!ownToo) return main
      return (
        <span className="actions">
          {main}
          {ownButton}
        </span>
      )
    }
    return (
      <>
        <td>{cell(term, ' proto-terminal', term ? protocolName(term) : '', notReady)}</td>
        <td>{cell(desk, ' proto-desktop', desk ? protocolName(desk) : '', false)}</td>
      </>
    )
  }

  return (
    <>
      <PageHead title="Targets" />
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      {items && items.length > 0 && (
        <div className="list-search">
          <input
            type="search"
            placeholder="Search by name or IP"
            aria-label="Search targets by name or IP"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      )}
      {notice && <Alert tone="ok" onDismiss={() => setNotice('')}>{notice}</Alert>}
      {(strip.open > 0 || strip.pending > 0 || strip.expiring > 0) && (
        <div className="stat-grid" style={{ marginBottom: 16 }}>
          {strip.open > 0 && <StatTile value={strip.open} label="Open sessions" to={accessDrill.openSessions} />}
          {strip.pending > 0 && <StatTile value={strip.pending} label="Pending requests" to={accessDrill.pendingRequests} />}
          {strip.expiring > 0 && <StatTile value={strip.expiring} label="Grants expiring soon" to={accessDrill.expiringGrants} tone="warn" />}
        </div>
      )}
      <Tabs
        label="Kinds of target"
        value={tab}
        onChange={setTab}
        tabs={[
          { key: 'static', label: counted('Hosts', statics) },
          { key: 'database', label: counted('Databases', databases) },
          { key: 'application', label: counted('Applications', applications) },
          { key: 'cluster', label: counted('Clusters', clusters) },
          { key: 'cloud', label: counted('Cloud', clouds) },
          { key: 'asg', label: counted('Autoscaling', groups) },
        ]}
      />

      {tab === 'application' && (
        <div className="card table-wrap">
          {applications === null ? (
            <Loading />
          ) : applications.length === 0 ? (
            <Empty>{emptyFor('applications', 'No applications are assigned to you.')}</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Tags</th>
                  <th>Open</th>
                </tr>
              </thead>
              <tbody>
                {applications.map((t) => (
                  <tr key={t.id}>
                    <td><strong>{t.name}</strong></td>
                    <td><Tags tags={t.tags} /></td>
                    <td>
                      {gated(t, 'http') ? (
                        <button className="btn sm" onClick={() => setReqModal({ target: t, protocol: 'http' })}>Request</button>
                      ) : (
                        // The application opens in an isolated browser beside
                        // the gateway, streamed like a desktop (ADR 0034), in a
                        // tab of its own (ADR 0038).
                        <SessionLink intent={{ target: t.id, protocol: 'http' }} className="btn sm proto-app" label={`Open ${t.name}`}>Open</SessionLink>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === 'database' && (
        <div className="card table-wrap">
          {databases === null ? (
            <Loading />
          ) : databases.length === 0 ? (
            <Empty>{emptyFor('databases', 'No databases are assigned to you.')}</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Engine</th>
                  <th>Tags</th>
                  <th>Connect</th>
                </tr>
              </thead>
              <tbody>
                {databases.map((t) => {
                  const p = pick(t, databaseProtocols)
                  return (
                    <tr key={t.id}>
                      <td><strong>{t.name}</strong></td>
                      <td><DatabaseIcon label={engineName(t.engine)} /> {engineName(t.engine)}</td>
                      <td><Tags tags={t.tags} /></td>
                      <td>
                        {p && gated(t, p) ? (
                          <button className="btn sm" onClick={() => setReqModal({ target: t, protocol: p })} title="request database access">Request</button>
                        ) : (
                          p ? (
                            <SessionLink intent={{ target: t.id, protocol: p }} className="btn sm proto-database" label="SQL client">SQL client</SessionLink>
                          ) : (
                            <NotOffered />
                          )
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === 'static' && (
        <div className="card table-wrap">
          {statics === null ? (
            <Loading />
          ) : statics.length === 0 ? (
            <Empty>{emptyFor('hosts', 'No hosts are assigned to you.')}</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>OS</th>
                  <th>IP</th>
                  <th>Tags</th>
                  <th>Terminal</th>
                  <th>Desktop</th>
                </tr>
              </thead>
              <tbody>
                {statics.map((t) => {
                  const notReady = !t.host_key_ready && pick(t, terminalProtocols) === 'ssh'
                  return (
                    <tr key={t.id}>
                      <td>
                        <strong>{t.name}</strong>
                        {notReady && (
                          <>
                            {' '}
                            <StateIcon state="warn" label="Awaiting host key trust" />
                          </>
                        )}
                      </td>
                      <td><OSIcon os={t.os_family} /></td>
                      <td className="mono">{t.private_ip ?? '—'}</td>
                      <td><Tags tags={t.tags} /></td>
                      {protoButtons(t, { link: true }, (p) => setReqModal({ target: t, protocol: p }), true)}
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === 'cluster' && (
        <div className="card table-wrap">
          {clusters === null ? (
            <Loading />
          ) : clusters.length === 0 ? (
            <Empty>{emptyFor('clusters', 'No clusters are assigned to you.')}</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Platform</th>
                  <th>Tags</th>
                  <th>Kubeconfig</th>
                </tr>
              </thead>
              <tbody>
                {clusters.map((t) => (
                  <tr key={t.id}>
                    <td><strong>{t.name}</strong></td>
                    <td>{platformName(t.platform)}</td>
                    <td><Tags tags={t.tags} /></td>
                    <td>
                      {gated(t, 'kube') ? (
                        <button className="btn sm" onClick={() => setReqModal({ target: t, protocol: 'kube' })}>Request</button>
                      ) : (
                        <button className="btn sm proto-kube" disabled={busy === 'kube:' + t.id} onClick={() => void openKubeconfig(t)}>Kubeconfig</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === 'cloud' && (
        <div className="card table-wrap">
          {cloudGroups === null ? (
            <Loading />
          ) : cloudGroups.length === 0 ? (
            <Empty>{emptyFor('cloud roles', 'No cloud roles are assigned to you.')}</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Role</th>
                  <th>Tags</th>
                  <th>Console</th>
                  <th>Command line</th>
                </tr>
              </thead>
              <tbody>
                {cloudGroups.map(([label, roles]) => (
                  <Fragment key={label}>
                    <tr className="row-group">
                      <th colSpan={4} scope="colgroup">{label}</th>
                    </tr>
                    {roles.map((t) => (
                      <tr key={t.id}>
                        <td>
                          <strong>{t.name}</strong>
                          {t.cloud?.role_name && t.cloud.role_name !== t.name && <span className="muted mono"> {t.cloud.role_name}</span>}
                        </td>
                        <td><Tags tags={t.tags} /></td>
                        {gated(t, 'cloud') ? (
                          <td colSpan={2}>
                            <button className="btn sm" onClick={() => setReqModal({ target: t, protocol: 'cloud' })} title="request access">Request</button>
                          </td>
                        ) : (
                          <>
                            <td>
                              <button className="btn sm proto-kube" disabled={!t.cloud?.console || busy === 'console:' + t.id} onClick={() => void openConsole(t)} aria-label={`Open the console of ${t.name}, opens in a new tab`} title={t.cloud?.console ? 'Opens in a new tab' : 'Not in the grant'}>Open console</button>
                            </td>
                            <td>
                              <button className="btn sm proto-kube" disabled={!t.cloud?.cli || busy === 'cli:' + t.id} onClick={() => void openCli(t)} aria-label={`Command line for ${t.name}`} title={t.cloud?.cli ? undefined : 'Not in the grant'}>Command line</button>
                            </td>
                          </>
                        )}
                      </tr>
                    ))}
                  </Fragment>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === 'asg' && (
        <div className="card table-wrap">
          {groups === null ? (
            <Loading />
          ) : groups.length === 0 ? (
            <Empty>{emptyFor('autoscaling groups', 'No autoscaling groups are assigned to you.')}</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Group</th>
                  <th>OS</th>
                  <th>Tags</th>
                  <th>Healthy</th>
                  <th>Terminal</th>
                  <th>Desktop</th>
                </tr>
              </thead>
              <tbody>
                {groups.map((g) => {
                  const healthy = g.healthy_count ?? 0
                  const total = g.instance_count ?? 0
                  return (
                    <tr key={g.id}>
                      <td><strong>{g.name}</strong></td>
                      <td><OSIcon os={g.os_family} /></td>
                      <td><Tags tags={g.tags} /></td>
                      <td>
                        <Badge tone={healthy === 0 ? 'danger' : 'ok'}>{healthy} / {total}</Badge>
                      </td>
                      {protoButtons(g, { onPick: (p) => void loadInstances(g, p) }, (p) => setReqModal({ target: g, protocol: p }))}
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {chooser && (
        <Modal title={`Connect to ${chooser.group.name}`} onClose={() => setChooser(null)} width={560}>
          {chooser.instances === null && <p className="muted">Loading…</p>}
          {chooser.instances !== null && chooser.instances.length === 0 && (
            <Alert tone="warn">This group has no healthy instance right now.</Alert>
          )}
          {chooser.instances && chooser.instances.length > 0 && (
            <div className="failover-list">
              {chooser.instances.map((i) => (
                <div key={i.id} className="failover-row">
                  <div>
                    <span className="mono">{i.instance_id}</span>
                    <span className="muted"> · {i.availability_zone} · launched {fmtAgo(i.launched_at)}</span>
                  </div>
                  <SessionLink intent={{ asg: chooser.group.id, instance: i.id, protocol: chooser.protocol }} className="btn sm" label={`Connect to ${i.instance_id}`}>
                    Connect
                  </SessionLink>
                </div>
              ))}
            </div>
          )}
          <div className="actions" style={{ justifyContent: 'space-between' }}>
            <a href="#refresh" className="muted" onClick={(e) => { e.preventDefault(); void loadInstances(chooser.group, chooser.protocol) }}>Refresh</a>
            <span>
              <button className="btn" onClick={() => setChooser(null)}>Cancel</button>
              {chooser.instances && chooser.instances.length > 0 ? (
                <SessionLink intent={{ asg: chooser.group.id, protocol: chooser.protocol }} className="btn primary connect-newest" style={{ marginLeft: 8 }} label="Connect to newest healthy">
                  Connect to newest healthy
                </SessionLink>
              ) : (
                <button className="btn primary connect-newest" style={{ marginLeft: 8 }} disabled>Connect to newest healthy</button>
              )}
            </span>
          </div>
        </Modal>
      )}

      {kubeconfig && (
        <Modal title={`Kubeconfig · ${kubeconfig.target.name}`} onClose={() => setKubeconfig(null)} width={720}>
          <pre className="mono" style={{ whiteSpace: 'pre', overflow: 'auto', maxHeight: '50vh' }}>{kubeconfig.res.kubeconfig}</pre>
          <p className="muted">
            {[
              kubeconfig.res.idle_seconds ? `Idle ${Math.round(kubeconfig.res.idle_seconds / 60)} min` : '',
              kubeconfig.res.expires_at ? `Ends ${fmtTime(kubeconfig.res.expires_at)}` : '',
            ].filter(Boolean).join(' · ')}
          </p>
          <div className="actions">
            <button className="btn" onClick={() => void navigator.clipboard.writeText(kubeconfig.res.kubeconfig ?? '')}>Copy</button>
            <button className="btn" onClick={() => download(kubeconfig.target.name, kubeconfig.res.kubeconfig ?? '')}>Download</button>
            <button className="btn primary" onClick={() => setKubeconfig(null)}>Close</button>
          </div>
        </Modal>
      )}

      {cli && cli.res.cloud && (
        <Modal title={`Command line · ${cli.target.name}`} onClose={() => setCli(null)} width={720}>
          <pre className="mono" style={{ whiteSpace: 'pre', overflow: 'auto', maxHeight: '50vh' }}>{cli.res.cloud.profile}</pre>
          <p className="muted">Until {fmtTime(cli.res.cloud.expires_at)}</p>
          <div className="actions">
            <button className="btn" onClick={() => void navigator.clipboard.writeText(cli.res.cloud?.profile ?? '')}>Copy</button>
            <button className="btn" onClick={() => downloadFile(`${cli.target.name}.awsconfig`, cli.res.cloud?.profile ?? '', 'text/plain')}>Download</button>
            <button className="btn primary" onClick={() => setCli(null)}>Close</button>
          </div>
        </Modal>
      )}

      {reqModal && (
        <Modal title={`Request access to ${reqModal.target.name}`} onClose={() => setReqModal(null)}>
          <form onSubmit={(e) => void submitRequest(e)}>
            <Field label="Reason">
              <textarea id="req-reason" autoFocus value={reqForm.reason} onChange={(e) => setReqForm({ ...reqForm, reason: e.target.value })} required placeholder="What you need to do" />
            </Field>
            <Field label="Duration (minutes)" hint="Capped by the policy">
              <input id="req-minutes" type="number" min={1} value={reqForm.minutes} onChange={(e) => setReqForm({ ...reqForm, minutes: Number(e.target.value) })} required />
            </Field>
            <div className="actions">
              <button type="button" className="btn" onClick={() => setReqModal(null)}>Cancel</button>
              <button type="submit" className="btn primary" disabled={busy === 'request'}>Request access</button>
            </div>
          </form>
        </Modal>
      )}

    </>
  )
}
