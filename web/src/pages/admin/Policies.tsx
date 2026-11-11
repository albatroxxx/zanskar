import { Fragment, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { count, fmtTime } from '../../api/format'
import type { AutoscalingGroup, Group, Policy, PolicyGrant, Target, User } from '../../api/types'
import { FilterChips } from '../../components/FilterChips'
import { StateIcon } from '../../components/icons'
import { Alert, Badge, Empty, Loading, PageHead } from '../../components/ui'
import { useList } from './lib'
import { accessLine, extrasLine, grantsLine, kinds, policyRollup, reaches, reachLine, standingNoMFA, targetsCell, whoSummary } from './policyModel'

/**
 * Policies lists the access policies (ADR 0036, amended 2026-10-30): who each
 * is for, its grants summed up, and its loosest terms in Access, so a policy
 * of twelve grants is two lines and a standing grant without MFA still
 * stands out. A row opens to a table of its grants; editing has a page.
 */
export function Policies() {
  const [sp, setSp] = useSearchParams()
  const onlyNoMFA = sp.get('show') === 'standing_no_mfa'
  const { items: all, err, setErr } = useList<Policy>('/access-policies')
  const items = onlyNoMFA && all ? all.filter(standingNoMFA) : all
  const groups = useList<Group>('/groups')
  const users = useList<User>('/users')
  const targets = useList<Target>('/targets')
  const asgs = useList<AutoscalingGroup>('/autoscaling-groups')
  const [open, setOpen] = useState<string[]>([])
  // Until every list has loaded a name cannot be called missing.
  const loaded = !!targets.items && !!asgs.items && !targets.truncated && !asgs.truncated
  const found = (id: string) => targets.items?.find((t) => t.id === id)?.name ?? asgs.items?.find((g) => g.id === id)?.name
  const nameOf = (id: string) => found(id) ?? (loaded ? 'not found' : '…')
  const groupName = (id: string) => groups.items?.find((g) => g.id === id)?.name ?? '…'
  const userName = (id: string) => users.items?.find((u) => u.id === id)?.username ?? '…'

  return (
    <>
      <PageHead title="Access policies" lead="Standing access wins over approval; where grants overlap, each limit is the strictest.">
        <Link className="btn primary" to="/admin/policies/new">Add policy</Link>
      </PageHead>
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      <FilterChips chips={onlyNoMFA ? [{ label: 'Standing access without MFA', onClear: () => setSp({}, { replace: true }) }] : []} />
      <div className="card table-wrap">
        {items === null ? (
          err ? null : <Loading />
        ) : items.length === 0 ? (
          <Empty>{onlyNoMFA ? 'No policies match.' : 'No policies yet. Nobody can connect until a policy grants access.'}</Empty>
        ) : (
          <table className="policy-table">
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Who</th>
                <th scope="col">Grants</th>
                <th scope="col">Access</th>
                <th scope="col">Enabled</th>
                <th scope="col"><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {items.map((p) => {
                const r = policyRollup(p)
                const who = whoSummary(p, groupName, userName)
                const missing = loaded ? new Set(p.grants.flatMap((g) => g.targets.map((t) => t.id)).filter((id) => !found(id))).size : 0
                const idle = loaded ? p.grants.filter((g) => reaches(g, targets.items!, asgs.items!) === 0).length : 0
                const isOpen = open.includes(p.id)
                const detail = `policy-${p.id}-grants`
                const extras = extrasLine(r)
                return (
                  <Fragment key={p.id}>
                    <tr className={'policy-row' + (p.enabled ? '' : ' off')}>
                      <th scope="row">
                        <strong>{p.name}</strong>
                        {p.description && <div className="muted">{p.description}</div>}
                      </th>
                      {/* Each name stays whole; a line breaks between names
                          (live, 2026-11-11: "aashish-" over "admin"). */}
                      <td className="who">{p.subjects.length === 0 ? <Badge tone="warn">no one</Badge> : who.text.split(/(, | · )/).map((part, i) => (i % 2 ? part : <span key={i}>{part}</span>))}</td>
                      <td>
                        {r.count === 0 ? (
                          <Badge tone="warn">no grants</Badge>
                        ) : (
                          <button type="button" className="expander" aria-expanded={isOpen} aria-controls={detail} onClick={() => setOpen((o) => (o.includes(p.id) ? o.filter((x) => x !== p.id) : [...o, p.id]))}>
                            <span className="chev" aria-hidden="true" />
                            <span>
                              {grantsLine(r)}
                              {reachLine(r) && <span className="muted rollup-reach">{reachLine(r)}</span>}
                            </span>
                          </button>
                        )}
                        {missing > 0 && <Badge tone="warn">{missing} not found</Badge>}
                        {idle > 0 && <Badge tone="warn">{idle === 1 ? (r.count === 1 ? 'opens nothing' : '1 opens nothing') : `${idle} open nothing`}</Badge>}
                      </td>
                      <td className="access">
                        {r.count === 0 ? (
                          <span className="muted">—</span>
                        ) : (
                          <>
                            <div>{accessLine(r)}</div>
                            {(r.standingNoMFA > 0 || r.approvalNoMFA > 0) && (
                              <div className="access-flags">
                                {/* The line above already says "Standing" when no grant is
                                    approval-gated, so the flag does not say it twice; a disabled
                                    policy grants nothing, so its flag is not the alarm the
                                    dashboard's count leaves it out of (2026-11-04). */}
                                {r.standingNoMFA > 0 && <Badge tone={p.enabled ? 'danger' : undefined}>{r.approval === 0 ? 'no MFA' : 'standing, no MFA'}{r.standingNoMFA > 1 || r.count > 1 ? ` ×${r.standingNoMFA}` : ''}</Badge>}
                                {r.approvalNoMFA > 0 && <Badge tone={p.enabled ? 'warn' : undefined}>no MFA{r.approvalNoMFA > 1 || r.count > 1 ? ` ×${r.approvalNoMFA}` : ''}</Badge>}
                              </div>
                            )}
                            {extras && <div className="muted">{extras}</div>}
                          </>
                        )}
                      </td>
                      <td>{p.enabled ? <StateIcon state="ok" label="Enabled" /> : <StateIcon state="unknown" label="Disabled" />}</td>
                      <td className="actions">
                        {/* An access review a quarter old, or never made, is due (ADR 0040). */}
                        <Link className="btn sm" to={`/admin/policies/${p.id}/review`} title={p.reviewed_at ? `Reviewed ${fmtTime(p.reviewed_at)}` : 'Never reviewed'}>
                          Review{p.review_state !== 'current' && <span className="dot-due" aria-label="due" />}
                        </Link>
                        <Link className="btn sm" to={`/admin/policies/${p.id}`}>Edit</Link>
                      </td>
                    </tr>
                    {isOpen && r.count > 0 && (
                      <tr className="policy-detail" id={detail}>
                        <td colSpan={6}>
                          {who.cut && (
                            <p className="policy-who-full">
                              <span className="muted">Who </span>
                              {p.subjects.map((s) => (s.kind === 'group' ? groupName(s.id) : userName(s.id))).join(', ')}
                            </p>
                          )}
                          <GrantsTable policy={p} nameOf={nameOf} reach={loaded ? (g) => reaches(g, targets.items!, asgs.items!) : undefined} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}

/** GrantsTable is one policy's grants side by side, the expanded row. */
function GrantsTable({ policy, nameOf, reach }: { policy: Policy; nameOf: (id: string) => string; reach?: (g: PolicyGrant) => number }) {
  return (
    <table className="grants-table" aria-label={`Grants of ${policy.name}`}>
      <thead>
        <tr>
          <th scope="col">Type</th>
          <th scope="col">Targets or tags</th>
          <th scope="col">Access</th>
          <th scope="col">MFA</th>
          <th scope="col">Clipboard, files</th>
          <th scope="col">Sign-in</th>
          <th scope="col">Idle / max</th>
          <th scope="col">Windows</th>
          <th scope="col">Recording retention</th>
        </tr>
      </thead>
      <tbody>
        {policy.grants.map((g, i) => (
          <tr key={g.id ?? i}>
            <td>{kinds.find((k) => k.kind === g.kind)?.label ?? g.kind}</td>
            <td>
              {targetsCell(g, nameOf)}
              {reach && reach(g) === 0 && (
                <>
                  {' '}
                  <Badge tone="warn">opens nothing</Badge>
                </>
              )}
            </td>
            <td>{g.access === 'approval' ? 'Approval' : 'Standing'}</td>
            <td>{g.require_mfa ? 'MFA' : <Badge tone={g.access === 'approval' ? 'warn' : 'danger'}>no MFA</Badge>}</td>
            <td>{[g.allow_clipboard && 'clipboard', g.allow_file_transfer && 'files', g.allow_devtools && 'dev tools'].filter(Boolean).join(', ') || <span className="muted">—</span>}</td>
            <td>{g.sign_in === 'own' ? 'Own login' : 'Target'}</td>
            <td>
              {g.idle_timeout_minutes}m / {g.max_session_minutes ? `${g.max_session_minutes}m` : '—'}
            </td>
            <td>{g.time_windows.length === 0 ? <span className="muted">Any time</span> : g.time_windows.length}</td>
            <td>{g.retention_days ? count(g.retention_days, 'day') : <span className="muted">Default</span>}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
