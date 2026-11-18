import { useEffect, useState } from 'react'
import { api } from '../../api/client'
import { cloudPlatformName, count } from '../../api/format'
import type { AdminOverview, Target } from '../../api/types'
import { TileIcon } from '../../components/icons'
import { PageHead, StatTile, Tags } from '../../components/ui'
import { accountLabel, roleName } from './cloudNames'
import { TargetsPage } from './TargetsPage'

// Cloud accounts (ADR 0050): a role in an account is a target, assumed by
// the gateway for the person as autoscaling and EKS roles are. One tile per
// platform, AWS alone until another is built (no placeholder tiles), then
// the roles under their accounts. The section's head owns the Add button,
// as Kubernetes does.

export function Cloud() {
  const [adding, setAdding] = useState(false)
  const [counts, setCounts] = useState<AdminOverview['inventory'] | null>(null)
  useEffect(() => {
    api
      .get<AdminOverview>('/admin/overview')
      .then((o) => setCounts(o.inventory))
      .catch(() => setCounts(null))
  }, [])
  return (
    <>
      <PageHead title="Cloud accounts">
        <button className="btn primary" onClick={() => setAdding(true)}>Add role</button>
      </PageHead>
      <nav className="stat-grid platforms" aria-label="Platforms">
        <StatTile
          value={counts ? counts.cloud_roles ?? 0 : null}
          label={cloudPlatformName('aws')}
          detail={counts ? count(counts.cloud_accounts ?? 0, 'account') : undefined}
          icon={<TileIcon kind="cloud" />}
          to="/admin/cloud"
          selected
        />
      </nav>
      <TargetsPage
        kind="cloud"
        title="Roles"
        addLabel="Add role"
        empty="No roles yet."
        columns={['Role', 'Max', 'Region', 'Tags']}
        cells={(t: Target) => (
          <>
            <td className="mono" title={t.cloud_role_arn}>{roleName(t.cloud_role_arn)}</td>
            <td>{t.cloud_max_minutes ? `${t.cloud_max_minutes} min` : '—'}</td>
            <td className="mono">{t.cloud_region || '—'}</td>
            <td><Tags tags={t.tags} /></td>
          </>
        )}
        // Accounts in the order they read, by alias where there is one, else by id.
        group={(t) => ({ key: accountLabel(t), label: accountLabel(t) })}
        adding={adding}
        setAdding={setAdding}
        headless
      />
    </>
  )
}
