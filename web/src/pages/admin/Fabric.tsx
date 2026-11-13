import { useEffect, useState } from 'react'
import { Navigate, useNavigate, useParams } from 'react-router-dom'
import { api } from '../../api/client'
import { platformName } from '../../api/format'
import type { AdminOverview, KubePlatform } from '../../api/types'
import { TileIcon } from '../../components/icons'
import { PageHead, StatTile, Tabs } from '../../components/ui'
import { Kubernetes } from './Kubernetes'

// Fabric (ADR 0048): Kubernetes clusters, vanilla and managed, reached
// through the gateway as the person. One tab today; /admin/fabric/<kind>
// names the open one. Autoscaling groups were its first tab for a day
// (2026-11-12) and went back to their own page: a person opens an
// instance as they open a host, so the groups belong beside the hosts.
const kinds = [{ key: 'kubernetes', label: 'Kubernetes', add: 'Add cluster' }] as const
type Kind = (typeof kinds)[number]['key']

// The four platforms, one tile each (the owner, 2026-11-13): a glyph, the
// count of clusters of that platform, and the list narrowed to it.
const platforms: { key: KubePlatform; icon: 'k8s' | 'eks' | 'gke' | 'aks' }[] = [
  { key: 'vanilla', icon: 'k8s' },
  { key: 'eks', icon: 'eks' },
  { key: 'gke', icon: 'gke' },
  { key: 'aks', icon: 'aks' },
]

export function Fabric() {
  const { kind = 'kubernetes' } = useParams()
  const nav = useNavigate()
  const [adding, setAdding] = useState(false)
  const [counts, setCounts] = useState<AdminOverview['inventory'] | null>(null)
  useEffect(() => {
    api
      .get<AdminOverview>('/admin/overview')
      .then((o) => setCounts(o.inventory))
      .catch(() => setCounts(null))
  }, [])
  if (kind === 'autoscaling') return <Navigate to="/admin/autoscaling" replace />
  const open = kinds.find((k) => k.key === kind)
  if (!open) return <Navigate to="/admin/fabric" replace />
  return (
    <>
      <PageHead title="Fabric">
        <button className="btn primary" onClick={() => setAdding(true)}>{open.add}</button>
      </PageHead>
      <Tabs<Kind> label="Fabric" value={open.key} onChange={(k) => nav(`/admin/fabric/${k}`)} tabs={kinds.map(({ key, label }) => ({ key, label }))} />
      <div className="stat-grid platforms">
        {platforms.map((p) => (
          <StatTile key={p.key} value={counts ? (counts.clusters_by_platform[p.key] ?? 0) : null} label={platformName(p.key)} icon={<TileIcon kind={p.icon} />} to={`/admin/fabric/kubernetes?platform=${p.key}`} />
        ))}
      </div>
      <Kubernetes adding={adding} setAdding={setAdding} />
    </>
  )
}
