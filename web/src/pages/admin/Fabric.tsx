import { useEffect, useState } from 'react'
import { Navigate, useNavigate, useParams } from 'react-router-dom'
import { api } from '../../api/client'
import { platformName } from '../../api/format'
import type { AdminOverview, KubePlatform } from '../../api/types'
import { TileIcon } from '../../components/icons'
import { PageHead, StatTile, Tabs } from '../../components/ui'
import { Kubernetes } from './Kubernetes'

// Fabric (ADR 0048): Kubernetes clusters, reached through the gateway as
// the person. It reads Kubernetes in the sidebar and as the heading (the
// owner, 2026-11-13: everything in it is Kubernetes, so the section's own
// name says nothing); the route and the code keep the section's name. A
// tab per platform (each its own thing, Vanilla since all four are
// Kubernetes), and a tile per platform above them that opens its tab;
// /admin/fabric/<platform> names the open one. Autoscaling groups were the first tab for a day (2026-11-12) and
// went back to their own page: a person opens an instance as they open a
// host, so the groups belong beside the hosts.
export const platforms: { key: KubePlatform; icon: 'k8s' | 'eks' | 'gke' | 'aks' }[] = [
  { key: 'vanilla', icon: 'k8s' },
  { key: 'eks', icon: 'eks' },
  { key: 'gke', icon: 'gke' },
  { key: 'aks', icon: 'aks' },
]

export function Fabric() {
  const { kind = 'vanilla' } = useParams()
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
  // The one-tab address of the day before (2026-11-12) opens the first platform.
  if (kind === 'kubernetes') return <Navigate to="/admin/fabric" replace />
  const open = platforms.find((p) => p.key === kind)
  if (!open) return <Navigate to="/admin/fabric" replace />
  return (
    <>
      <PageHead title="Kubernetes">
        <button className="btn primary" onClick={() => setAdding(true)}>Add cluster</button>
      </PageHead>
      <div className="stat-grid platforms">
        {platforms.map((p) => (
          <StatTile key={p.key} value={counts ? (counts.clusters_by_platform[p.key] ?? 0) : null} label={platformName(p.key)} icon={<TileIcon kind={p.icon} />} to={`/admin/fabric/${p.key}`} selected={p.key === open.key} />
        ))}
      </div>
      <Tabs<KubePlatform> label="Platforms" value={open.key} onChange={(k) => nav(`/admin/fabric/${k}`)} tabs={platforms.map((p) => ({ key: p.key, label: platformName(p.key) }))} />
      <Kubernetes key={open.key} platform={open.key} adding={adding} setAdding={setAdding} />
    </>
  )
}
