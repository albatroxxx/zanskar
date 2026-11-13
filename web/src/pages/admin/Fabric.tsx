import { useState } from 'react'
import { Navigate, useNavigate, useParams } from 'react-router-dom'
import { PageHead, Tabs } from '../../components/ui'
import { Kubernetes } from './Kubernetes'

// Fabric (ADR 0048): Kubernetes clusters, vanilla and managed, reached
// through the gateway as the person. One tab today; /admin/fabric/<kind>
// names the open one. Autoscaling groups were its first tab for a day
// (2026-11-12) and went back to their own page: a person opens an
// instance as they open a host, so the groups belong beside the hosts.
const kinds = [{ key: 'kubernetes', label: 'Kubernetes', add: 'Add cluster' }] as const
type Kind = (typeof kinds)[number]['key']

export function Fabric() {
  const { kind = 'kubernetes' } = useParams()
  const nav = useNavigate()
  const [adding, setAdding] = useState(false)
  if (kind === 'autoscaling') return <Navigate to="/admin/autoscaling" replace />
  const open = kinds.find((k) => k.key === kind)
  if (!open) return <Navigate to="/admin/fabric" replace />
  return (
    <>
      <PageHead title="Fabric">
        <button className="btn primary" onClick={() => setAdding(true)}>{open.add}</button>
      </PageHead>
      <Tabs<Kind> label="Fabric" value={open.key} onChange={(k) => nav(`/admin/fabric/${k}`)} tabs={kinds.map(({ key, label }) => ({ key, label }))} />
      <Kubernetes adding={adding} setAdding={setAdding} />
    </>
  )
}
