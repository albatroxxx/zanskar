import { useState } from 'react'
import { Navigate, useNavigate, useParams } from 'react-router-dom'
import { PageHead, Tabs } from '../../components/ui'
import { AutoscalingGroups } from './Autoscaling'

// Fabric (ADR 0048): what Zanskar reaches through a control plane, where
// the members come and go. A tab per kind, added as each kind is built;
// /admin/fabric/<kind> names the open one.
const kinds = [{ key: 'autoscaling', label: 'Autoscaling', add: 'Enroll group' }] as const
type Kind = (typeof kinds)[number]['key']

export function Fabric() {
  const { kind = 'autoscaling' } = useParams()
  const nav = useNavigate()
  const [adding, setAdding] = useState(false)
  const open = kinds.find((k) => k.key === kind)
  if (!open) return <Navigate to="/admin/fabric" replace />
  return (
    <>
      <PageHead title="Fabric">
        <button className="btn primary" onClick={() => setAdding(true)}>{open.add}</button>
      </PageHead>
      <Tabs<Kind> label="Fabric" value={open.key} onChange={(k) => nav(`/admin/fabric/${k}`)} tabs={kinds.map(({ key, label }) => ({ key, label }))} />
      {open.key === 'autoscaling' && <AutoscalingGroups adding={adding} setAdding={setAdding} />}
    </>
  )
}
