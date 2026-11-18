import { Navigate, useParams } from 'react-router-dom'

// The Kubernetes section read /admin/fabric until 2.0.0 (the owner,
// 2026-11-16: the address should say what the sidebar says; ADR 0048,
// decision 7). An old address leads to the new one, its tab kept; the page
// then sorts out a tab it no longer has, as it always did.
export function FabricMoved() {
  const { kind } = useParams()
  return <Navigate to={kind ? `/admin/kubernetes/${encodeURIComponent(kind)}` : '/admin/kubernetes'} replace />
}
