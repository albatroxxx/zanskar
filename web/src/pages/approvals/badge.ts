import { api } from '../../api/client'
import type { AccessRequest, Page } from '../../api/types'

/** pendingForMe feeds an approver's Approvals badge (ADR 0049): how many
 *  requests in their scope await a decision. The approver's page shares its
 *  own count when it reads them. */
export const pendingForMe = () => api.cached<Page<AccessRequest>>('/access-requests?scope=mine&status=pending', 30_000).then((p) => (p.items ?? []).length)
