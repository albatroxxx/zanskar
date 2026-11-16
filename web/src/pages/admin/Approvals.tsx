import { PageHead } from '../../components/ui'
import { ApprovalsQueue } from '../approvals/ApprovalsQueue'

/** Approvals is the admin queue for just-in-time access requests (ADR 0018):
 *  every request, with the approvers a grant names (ADR 0049), whose
 *  requests an administrator sees and revokes but does not decide. */
export function Approvals() {
  return (
    <>
      <PageHead title="Approvals" />
      <ApprovalsQueue scope="all" badgePath="/admin/approvals" />
    </>
  )
}
