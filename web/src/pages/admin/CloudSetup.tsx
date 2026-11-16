import { useEffect, useState } from 'react'
import { api, errorMessage } from '../../api/client'
import type { CloudSetup as Setup, Target } from '../../api/types'
import { CopyButton } from '../../components/CopyButton'
import { Alert, Loading, Modal } from '../../components/ui'
import { accountLabel } from './cloudNames'

/**
 * CloudSetup is a cloud role's pastes (ADR 0050): the trust policy that lets
 * this gateway, and nothing else, assume the role with the ExternalId Zanskar
 * minted, and the one-line CLI and the CloudFormation that create the role
 * with it. The trust policy waits for the gateway's principal, as the
 * autoscaling and EKS pages' do (ADR 0023): a policy with a placeholder looks
 * finished and is not.
 */
export function CloudSetup({ target, onClose }: { target: Target; onClose: () => void }) {
  const [setup, setSetup] = useState<Setup | null>(null)
  const [err, setErr] = useState('')
  const [checking, setChecking] = useState(false)

  useEffect(() => {
    let live = true
    api.get<Setup>(`/targets/${target.id}/cloud/setup`).then(
      (s) => { if (live) setSetup(s) },
      (e) => { if (live) setErr(errorMessage(e)) },
    )
    return () => { live = false }
  }, [target.id])
  const check = async () => {
    setChecking(true)
    setErr('')
    try {
      setSetup(await api.get<Setup>(`/targets/${target.id}/cloud/setup`))
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setChecking(false)
    }
  }

  return (
    <Modal title={`${target.name}: setup`} onClose={onClose} width={720}>
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      {!setup && !err && <Loading />}
      {setup && (
        <>
          <dl className="kv">
            <dt>Account</dt><dd className="mono">{accountLabel(target)}</dd>
            <dt>Role</dt><dd className="mono">{target.cloud_role_arn}</dd>
            <dt>Gateway principal</dt>
            <dd className="mono">{setup.principal ?? <span className="muted">unknown</span>}</dd>
            <dt>External ID</dt><dd className="mono">{setup.external_id}</dd>
          </dl>
          <h3>1 · Trust policy</h3>
          {setup.pending ? (
            <>
              <Alert tone="warn">The gateway's AWS principal is not known yet.</Alert>
              <div className="actions">
                <button className="btn" onClick={() => void check()} disabled={checking}>{checking ? 'Checking…' : 'Check again'}</button>
              </div>
            </>
          ) : (
            <>
              <Paste text={setup.trust_policy} name="trust policy" />
              <h3>2 · Create the role</h3>
              <Paste text={setup.cli} name="CLI" />
              <h3>3 · CloudFormation</h3>
              <Paste text={setup.cloudformation} name="CloudFormation" />
            </>
          )}
        </>
      )}
    </Modal>
  )
}

function Paste({ text, name }: { text: string; name: string }) {
  return (
    <div>
      <pre className="mono" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: '4px 0' }}>{text}</pre>
      <CopyButton text={text} name={name} />
    </div>
  )
}
