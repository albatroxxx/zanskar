import { useEffect, useState } from 'react'
import { api, errorMessage } from '../../api/client'
import type { Credential, EKSCheck, EKSSetup as Setup } from '../../api/types'
import { CopyButton } from '../../components/CopyButton'
import { Alert, Loading, Modal } from '../../components/ui'

/**
 * EKSSetup is an EKS role's page (ADR 0045, 8): the three pastes that let
 * the gateway reach the cluster as the role, and the test that it does.
 * The trust policy waits for the gateway's principal, as the autoscaling
 * page's does (ADR 0023): a policy with a placeholder looks finished and is
 * not.
 */
export function EKSSetup({ credential, onClose }: { credential: Credential; onClose: () => void }) {
  const [setup, setSetup] = useState<Setup | null>(null)
  const [err, setErr] = useState('')
  const [check, setCheck] = useState<EKSCheck | null>(null)
  const [testing, setTesting] = useState(false)

  useEffect(() => {
    let live = true
    api.get<Setup>(`/credentials/${credential.id}/eks/setup`).then(
      (s) => { if (live) setSetup(s) },
      (e) => { if (live) setErr(errorMessage(e)) },
    )
    return () => { live = false }
  }, [credential.id])

  const test = async () => {
    setTesting(true)
    setErr('')
    try {
      setCheck(await api.post<EKSCheck>(`/credentials/${credential.id}/eks/describe`, {}))
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setTesting(false)
    }
  }

  return (
    <Modal title={`${credential.name}: EKS role`} onClose={onClose} width={720}>
      {err && <Alert tone="danger" onDismiss={() => setErr('')}>{err}</Alert>}
      {!setup && !err && <Loading />}
      {setup && (
        <>
          <dl className="kv">
            <dt>Cluster</dt><dd className="mono">{credential.eks_cluster} · {credential.aws_region}</dd>
            <dt>Role</dt><dd className="mono">{credential.aws_role_arn}</dd>
            <dt>Gateway principal</dt>
            <dd className="mono">{setup.gateway_principal ?? <span className="muted">{setup.principal_error ?? 'unknown'}</span>}</dd>
          </dl>
          <h3>1 · Trust policy</h3>
          {setup.trust_policy ? (
            <Paste text={setup.trust_policy} name="trust policy" />
          ) : (
            <Alert tone="warn">The gateway's AWS principal is not known, so the trust policy cannot be written.</Alert>
          )}
          <h3>2 · Permissions policy</h3>
          <Paste text={setup.permissions_policy} name="permissions policy" />
          <h3>3 · Map the role in the cluster</h3>
          <p className="muted">Authentication mode API or API_AND_CONFIG_MAP:</p>
          <Paste text={setup.access_entry} name="access entry" />
          <p className="muted">Authentication mode CONFIG_MAP, under <code>mapRoles</code> in <code>aws-auth</code>:</p>
          <Paste text={setup.aws_auth} name="aws-auth entry" />
          <p className="muted">Then the cluster's RBAC manifest, from its page, binds the user <code>{setup.username}</code>.</p>
          <div className="actions">
            <button className="btn" onClick={() => void test()} disabled={testing}>{testing ? 'Testing…' : 'Test'}</button>
            {check && (check.ok ? (
              <span>
                Assumed <span className="mono">{check.assumed_arn}</span>; {check.cluster?.name} {check.cluster?.version} is {check.cluster?.status?.toLowerCase()} ({check.cluster?.authentication_mode}).
              </span>
            ) : (
              <span style={{ color: 'var(--danger)' }}>{check.stage === 'assume' ? 'Not assumed' : 'Not described'}: {check.error}</span>
            ))}
          </div>
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
