// The words the Events page uses for audit events: action names, object
// types and the one-line sentence per event. Kept apart from the page so the
// wording can be tested, since a reader sees words and never ids.
import { shortId } from '../../api/format'
import type { AuditEvent } from '../../api/types'

/** Readable names for the action codes the gateway records. The code stays
 *  the stored value and the filter key (and what a SIEM correlates on), so it
 *  is kept one hover away; people read the label. */
const actionLabels: Record<string, string> = {
  'access.grant.expire': 'Access grant expired',
  'access.request.approve': 'Access request approved',
  'access.request.create': 'Access requested',
  'access.request.deny': 'Access request denied',
  'access.request.revoke': 'Access request revoked',
  'asg.create': 'Autoscaling group created',
  'asg.update': 'Autoscaling group updated',
  'asg.delete': 'Autoscaling group deleted',
  'asg.sync': 'Autoscaling group synced',
  'asg.test': 'Autoscaling group role tested',
  'asg.credential.set': 'Autoscaling group credential set',
  'asg.credential.unset': 'Autoscaling group credential removed',
  'asg.external_id.rotate': 'Autoscaling group ExternalId rotated',
  'asg.instance.joined': 'Instance joined autoscaling group',
  'asg.instance.left': 'Instance left autoscaling group',
  'asg.instance.unhealthy': 'Instance became unhealthy',
  'asg.instance.certificate.changed': 'Instance certificate changed',
  'asg.instance.hostkey.changed': 'Instance host key changed',
  'asg.instance.hostkey.mismatch': 'Instance host key changed',
  'audit.read': 'Audit log viewed',
  'audit.reseal': 'Audit chain resealed',
  'aws.identity.refresh': 'AWS principal checked',
  'credential.create': 'Credential created',
  'credential.update': 'Credential updated',
  'credential.delete': 'Credential deleted',
  'credential.rotate': 'Credential rotated',
  'credential.rotate.prepare': 'Authority next key prepared',
  'credential.rotate.cancel': 'Authority prepared key discarded',
  'credential.rotate.retire': 'Authority old key retired',
  'database.proxy_image': 'Database relay image changed',
  'file.download': 'File downloaded',
  'file.upload': 'File uploaded',
  'group.create': 'Group created',
  'group.update': 'Group updated',
  'group.delete': 'Group deleted',
  'group.members.update': 'Group members updated',
  'idp.create': 'Identity provider created',
  'idp.update': 'Identity provider updated',
  'idp.delete': 'Identity provider deleted',
  'idp.test': 'Identity provider tested',
  'key.rotate': 'Encryption key rotated',
  'key.rotate_master': 'Master key rotated',
  'logs.download': 'Logs downloaded',
  'policy.create': 'Policy created',
  'policy.update': 'Policy updated',
  'policy.delete': 'Policy deleted',
  'recording.download': 'Recording downloaded',
  'recording.purge': 'Recordings purged',
  'recording.view': 'Recording played',
  'recording.storage.move': 'Recordings moved to new storage',
  'recording.storage.update': 'Recording storage changed',
  'recording.storage.reset': 'Recording storage reset',
  'retention.policy.update': 'Retention policy updated',
  'session.connect': 'Session requested',
  'session.start': 'Session started',
  'session.end': 'Session ended',
  'session.terminate': 'Session terminated',
  'session.failover': 'Session failed over',
  'session.shadow.start': 'Started watching a session',
  'session.shadow.end': 'Stopped watching a session',
  'settings.update': 'Settings updated',
  'settings.reset': 'Settings reset',
  'system.start': 'Gateway started',
  'system.restart': 'Gateway restart requested',
  'system.restart_cancel': 'Gateway restart cancelled',
  'target.create': 'Target created',
  'target.update': 'Target updated',
  'target.delete': 'Target deleted',
  'target.credential.set': 'Target credential set',
  'target.credential.unset': 'Target credential removed',
  'target.hostkey.trust': 'Target host key trusted',
  'target.hostkey.changed': 'Target host key changed',
  'target.hostkey.mismatch': 'Target host key changed',
  'target.probe': 'Target connection tested',
  'target.probe.certificate': 'Target certificate login tested',
  'target.tls.mismatch': 'Target certificate changed',
  'tls.certificate.upload': 'TLS certificate uploaded',
  'tls.certificate.regenerate': 'TLS certificate regenerated',
  'tls.certificate.reset': 'TLS certificate reset',
  'user.create': 'User created',
  'user.update': 'User updated',
  'user.delete': 'User deleted',
  'user.login': 'Sign-in',
  'user.logout': 'Sign-out',
  'user.mfa.enroll': 'Authenticator enrollment started',
  'user.mfa.confirm': 'Authenticator enrolled',
  'user.mfa.verify': 'Second factor checked',
  'user.mfa.reset': 'Authenticator reset',
  'user.password.change': 'Password changed',
  'user.password.reset': 'Password reset',
  'user.roles.update': 'User roles updated',
  'user.sessions.revoke': 'User signed out everywhere',
}

const acronyms: Record<string, string> = { mfa: 'MFA', tls: 'TLS', aws: 'AWS', asg: 'autoscaling group', idp: 'identity provider' }

/** humanAction names an action code for people. Codes without a label (a
 *  newer gateway than this console) still read as words, never as a code. */
export function humanAction(code: string): string {
  if (actionLabels[code]) return actionLabels[code]
  const s = code.split(/[._]/).map((w) => acronyms[w] ?? w).join(' ')
  return s.charAt(0).toUpperCase() + s.slice(1)
}

export const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1)

export const typeLabel: Record<string, string> = {
  target: 'target',
  credential: 'credential',
  access_policy: 'policy',
  group: 'group',
  user: 'user',
  identity_provider: 'identity provider',
  autoscaling_group: 'autoscaling group',
  asg_instance: 'instance',
  access_session: 'session',
  access_request: 'access request',
  session: 'session',
  recording: 'recording',
  audit_log: 'audit log',
}

const verbs: Record<string, string> = {
  create: 'created', update: 'updated', delete: 'deleted', probe: 'probed', sync: 'synced', rotate: 'rotated',
  set: 'set', unset: 'removed', trust: 'trusted', reset: 'reset', revoke: 'revoked', test: 'tested',
  change: 'changed', approve: 'approved', deny: 'denied', expire: 'expired', upload: 'uploaded',
  download: 'downloaded', purge: 'purged', move: 'moved', regenerate: 'regenerated',
}

/** session splits "user → target (PROTO)" as the API labels sessions and recordings. */
function session(name?: string) {
  const m = /^(.+) → (.+) \((\w+)\)$/.exec(name ?? '')
  // SSH and RDP read as acronyms; DATABASE would read as a code.
  return m ? { user: m[1], target: m[2], proto: m[3] === 'DATABASE' ? 'database' : m[3] } : null
}

const str = (v: unknown) => (typeof v === 'string' ? v : '')
export const words = (s: string) => s.replace(/_/g, ' ')

/** describe turns an event into the sentence a reviewer wants: who did what,
 *  to which named thing. It falls back to the raw action for anything unknown. */
export function describe(ev: AuditEvent): string {
  const d = ev.details ?? {}
  const fail = ev.outcome === 'failure'
  const name = ev.object_name || (ev.object_id ? shortId(ev.object_id) : '')
  const s = session(ev.object_name)
  const proto = s?.proto ?? str(d.protocol).toUpperCase()
  const reason = str(d.reason)
  switch (ev.action) {
    case 'user.login':
      if (fail) return `failed to sign in${str(d.username) ? ` as ${str(d.username)}` : ''}${reason ? ` (${words(reason)})` : ''}`
      if (d.stage === 'password') return d.next === 'mfa_enrollment' ? 'entered a valid password; authenticator enrollment pending' : 'entered a valid password; second factor pending'
      return str(d.mfa) && d.mfa !== 'none' ? `signed in with ${str(d.mfa).toUpperCase()}` : 'signed in'
    case 'user.logout': return 'signed out'
    case 'user.mfa.enroll': return 'started enrolling an authenticator'
    case 'user.mfa.confirm': return fail ? 'failed to confirm an authenticator' : 'enrolled an authenticator'
    case 'user.mfa.verify': return fail ? 'failed the second factor' : 'passed the second factor'
    case 'session.connect': return fail ? `was refused ${proto} access to ${name}${reason ? ` (${words(reason)})` : ''}` : `requested ${proto} access to ${name}`
    case 'session.start': return s ? `opened a ${s.proto} session on ${s.target}` : `opened a session ${name}`
    case 'session.end': return s ? `ended the ${s.proto} session on ${s.target}${reason ? ` (${words(reason)})` : ''}` : `ended session ${name}`
    case 'session.terminate': return s ? `terminated ${s.user}'s ${s.proto} session on ${s.target}` : `terminated session ${name}`
    case 'session.shadow.start': return s ? `started watching ${s.user}'s ${s.proto} session on ${s.target}` : `started watching session ${name}`
    case 'session.shadow.end': return s ? `stopped watching ${s.user}'s session on ${s.target}` : `stopped watching session ${name}`
    case 'session.failover': return s ? `moved the ${s.proto} session on ${s.target} to another instance` : `failed over session ${name}`
    case 'recording.view': return s ? `played the recording of ${s.user} on ${s.target} (${s.proto})` : `played recording ${name}`
    case 'audit.read': return 'viewed the audit log'
    // Access requests resolve to "requester → target (PROTO)", like sessions.
    // Without a label (the request was deleted with its user) the sentence
    // still reads as words rather than an id.
    case 'access.request.create': return s ? `requested ${s.proto} access to ${s.target}` : 'requested access'
    case 'access.request.approve': return s ? `approved ${s.user}'s request for ${s.proto} access to ${s.target}` : 'approved an access request'
    case 'access.request.deny': return s ? `denied ${s.user}'s request for ${s.proto} access to ${s.target}` : 'denied an access request'
    case 'access.request.revoke': return s ? `revoked ${s.user}'s ${s.proto} access to ${s.target}` : 'revoked an access grant'
    case 'access.grant.expire': return s ? `ended ${s.user}'s ${s.proto} access to ${s.target} (time limit reached)` : 'ended an access grant (time limit reached)'
    case 'target.hostkey.trust': return `trusted the host key of target ${name}`
    case 'target.hostkey.changed':
    case 'target.hostkey.mismatch': return `saw a changed host key on target ${name}`
    case 'target.tls.mismatch': return `saw a changed certificate on target ${name}`
    case 'target.credential.set': return `set a credential on target ${name}`
    case 'target.credential.unset': return `removed a credential from target ${name}`
    case 'asg.credential.set': return `set a credential on autoscaling group ${name}`
    case 'asg.credential.unset': return `removed a credential from autoscaling group ${name}`
    case 'asg.external_id.rotate': return `rotated the ExternalId of autoscaling group ${name}`
    case 'asg.test': return `tested the role of autoscaling group ${name}`
    case 'aws.identity.refresh': return 'checked the AWS principal of the gateway'
    case 'target.probe.certificate': return `tested a certificate login on target ${name}`
    case 'credential.rotate.prepare': return `prepared the next key of authority ${name}`
    case 'credential.rotate.cancel': return `discarded the prepared key of authority ${name}`
    case 'credential.rotate.retire': return `confirmed the retired key of authority ${name} is removed from targets`
    case 'asg.instance.joined': return `instance ${name} joined autoscaling group ${str(d.name)}`
    case 'asg.instance.left': return `instance ${name} left autoscaling group ${str(d.name)}`
    case 'asg.instance.unhealthy': return `instance ${name} became unhealthy in autoscaling group ${str(d.name)}`
    case 'asg.instance.hostkey.changed':
    case 'asg.instance.hostkey.mismatch': return `saw a changed host key on instance ${name}`
    case 'group.members.update': return `updated the members of group ${name}`
    case 'user.roles.update': return `updated the roles of user ${name}`
    case 'user.password.change': return fail ? 'failed to change their password' : 'changed their password'
    case 'user.password.reset': return `reset the password of user ${name}`
    case 'user.mfa.reset': return `reset the authenticator of user ${name}`
    case 'user.sessions.revoke': return `signed user ${name} out everywhere`
    default: {
      const parts = ev.action.split('.')
      const verb = verbs[parts[parts.length - 1]] ?? words(parts[parts.length - 1])
      const type = typeLabel[ev.object_type] ?? words(ev.object_type || parts[0])
      return `${fail ? 'failed to ' + (verbs[parts[parts.length - 1]] ? parts[parts.length - 1] : verb) : verb} ${type}${name ? ' ' + name : ''}`
    }
  }
}

export function who(ev: AuditEvent): { name: string; system: boolean } {
  if (ev.actor_username) return { name: ev.actor_username, system: false }
  // A user id the API could not name belongs to a deleted account: say so in
  // words; the id stays in the event's details and exports.
  if (ev.actor_user_id) return { name: 'deleted user', system: false }
  return { name: ev.actor_ip === 'sync' ? 'gateway' : 'system', system: true }
}
