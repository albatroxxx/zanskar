// The words the Events page uses for audit events: action names, object
// types and the one-line sentence per event. Kept apart from the page so the
// wording can be tested, since a reader sees words and never ids.
import { fmtPreciseTime, protocolName, shortId } from '../../api/format'
import type { AuditEvent, AuditTallies } from '../../api/types'

/** Readable names for the action codes the gateway records. The code stays
 *  the stored value and the filter key (and what a SIEM correlates on), so it
 *  is kept one hover away; people read the label. */
const actionLabels: Record<string, string> = {
  'access.grant.expire': 'Access grant expired',
  'access.request.approve': 'Access request approved',
  'access.request.create': 'Access requested',
  'access.request.deny': 'Access request denied',
  'access.request.revoke': 'Access request revoked',
  'api_token.create': 'API token created',
  'api_token.revoke': 'API token revoked',
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
  'config.export': 'Configuration exported',
  'config.import': 'Configuration imported',
  'credential.create': 'Credential created',
  'credential.update': 'Credential updated',
  'credential.delete': 'Credential deleted',
  'credential.rotate': 'Credential rotated',
  'credential.rotate.prepare': 'Authority next key prepared',
  'credential.rotate.cancel': 'Authority prepared key discarded',
  'credential.rotate.retire': 'Authority old key retired',
  'credential.test': 'Cluster role tested',
  'cli.command': 'Command line used',
  'cli.unlock': 'Command line opened',
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
  'idp.sync': 'Directory users synced',
  'idp.scim': 'SCIM request refused',
  'idp.scim_token': 'SCIM token changed',
  'key.rotate': 'Encryption key rotated',
  'key.rotate_master': 'Master key rotated',
  'logs.download': 'Logs downloaded',
  'notify.channel.create': 'Notification channel added',
  'notify.channel.update': 'Notification channel changed',
  'notify.channel.delete': 'Notification channel removed',
  'notify.channel.test': 'Notification channel tested',
  'notify.channel.key': 'Notification signing key changed',
  'notify.email_server.update': 'Email server set',
  'notify.email_server.delete': 'Email server removed',
  'notify.email_server.test': 'Email server tested',
  'policy.create': 'Policy created',
  'policy.review': 'Access review completed',
  'policy.update': 'Policy updated',
  'policy.delete': 'Policy deleted',
  'recording.download': 'Recording downloaded',
  'recording.lost': 'Recording could not be saved',
  'recording.purge': 'Recordings purged',
  'recording.search': 'Recordings searched',
  'recording.view': 'Recording played',
  'recording.storage.move': 'Recordings moved to new storage',
  'recording.storage.update': 'Recording storage changed',
  'recording.storage.reset': 'Recording storage reset',
  'retention.policy.update': 'Retention policy updated',
  'session.connect': 'Session requested',
  'session.start': 'Session started',
  'session.end': 'Session ended',
  'session.terminate': 'Session terminated',
  'session.watcher.wait': 'Session waiting for a watcher',
  'session.failover': 'Session failed over',
  'session.shadow.start': 'Started watching a session',
  'session.shadow.end': 'Stopped watching a session',
  'settings.update': 'Settings updated',
  'settings.reset': 'Settings reset',
  'settings.boot_request': 'Install settings change requested',
  'settings.boot_apply': 'Install settings change applied',
  'system.restart': 'Gateway restart requested',
  'system.restart_cancel': 'Gateway restart cancelled',
  'system.reboot': 'Host reboot requested',
  'system.poweroff': 'Host power-off requested',
  'system.update': 'Gateway update requested',
  'system.images_remove': 'Old images removed',
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
  'target.tls.changed': 'Target certificate changed',
  'target.tls.trust': 'Target certificate accepted',
  'tls.certificate.upload': 'TLS certificate uploaded',
  'tls.certificate.regenerate': 'TLS certificate regenerated',
  'tls.certificate.reset': 'TLS certificate reset',
  'user.create': 'User created',
  'user.update': 'User updated',
  'user.delete': 'User deleted',
  'user.link': 'Account linked to its identity provider',
  'user.groups.sync': 'Group memberships updated at sign-in',
  'user.login': 'Sign-in',
  'user.logout': 'Sign-out',
  'user.mfa.enroll': 'Authenticator enrollment started',
  'user.mfa.confirm': 'Authenticator enrolled',
  'user.mfa.verify': 'Second factor checked',
  'user.mfa.reset': 'Authenticator reset',
  'user.mfa.recovery_codes': 'Recovery codes replaced',
  'user.key.register': 'Security key added',
  'user.key.rename': 'Security key renamed',
  'user.key.remove': 'Security key removed',
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

/** What a failed action is called in the plural, for the common ones. */
/** secondFactorWords names how a sign-in passed its second step. */
const secondFactorWords: Record<string, string> = { totp: 'TOTP', webauthn: 'a security key', recovery_code: 'a recovery code' }

const failedNoun: Record<string, string> = {
  'idp.sync': 'provider syncs',
  'user.login': 'sign-ins',
  'session.connect': 'refused connections',
  'session.end': 'sessions ending in error',
  'cli.unlock': 'command line codes',
  'user.mfa.verify': 'second-factor checks',
}

/** failureDetail says what most of a day's failed actions were, under the
 *  dashboards' count: "mostly provider syncs (19)", "all sign-ins", or for a
 *  plurality "most often …" (2026-11-03 live audit, Q2). */
export function failureDetail(t: Pick<AuditTallies, 'failures' | 'top_failure' | 'top_failure_count'>): string | undefined {
  const n = t.top_failure_count ?? 0
  if (!t.top_failure || n <= 0 || t.failures <= 0) return undefined
  const what = failedNoun[t.top_failure]
  // An action without a plural noun here is named by its label instead.
  if (!what) return `${Math.min(n, t.failures)} of ${t.failures}: ${humanAction(t.top_failure)}`
  if (n >= t.failures) return `all ${what}`
  return n * 2 > t.failures ? `mostly ${what} (${n})` : `most often ${what} (${n})`
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
  notification_channel: 'notification channel',
  email_server: 'email server',
  retention_policy: 'retention policy',
  cli: 'command line',
}

const verbs: Record<string, string> = {
  create: 'created', update: 'updated', delete: 'deleted', probe: 'probed', sync: 'synced', rotate: 'rotated',
  set: 'set', unset: 'removed', trust: 'trusted', reset: 'reset', revoke: 'revoked', test: 'tested',
  change: 'changed', approve: 'approved', deny: 'denied', expire: 'expired', upload: 'uploaded',
  download: 'downloaded', purge: 'purged', move: 'moved', regenerate: 'regenerated', review: 'reviewed',
}

// How a command line entry ended, beside the line itself; ok needs no note.
const cliResults: Record<string, string> = {
  confirm_requested: 'asked to confirm', cancelled: 'cancelled', invalid: 'not understood', unknown: 'not a command',
  denied: 'refused', error: 'failed', locked: 'needed a code first',
}

/** session splits "user → target (PROTO)" as the API labels sessions and recordings. */
function session(name?: string) {
  const m = /^(.+) → (.+) \((\w+)\)$/.exec(name ?? '')
  return m ? { user: m[1], target: m[2], proto: m[3] } : null
}

const str = (v: unknown) => (typeof v === 'string' ? v : '')
export const words = (s: string) => s.replace(/_/g, ' ')

/** article is "a" or "an" before a word as it is said: an acronym is spelled
 *  out (an HTTP, an SSH, an RDP, a VNC), anything else goes by its first letter. */
export function article(word: string): 'a' | 'an' {
  const w = word.trim()
  if (w.length > 1 && w === w.toUpperCase() && /^[A-Z]/.test(w)) return /^[AEFHILMNORSX]/.test(w) ? 'an' : 'a'
  return /^[aeiou]/i.test(w) ? 'an' : 'a'
}

/** installVariables are the environment variables an install settings change
 *  names. The request records them as {NAME: value} (the values stay in the
 *  details), the helper's answer as a list of names; neither holds a secret. */
function installVariables(d: Record<string, unknown>): string[] {
  const v = d.changes ?? d.changed
  if (Array.isArray(v)) return v.filter((n): n is string => typeof n === 'string' && n !== '')
  return v && typeof v === 'object' ? Object.keys(v) : []
}

/** describe turns an event into the sentence a reviewer wants: who did what,
 *  to which named thing. It falls back to the raw action for anything unknown. */
export function describe(ev: AuditEvent): string {
  const d = ev.details ?? {}
  const fail = ev.outcome === 'failure'
  // An id is shortened, a setting's key ("display.theme", "login_banner") is
  // its name and is not (it read "updated setting display."), and the delete
  // event of an account already says what it did, so the "(deleted)" the
  // resolver appends to a gone account's name is dropped from its sentence.
  const opaque = /^[0-9a-f]{8,}$/.test(ev.object_id ?? '')
  let name = ev.object_name || (ev.object_id ? (opaque ? shortId(ev.object_id) : ev.object_id) : '')
  if (ev.action === 'user.delete') name = name.replace(/ \(deleted\)$/, '')
  const s = session(ev.object_name)
  const proto = s?.proto ?? protocolName(str(d.protocol))
  const reason = str(d.reason)
  switch (ev.action) {
    case 'user.login':
      if (fail) return `failed to sign in${str(d.username) ? ` as ${str(d.username)}` : ''}${reason ? ` (${words(reason)})` : ''}`
      if (d.stage === 'password') return d.next === 'mfa_enrollment' ? 'entered a valid password; authenticator enrollment pending' : 'entered a valid password; second factor pending'
      return str(d.mfa) && d.mfa !== 'none' ? `signed in with ${secondFactorWords[str(d.mfa)] ?? str(d.mfa).toUpperCase()}` : 'signed in'
    case 'user.logout': return 'signed out'
    case 'user.mfa.enroll': return 'started enrolling an authenticator'
    case 'user.mfa.confirm': return fail ? 'failed to confirm an authenticator' : 'enrolled an authenticator'
    case 'user.mfa.verify':
      if (!fail) return d.method === 'webauthn' ? 'passed the second factor with a security key' : 'passed the second factor'
      if (reason === 'code_reused') return 'failed the second factor (a code already used)'
      if (reason === 'key_counter_went_back' || reason === 'key counter went back') return "failed the second factor (the key's counter went back: a copy may exist)"
      if (reason === 'key_required') return 'failed the second factor (a security key is required)'
      return 'failed the second factor'
    case 'user.mfa.recovery_codes': return 'replaced their recovery codes'
    case 'user.key.register': return fail ? 'failed to add a security key' : `added the security key ${str(d.name)}`.trimEnd()
    case 'user.key.rename': return 'renamed a security key'
    case 'user.key.remove': return `removed the security key ${str(d.name)}`.trimEnd()
    case 'session.connect': return fail ? `was refused ${proto} access to ${name}${reason ? ` (${words(reason)})` : ''}` : `requested ${proto} access to ${name}`
    case 'session.start': return s ? `opened ${article(s.proto)} ${s.proto} session on ${s.target}` : `opened a session ${name}`
    case 'session.end': {
      // A desktop that guacd ended carries guacd's words: "target lost: Upstream error."
      const why = [reason && words(reason), str(d.detail)].filter(Boolean).join(': ')
      return s ? `ended the ${s.proto} session on ${s.target}${why ? ` (${why})` : ''}` : `ended session ${name}`
    }
    case 'session.terminate': return s ? `terminated ${s.user}'s ${s.proto} session on ${s.target}` : `terminated session ${name}`
    case 'session.shadow.start': return s ? `started watching ${s.user}'s ${s.proto} session on ${s.target}` : `started watching session ${name}`
    case 'session.shadow.end': return s ? `stopped watching ${s.user}'s session on ${s.target}` : `stopped watching session ${name}`
    case 'session.failover': return s ? `moved the ${s.proto} session on ${s.target} to another instance` : `failed over session ${name}`
    case 'recording.view': return s ? `played the recording of ${s.user} on ${s.target} (${s.proto})` : `played recording ${name}`
    case 'recording.search': {
      // Live, 2026-11-11: it read "search recording", the one row that was
      // not a sentence; its term and count were only in the raw details.
      const n = typeof d.count === 'number' ? d.count : undefined
      const found = n === undefined ? '' : ` (${n} ${n === 1 ? 'match' : 'matches'})`
      return `searched the recordings' ${d.in === 'output' ? 'output' : 'commands'} for “${str(d.q)}”${found}`
    }
    case 'audit.read': return 'viewed the audit log'
    case 'cli.unlock':
      if (fail) return `failed to open the command line${reason ? ` (${reason})` : ''}`
      return d.recovery_code_used ? 'opened the command line with a recovery code' : 'opened the command line'
    case 'cli.command': {
      const line = str(d.line)
      const ran = line ? `“${line}”` : 'a line'
      const result = cliResults[str(d.result)]
      return `ran ${ran} on the command line${result ? ` (${result})` : ''}`
    }
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
    case 'target.tls.changed':
    case 'target.tls.mismatch': return `saw a changed certificate on target ${name}`
    case 'target.tls.trust': return `accepted a new certificate for target ${name}`
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
    // The gateway itself (object: system, gateway) and the mail server (object:
    // email_server, id 1): the sentence names the thing, never its id. A
    // success of a restart, an update or an install settings change is the
    // request; it happens after the drain, and a failure is a row of its own.
    case 'settings.boot_request': {
      const vars = installVariables(d)
      return `${fail ? 'failed to request' : 'requested'} an install settings change${vars.length ? ` (${vars.join(', ')})` : ''}`
    }
    case 'settings.boot_apply':
      if (!fail) return 'applied an install settings change'
      // rolled_back: written, the gateway did not come back, the old file is back.
      return `failed to apply an install settings change${d.state === 'rolled_back' ? ': rolled back' : ''}`
    case 'system.update': {
      const to = str(d.version) ? ` to ${str(d.version)}` : ''
      return fail ? `failed to update the gateway${to}` : `requested a gateway update${to}`
    }
    case 'system.restart': return fail ? 'failed to request a gateway restart' : 'requested a gateway restart'
    case 'system.restart_cancel': return fail ? 'failed to cancel the gateway restart' : 'cancelled the gateway restart'
    case 'system.reboot': return fail ? 'failed to request a host reboot' : 'requested a host reboot'
    case 'system.poweroff': return fail ? 'failed to request a host power-off' : 'requested a host power-off'
    case 'system.images_remove': return fail ? 'failed to remove old images' : 'removed old images'
    case 'config.export': return fail ? 'failed to export the configuration' : 'exported the configuration'
    case 'config.import': return fail ? 'failed to import the configuration' : 'imported the configuration'
    case 'notify.email_server.update': return fail ? 'failed to set the email server' : 'set the email server'
    case 'notify.email_server.delete': return fail ? 'failed to remove the email server' : 'removed the email server'
    case 'notify.email_server.test': return fail ? 'failed to test the email server' : 'tested the email server'
    default: {
      const parts = ev.action.split('.')
      const verb = verbs[parts[parts.length - 1]] ?? words(parts[parts.length - 1])
      const type = typeLabel[ev.object_type] ?? words(ev.object_type || parts[0])
      // A failed create has no object yet; the name asked for and why it was
      // refused are in its details (2026-11-04: "failed to create target").
      const label = name || (fail ? str(d.name) : '')
      const why = fail && reason ? ` (${words(reason)})` : ''
      return `${fail ? 'failed to ' + (verbs[parts[parts.length - 1]] ? parts[parts.length - 1] : verb) : verb} ${type}${label ? ' ' + label : ''}${why}`
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

const isoTime = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/

/** detailText is how a plain detail value reads: a timestamp as a date and
 *  time like the row's own (the exact value goes in title), anything else as
 *  itself. */
export function detailText(v: unknown): { text: string; title?: string } {
  if (typeof v === 'string' && isoTime.test(v)) return { text: fmtPreciseTime(v), title: v }
  return { text: String(v) }
}
