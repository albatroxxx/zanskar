// Types mirror docs/api/openapi.yaml and the Go JSON tags.

export type Role = 'admin' | 'auditor' | 'user'

export interface User {
  id: string
  username: string
  email?: string
  display_name: string
  status: 'active' | 'disabled' | 'locked'
  roles: Role[]
  /** An administrator set the password; the user replaces it at the next sign-in. */
  must_change_password?: boolean
  locked_until?: string
  created_at: string
  updated_at: string
  last_login_at?: string
  /** The identity provider the account belongs to, when one does. */
  idp_id?: string
  /** No password of its own: it signs in through an identity provider, linked or waiting for its first sign-in. */
  provider_sign_in?: boolean
}

export interface Me {
  csrf_token: string
  mfa_enrolled: boolean
  // Set on a partial (MFA-incomplete) session so a reload can resume the right
  // step; null/absent on a full session, where user and session are present.
  pending?: 'verify' | 'enroll' | 'password' | null
  user?: User
  session?: { id: string; created_at: string; expires_at: string }
  /** The console's time zone (display.time_zone); absent on a partial session. */
  time_zone?: string
}

export type LoginStatus = 'ok' | 'mfa_required' | 'mfa_enrollment_required' | 'password_change_required'
export interface LoginResponse { status: LoginStatus; csrf_token?: string; user?: User }

export interface Page<T> { items: T[]; next_cursor?: string }

export interface ApiErrorBody { code: string; message: string; request_id?: string }

/** How a target is reached; `http` is a web application opened in an isolated browser beside the gateway (ADR 0034). */
export type Protocol = 'ssh' | 'rdp' | 'vnc' | 'winrm' | 'database' | 'http'
export type OSFamily = 'linux' | 'windows' | 'other'
export type HostKeyStatus = 'unknown' | 'pending' | 'trusted' | 'changed'

/** One prerequisite of opening applications, from GET /admin/applications/readiness (ADR 0034):
 *  a guacd address, a container runtime the service can reach, and the browser image. */
export interface AppsCheck {
  key: 'guacd' | 'runtime' | 'image'
  title: string
  ok: boolean
  detail: string
}
export interface AppsReadiness {
  ready: boolean
  checks: AppsCheck[]
}

export interface Target {
  id: string
  name: string
  address: string
  os_family: OSFamily
  /** Database engine and version for database targets (ADR 0017); empty for hosts. */
  engine?: string
  engine_version?: string
  /** Recording retention override in days; null defers to the policy or the global policy. */
  retention_days?: number | null
  /** Database targets only: the database to open, and how the sidecar protects its upstream connection. */
  database_name?: string
  tls_mode?: 'disable' | 'prefer' | 'require' | 'verify-full'
  /** CA bundle the upstream is verified against: a database under verify-full, or an application's https upstream. */
  tls_ca?: string
  /** Application targets (ADR 0034): the one origin the isolated browser can reach. */
  app_upstream?: string
  ports: Partial<Record<Protocol, number>>
  capabilities: Protocol[]
  host_key_fingerprint: string | null
  host_key_status: HostKeyStatus
  tls_fingerprint: string | null
  winrm_tls_fingerprint: string | null
  /** A different certificate a probe saw after one was pinned; awaits confirmation (ADR 0012). */
  tls_fingerprint_pending?: string | null
  winrm_tls_fingerprint_pending?: string | null
  tags: Record<string, string>
  status: 'active' | 'disabled'
  notes: string
  credentials: Partial<Record<Protocol, string>>
  created_at: string
  updated_at: string
  last_probed_at: string | null
}

export interface PortResult { reachable: boolean; latency_ms: number; error?: string }

/** A probe as the gateway reports it. Mirrors internal/target.ProbeResult. */
export interface ProbeResult {
  address: string
  resolved_ip: string
  ports: Partial<Record<Protocol, PortResult>>
  capabilities: Protocol[]
  ssh_host_key?: { fingerprint: string; type: string; banner: string }
  /** The RDP listener's certificate. */
  tls?: { fingerprint: string; subject: string; source: string }
  /** The WinRM HTTPS listener's certificate. */
  winrm_tls?: { fingerprint: string; subject: string; source: string }
  vnc_version?: string
  probed_at: string
}

export interface ProbeResponse {
  target: Target
  probe: ProbeResult
  host_key_status: HostKeyStatus
  host_key_fingerprint: string | null
  host_key_changed_from?: string | null
}

export interface ReachableTarget {
  id: string
  name: string
  os_family: OSFamily
  tags: Record<string, string>
  capabilities: Protocol[]
  allowed_protocols: Protocol[]
  /** Allowed protocols that are approval-gated (ADR 0018): request access, don't connect directly. */
  requires_approval?: Protocol[]
  /** Allowed protocols on which the user may sign in with their own login (ADR 0036). */
  own_login?: Protocol[]
  host_key_ready: boolean
  /** Private (RFC1918/ULA) IP when the target has one; withheld for public addresses/hostnames. */
  private_ip?: string
  /** database engine when this is a database target (ADR 0017). */
  engine?: string
  /** "target" for a static machine, "asg" for an autoscaling group, "application" for a web app (ADR 0034); missing means "target". */
  kind?: 'target' | 'asg' | 'application'
  healthy_count?: number
  instance_count?: number
  /** An application's upstream, when the gateway chooses to show it; it opens through POST /connect like a desktop. */
  app_upstream?: string
}

export type AccessStatus = 'pending' | 'approved' | 'denied' | 'expired' | 'revoked'

/** A just-in-time access request and, once approved, the time-bounded grant (ADR 0018). */
export interface AccessRequest {
  id: string
  user_id: string
  policy_id?: string
  /** The approval grant whose maximum capped the request (ADR 0036). */
  grant_id?: string
  target_id?: string
  asg_id?: string
  protocol: Protocol
  reason: string
  requested_minutes: number
  status: AccessStatus
  approver_user_id?: string
  /** What the approver granted; may differ from requested_minutes. Zero until decided. */
  approved_minutes?: number
  /** The active grant this request asks to extend; the new grant runs on from its expiry. */
  extends_request_id?: string
  /** Resolved at read time. */
  username?: string
  approver_username?: string
  target_name?: string
  asg_name?: string
  decision_note?: string
  decided_at?: string
  expires_at?: string
  created_at: string
  updated_at: string
}

/** A healthy autoscaling instance a user may connect to. No addresses are exposed. */
export interface ReachableInstance {
  id: string
  instance_id: string
  availability_zone: string
  launched_at: string
  healthy: boolean
}

export type CredentialType = 'password' | 'ssh_key' | 'ssh_ca' | 'domain' | 'ec2_instance_connect'
export type CredentialMode = 'vaulted' | 'user_supplied' | 'passthrough'

export interface Credential {
  id: string
  name: string
  type: CredentialType
  mode: CredentialMode
  username?: string
  domain?: string
  public_key?: string
  has_secret: boolean
  key_version?: number
  created_at: string
  updated_at: string
  rotated_at?: string | null
  /** Counts of targets and autoscaling groups bound to it. */
  in_use_by?: { targets?: number; autoscaling_groups?: number }
  /** ssh_ca only (ADR 0022): lifetime of each session certificate (default 300 s) and the login users the authority issues for (empty = any). */
  certificate_ttl_seconds?: number
  certificate_principals?: string[]
  /** ssh_ca only: a prepared next key and/or a retired public key still to remove from targets (two-phase rotation, ADR 0022). */
  rotation?: { pending_public_key?: string; pending_since?: string; retired_public_key?: string; retired_at?: string }
}

/** POST /targets/{id}/probe-certificate: one real login with a certificate from the bound authority, then disconnect. */
export interface CertificateProbe {
  accepted: boolean
  key: 'current' | 'pending'
  login_user: string
  reason?: 'certificate_rejected' | 'host_key_mismatch' | 'unreachable'
  error?: string
}

export interface Group {
  id: string
  name: string
  description: string
  /** Set when an identity provider owns the group and its members (SCIM, ADR 0035). */
  idp_id?: string
  member_count?: number
  created_at: string
  updated_at: string
}

export interface GroupMember { user_id: string; username: string; display_name: string; added_at: string }

export interface TimeWindow { days: string[]; from: string; to: string; tz: string }
/** What a policy grant covers (ADR 0036); each kind serves its own protocols. */
export type TargetKind = 'host' | 'database' | 'application' | 'autoscaling'

/** One group or user a policy applies to. */
export interface PolicySubject { kind: 'group' | 'user'; id: string }

/** A named target (or autoscaling group) with the protocols granted on it. */
export interface GrantTarget { id: string; protocols: Protocol[] }

/** Every target of the grant's kind carrying every key with one of its values. */
export interface TagMatch { match: Record<string, string[]>; protocols: Protocol[] }

/** One grant of a policy: what, and the conditions it opens and runs under. */
export interface PolicyGrant {
  /** Given by the server; sent back on edit so requests keep pointing at it. */
  id?: string
  kind: TargetKind
  targets: GrantTarget[]
  tags?: TagMatch
  access: 'standing' | 'approval'
  /** target: the target's own credential setting decides; own: the person's own login. */
  sign_in: 'target' | 'own'
  require_mfa: boolean
  allow_clipboard: boolean
  allow_file_transfer: boolean
  /** Chromium's developer tools in an application's isolated browser (ADR 0037); applications only. */
  allow_devtools?: boolean
  idle_timeout_minutes: number
  max_session_minutes: number | null
  time_windows: TimeWindow[]
  retention_days: number | null
}

/** An access policy: an audience and the grants it holds (ADR 0036). */
export interface Policy {
  id: string
  name: string
  description: string
  enabled: boolean
  subjects: PolicySubject[]
  grants: PolicyGrant[]
  created_at: string
  updated_at: string
}

export interface Session {
  id: string
  user_id: string
  username?: string
  target_name?: string
  /** For a session on an autoscaling instance: the group's name and the cloud instance id. */
  asg_name?: string
  instance_id?: string
  policy_id?: string
  target_id?: string
  asg_id?: string
  asg_instance_id?: string
  protocol: Protocol
  credential_id?: string
  client_ip: string
  user_agent?: string
  started_at: string
  ended_at?: string
  end_reason?: string
  failover_from_session_id?: string
  recording_id?: string
}

export interface Recording {
  id: string
  session_id: string
  /** Set once retention deleted the blob; the row stays so audit events resolve. */
  purged_at?: string
  /** The session this recording belongs to, with user and target names resolved. */
  session?: Session
  format: 'asciicast' | 'guac'
  size_bytes: number
  sha256?: string
  started_at: string
  finished_at?: string
  retention_until?: string
  created_at: string
}

export interface AuditEvent {
  id: number
  ts: string
  actor_user_id: string
  /** Resolved at read time; absent when the actor was the gateway itself or a deleted user. */
  actor_username?: string
  /** Resolved at read time: a target or user name, or "user → target (PROTO)" for sessions. */
  object_name?: string
  /** Names for the ids inside details, keyed by the detail key ("target_id" → "web-1"). */
  details_names?: Record<string, string>
  actor_ip: string
  action: string
  object_type: string
  object_id: string
  outcome: 'success' | 'failure'
  details: Record<string, unknown>
  prev_hash: string
  hash: string
}

export interface AuditAnchor { id: number; event_id: number; hash: string; created_at: string; mac: string }

/** intact is false on a broken chain and on any problem: a log whose newest
 *  events were deleted still links, so broken can be null while intact is false. */
export interface AuditVerify {
  intact: boolean
  checked: number
  last_id: number
  last_hash: string
  broken?: { Index: number; ID: number; Reason: string } | null
  anchors_checked?: number
  last_anchor?: AuditAnchor | null
  problems?: string[]
  warnings?: string[]
}

/** Session counts shared by both overviews. Mirrors internal/session.Counts. */
export interface SessionCounts {
  open: number
  started_24h: number
}

/** The last 24 hours of the audit log, as counts. */
export interface AuditTallies {
  events: number
  failures: number
  failed_logins: number
  refused_connects: number
}

/** GET /admin/overview (ADR 0029). Counts only, never row data. */
export interface AdminOverview {
  sessions: SessionCounts
  pending_requests: number
  targets: {
    active: number
    host_key_pending: number
    host_key_changed: number
    certificate_pending: number
    /** Hosts waiting on any of the above, each once: the dashboard's number. */
    needing_attention: number
  }
  inventory: {
    hosts: number
    hosts_by_os: Record<string, number>
    databases: number
    databases_by_engine: Record<string, number>
    applications: number
  }
  autoscaling: {
    groups: number
    instances: number
    healthy_instances: number
  }
  audit_24h: AuditTallies
  /** What weakens access (2026-10-31): standing grants without MFA, accounts not yet enrolled, dormant ones, administrators. */
  posture?: {
    standing_no_mfa: { grants: number; policies: number }
    admins: number
    dormant: number
    not_enrolled: number
  }
  /** Whether the evidence is whole (2026-10-31). audit_chain is null before the gateway's first check. */
  integrity?: {
    audit_chain: { at: string; intact: boolean; checked: number; problems: number; error?: string } | null
    recordings_lost_7d: number
    directories: { listed: number; failing: number; not_run: number; held_back: number }
    export: { sinks: number; behind: number }
  }
  /** Access in flight (2026-10-31): just-in-time grants active now, those ending within the hour, the oldest pending request's wait. */
  in_flight?: { active: number; ending_soon: number; oldest_pending_seconds: number }
}

/** GET /audit/overview (ADR 0029). Counts only, never row data. */
export interface AuditOverview {
  sessions: SessionCounts
  events_24h: AuditTallies
  reviews_24h: {
    recording_views: number
    recording_downloads: number
  }
}

export interface ConnectResponse {
  ticket: string
  expires_at: string
  ws_path: string
  asg_id?: string
  asg_instance_id?: string
  /** e.g. "i-0abc · ap-south-1a" */
  instance_label?: string
}

export interface AutoscalingGroup {
  id: string
  name: string
  provider: string
  region: string
  external_name: string
  role_arn: string
  external_id: string
  os_family: OSFamily
  ports: Partial<Record<Protocol, number>>
  capabilities: Protocol[]
  address_preference: 'private' | 'public'
  poll_interval_seconds: number
  tags: Record<string, string>
  status: 'active' | 'disabled'
  last_synced_at: string | null
  last_error?: string
  credentials: Partial<Record<Protocol, string>>
  created_by?: string
  created_at: string
  updated_at: string
  /** present on the list endpoint only */
  healthy_count?: number
  instance_count?: number
}

/** GET /admin/aws/identity: the principal the gateway runs as, for autoscaling trust policies (ADR 0023). */
export interface AwsIdentity {
  principal?: string
  source: 'environment' | 'detected' | 'none'
  /** Off AWS ("none"), a missing identity is the ordinary case, not an error. */
  platform: 'aws' | 'none'
  account_id?: string
  raw_arn?: string
  checked_at: string
  error?: string
}

/** IAM documents for a group; trust policy and scripts are absent when the principal is unknown (never a placeholder). */
export interface AsgIAMDocs {
  external_id: string
  gateway_principal?: string
  principal_source: 'environment' | 'detected' | 'none'
  principal_error?: string
  role_name: string
  trust_policy?: string
  permissions_policy: string
  cli?: string
  cloudformation?: string
}

/** POST /autoscaling-groups/test and /autoscaling-groups/{id}/test. */
export interface AsgAccessTest {
  ok: boolean
  stage?: 'assume' | 'describe' | 'group'
  error?: string
  assumed_arn?: string
  group_found: boolean
  instance_count: number
}

export interface AsgInstance {
  id: string
  asg_id: string
  instance_id: string
  private_ip?: string
  public_ip?: string
  availability_zone?: string
  lifecycle_state: string
  lb_health?: string
  probe_health: 'unknown' | 'healthy' | 'unhealthy'
  host_key_fingerprint?: string
  host_key_source?: 'console' | 'tofu' | ''
  launched_at?: string
  first_seen_at: string
  last_seen_at: string
  terminated_at?: string
  healthy: boolean
}

/** Values the audit filter can offer, taken from what the log contains. */
export interface AuditFacets {
  actions: string[]
  object_types: string[]
}

/** One runtime setting resolved with its precedence (ADR 0020). Mirrors internal/settings.Value. */
export interface RuntimeSetting {
  key: string
  category: string
  title: string
  description: string
  type: 'string' | 'text' | 'bool' | 'enum' | 'hostport' | 'timezone'
  default: string
  env_var?: string
  enum?: string[]
  value: string
  source: 'default' | 'environment' | 'console'
  updated_at?: string
  updated_by?: string
  /** Changing or resetting it asks for an authenticator code proved in the last five minutes: it decides where a vaulted credential is sent. */
  step_up?: boolean
}

/** A setting fixed at install from the environment, read-only; secrets masked. */
export interface BootSetting {
  key: string
  title: string
  env_var: string
  value: string
  description: string
  /** How the console may change it through the root helper (ADR 0020, amended 2026-10-30). */
  editable?: 'value' | 'preset'
  /** An editable variable's value as the file has it. */
  raw?: string
}

/** The root helper's answer to a change of the environment file. */
export interface ConfigResult {
  id: string
  state: 'applied' | 'refused' | 'rolled_back'
  message?: string
  changed?: string[]
  at: string
}

export interface SettingsListing {
  runtime: RuntimeSetting[]
  boot: BootSetting[]
}

/** The environment file compared with what the process started with; names only, never values. */
export interface EnvFileReport {
  path?: string
  state: 'unchanged' | 'changed' | 'missing' | 'unreadable' | 'none'
  changed?: string[]
  error?: string
  mod_time?: string
  checked_at: string
}

/** One log line from the gateway's in-memory ring. Mirrors internal/logring.Record. */
export interface LogRecord {
  time: string
  level: string
  msg: string
  attrs?: Record<string, string>
}

export interface LogsPage {
  items: LogRecord[]
  capacity: number
  seen: number
}

/** A TLS certificate as the console sees it; never the key. Mirrors internal/tlscert.Info. */
export interface TLSCertInfo {
  source: 'uploaded' | 'file' | 'generated'
  subject: string
  issuer: string
  hosts: string[]
  not_before: string
  not_after: string
  fingerprint: string
  self_signed: boolean
  cert_pem?: string
  /** Why a stored certificate cannot serve now (expired, not valid yet, ...). */
  problem?: string
}

/** GET /admin/tls. */
export interface TLSStatus {
  mode: 'file' | 'managed' | 'proxy'
  active?: TLSCertInfo
  uploaded?: TLSCertInfo
  generated?: TLSCertInfo
  file_hint?: string
  /** Let's Encrypt, when the gateway serves TLS itself (ADR 0021, amended 2026-10-30). */
  acme?: { on: boolean; names: string[] | null; not_after?: string; issuer?: string; last_error?: string }
}

/** Recording storage as the console edits it; the secret is write-only. Mirrors internal/recstorage.Config. */
export interface StorageConfig {
  bucket: string
  prefix: string
  region?: string
  endpoint?: string
  kms_key_id?: string
  auth: 'role' | 'keys'
  access_key_id?: string
  secret_access_key?: string
  secret_set?: boolean
}

/** GET /admin/storage. */
export interface StorageStatus {
  source: 'console' | 'environment' | 'local'
  active?: StorageConfig
  environment?: StorageConfig
  counts: Record<string, number>
  move: { running: boolean; started_at?: string; finished_at?: string; moved: number; failed: number; total: number; last_error?: string }
}

/** GET /admin/system/host. Mirrors internal/lifecycle.HostStatus (ADR 0032). */
export interface HostStatus {
  hostname: string
  supervisor: string
  available: boolean
  reason?: string
  mfa_fresh: boolean
  step_up_minutes: number
}

/** GET /admin/system/update. Mirrors internal/update.Status (ADR 0032). */
export interface UpdateStatus {
  current: string
  latest?: string
  notes_url?: string
  published_at?: string
  newer: boolean
  checked_at?: string
  error?: string
  enabled: boolean
  /** The console may ask for the install: a systemd host with a state directory. */
  installable: boolean
  /** The installer's last report, when there is one. */
  install?: { state: 'running' | 'done' | 'failed'; version: string; message: string; at: string }
}

/** GET /admin/system/metrics. Mirrors internal/lifecycle.Metrics. */
export interface SystemMetrics {
  cpu?: { percent: number; window_seconds: number }
  load?: { one: number; five: number; fifteen: number }
  memory?: { total_bytes: number; available_bytes: number }
  disks: { what: string; path: string; system: boolean; total_bytes: number; free_bytes: number; used_bytes?: number }[]
  database_sessions: number
  guacd?: { address: string; reachable: boolean }
  cpus: number
}

/** GET /admin/system/status. Mirrors internal/lifecycle.Status. */
export interface SystemStatus {
  version: string
  started_at: string
  uptime_seconds: number
  supervisor: 'systemd' | 'kubernetes' | 'unknown'
  live_sessions: number
  env_file: EnvFileReport
  restart_required: boolean
  draining: boolean
  drain?: { requested_at: string; requested_by: string; deadline: string; wait_minutes: number }
  /** The gateway's clock when it answered. */
  now?: string
}

/** Recording retention policy (admin-editable). Mirrors internal/session. */
export interface RetentionPolicy {
  max_age_days: number
  max_total_bytes: number
  updated_at?: string
  updated_by?: string
}

/** What deleting a target or autoscaling group changes (GET …/usage; ADR 0036, amended 2026-10-30). */
export interface AssetUsage {
  policies: { policy_id: string; name: string; grants_removed: number; no_grants_left: boolean }[]
  live_sessions: number
  open_requests: number
}
