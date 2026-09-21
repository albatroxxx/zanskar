// Types mirror docs/api/openapi.yaml and the Go JSON tags.

export type Role = 'admin' | 'auditor' | 'user'

export interface User {
  id: string
  username: string
  email?: string
  display_name: string
  status: 'active' | 'disabled' | 'locked'
  roles: Role[]
  locked_until?: string
  created_at: string
  updated_at: string
  last_login_at?: string
}

export interface Me {
  user: User
  csrf_token: string
  mfa_enrolled: boolean
  session: { id: string; created_at: string; expires_at: string }
}

export type LoginStatus = 'ok' | 'mfa_required' | 'mfa_enrollment_required'
export interface LoginResponse { status: LoginStatus; csrf_token?: string; user?: User }

export interface Page<T> { items: T[]; next_cursor?: string }

export interface ApiErrorBody { code: string; message: string; request_id?: string }

export type Protocol = 'ssh' | 'rdp' | 'vnc' | 'winrm'
export type OSFamily = 'linux' | 'windows' | 'other'
export type HostKeyStatus = 'unknown' | 'pending' | 'trusted' | 'changed'

export interface Target {
  id: string
  name: string
  address: string
  os_family: OSFamily
  ports: Partial<Record<Protocol, number>>
  capabilities: Protocol[]
  host_key_fingerprint: string | null
  host_key_status: HostKeyStatus
  tls_fingerprint: string | null
  winrm_tls_fingerprint: string | null
  tags: Record<string, string>
  status: 'active' | 'disabled'
  notes: string
  credentials: Partial<Record<Protocol, string>>
  created_at: string
  updated_at: string
  last_probed_at: string | null
}

export interface PortResult { reachable: boolean; latency_ms?: number; error?: string }

export interface ProbeResult {
  address: string
  resolved_ip: string
  ports: Partial<Record<Protocol, PortResult>>
  capabilities: Protocol[]
  ssh_host_key?: { fingerprint: string; type: string; banner: string }
  tls?: { fingerprint: string; subject: string; source?: string }
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
  host_key_ready: boolean
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
  in_use_by?: { targets?: string[]; autoscaling_groups?: string[] }
}

export interface Group {
  id: string
  name: string
  description: string
  member_count?: number
  created_at: string
  updated_at: string
}

export interface GroupMember { user_id: string; username: string; display_name: string; added_at: string }

export interface TimeWindow { days: string[]; from: string; to: string; tz: string }
export interface Selector { targets?: string[]; asgs?: string[]; tags?: Record<string, string> }

export interface Policy {
  id: string
  name: string
  description: string
  enabled: boolean
  group_id: string
  target_selector: Selector
  protocols: Protocol[]
  time_windows: TimeWindow[]
  max_session_minutes?: number | null
  idle_timeout_minutes: number
  allow_clipboard: boolean
  allow_file_transfer: boolean
  require_mfa: boolean
  created_at: string
  updated_at: string
}

export interface Session {
  id: string
  user_id: string
  username?: string
  target_name?: string
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
  actor_ip: string
  action: string
  object_type: string
  object_id: string
  outcome: 'success' | 'failure'
  details: Record<string, unknown>
  prev_hash: string
  hash: string
}

export interface AuditVerify { intact: boolean; checked: number; last_id: number; last_hash: string; broken?: { Index: number; ID: number; Reason: string } | null }

export interface ConnectResponse { ticket: string; expires_at: string; ws_path: string }
