// SPDX-License-Identifier: Apache-2.0

package audit

// The actions the gateway records events under. An action is the stored
// value, the console's filter and label key, and what a SIEM rule matches on,
// so a released name never changes. Record events with these constants, not
// with literals: a test fails on a literal action anywhere else in the code,
// and on any difference between this list and the console's labels
// (web/src/pages/audit/eventText.ts).
//
// #nosec G101 -- names such as "credential.create" are actions, not secrets.
const (
	// Just-in-time access requests and the grants they become (ADR 0018).
	AccessGrantExpire    = "access.grant.expire"
	AccessRequestApprove = "access.request.approve"
	AccessRequestCreate  = "access.request.create"
	AccessRequestDeny    = "access.request.deny"
	AccessRequestRevoke  = "access.request.revoke"

	// Autoscaling groups and the instances the sync loop sees come and go.
	ASGCreate                     = "asg.create"
	ASGUpdate                     = "asg.update"
	ASGDelete                     = "asg.delete"
	ASGSync                       = "asg.sync"
	ASGTest                       = "asg.test"
	ASGCredentialSet              = "asg.credential.set"
	ASGCredentialUnset            = "asg.credential.unset"
	ASGExternalIDRotate           = "asg.external_id.rotate"
	ASGInstanceJoined             = "asg.instance.joined"
	ASGInstanceLeft               = "asg.instance.left"
	ASGInstanceUnhealthy          = "asg.instance.unhealthy"
	ASGInstanceCertificateChanged = "asg.instance.certificate.changed"
	ASGInstanceHostKeyChanged     = "asg.instance.hostkey.changed"
	ASGInstanceHostKeyMismatch    = "asg.instance.hostkey.mismatch"

	// The audit log itself.
	AuditRead   = "audit.read"
	AuditReseal = "audit.reseal"

	// The gateway's own AWS identity.
	AWSIdentityRefresh = "aws.identity.refresh"

	// Vaulted credentials, and the key rotation of an SSH certificate authority (ADR 0022).
	CredentialCreate        = "credential.create"
	CredentialUpdate        = "credential.update"
	CredentialDelete        = "credential.delete"
	CredentialRotate        = "credential.rotate"
	CredentialRotatePrepare = "credential.rotate.prepare"
	CredentialRotateCancel  = "credential.rotate.cancel"
	CredentialRotateRetire  = "credential.rotate.retire"

	// The console command line (ADR 0027).
	CLICommand = "cli.command"
	CLIUnlock  = "cli.unlock"

	// Files moved through a session.
	FileDownload = "file.download"
	FileUpload   = "file.upload"

	// Groups.
	GroupCreate        = "group.create"
	GroupUpdate        = "group.update"
	GroupDelete        = "group.delete"
	GroupMembersUpdate = "group.members.update"

	// Identity providers.
	IdPCreate = "idp.create"
	IdPUpdate = "idp.update"
	IdPDelete = "idp.delete"
	IdPTest   = "idp.test"

	// The key ring and the master key.
	KeyRotate       = "key.rotate"
	KeyRotateMaster = "key.rotate_master"

	// The gateway's log.
	LogsDownload = "logs.download"

	// Access policies.
	PolicyCreate = "policy.create"
	PolicyUpdate = "policy.update"
	PolicyDelete = "policy.delete"

	// Session recordings and where they are stored.
	RecordingDownload      = "recording.download"
	RecordingPurge         = "recording.purge"
	RecordingView          = "recording.view"
	RecordingStorageMove   = "recording.storage.move"
	RecordingStorageUpdate = "recording.storage.update"
	RecordingStorageReset  = "recording.storage.reset"

	// How long recordings are kept.
	RetentionPolicyUpdate = "retention.policy.update"

	// Sessions: the ticket, the session itself, failover and watching.
	SessionConnect     = "session.connect"
	SessionStart       = "session.start"
	SessionEnd         = "session.end"
	SessionTerminate   = "session.terminate"
	SessionFailover    = "session.failover"
	SessionShadowStart = "session.shadow.start"
	SessionShadowEnd   = "session.shadow.end"

	// Runtime settings.
	SettingsUpdate = "settings.update"
	SettingsReset  = "settings.reset"

	// The gateway process.
	SystemRestart       = "system.restart"
	SystemRestartCancel = "system.restart_cancel"

	// Targets, their host keys and their certificates.
	TargetCreate           = "target.create"
	TargetUpdate           = "target.update"
	TargetDelete           = "target.delete"
	TargetCredentialSet    = "target.credential.set"
	TargetCredentialUnset  = "target.credential.unset"
	TargetHostKeyTrust     = "target.hostkey.trust"
	TargetHostKeyChanged   = "target.hostkey.changed"
	TargetHostKeyMismatch  = "target.hostkey.mismatch"
	TargetProbe            = "target.probe"
	TargetProbeCertificate = "target.probe.certificate"
	TargetTLSMismatch      = "target.tls.mismatch"
	TargetTLSChanged       = "target.tls.changed"
	TargetTLSTrust         = "target.tls.trust"

	// The console's own TLS certificate.
	TLSCertificateUpload     = "tls.certificate.upload"
	TLSCertificateRegenerate = "tls.certificate.regenerate"
	TLSCertificateReset      = "tls.certificate.reset"

	// Accounts, sign-in and second factors.
	UserCreate         = "user.create"
	UserUpdate         = "user.update"
	UserDelete         = "user.delete"
	UserLink           = "user.link"
	UserGroupsSync     = "user.groups.sync"
	UserLogin          = "user.login"
	UserLogout         = "user.logout"
	UserMFAEnroll      = "user.mfa.enroll"
	UserMFAConfirm     = "user.mfa.confirm"
	UserMFAVerify      = "user.mfa.verify"
	UserMFAReset       = "user.mfa.reset"
	UserPasswordChange = "user.password.change"
	UserPasswordReset  = "user.password.reset"
	UserRolesUpdate    = "user.roles.update"
	UserSessionsRevoke = "user.sessions.revoke"
)
