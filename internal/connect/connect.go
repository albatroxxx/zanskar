// SPDX-License-Identifier: Apache-2.0

// Package connect is where a user's request to reach a target is decided
// and, if allowed, turned into a live bridge. POST /connect evaluates policy
// and issues a ticket; GET /ws/terminal redeems the ticket and runs the
// session. The credential never reaches the browser, and a public address or
// hostname is withheld too; only a private (RFC1918/ULA) IP is surfaced, to
// help users identify a machine (see myTargets).
package connect

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/access"
	"github.com/albatroxxx/zanskar/internal/asg"
	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/credential"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/gateway/sshgw"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/protocol"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/sshca"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/ticket"
)

// Handler wires the connect flow.
type Handler struct {
	Targets  *target.Repo
	Policies *policy.Repo
	// Access holds the just-in-time grants that gate approval-required policies
	// (ADR 0018); nil leaves every policy standing.
	Access   *access.Repo
	Vault    *credential.Vault
	Sessions *session.Repo
	Tickets  *ticket.Store
	Registry *gateway.Registry
	Storage  recording.Storage
	Audit    *audit.Log
	Log      *slog.Logger
	// MFAEnrolled reports whether the user has a second factor, for a
	// policy that requires one: an authenticator, or a provider whose sign-in
	// is the second factor (idp.SecondFactor).
	MFAEnrolled func(ctx context.Context, userID string) (bool, error)
	// Prober holds the address rules a session's target must pass when it
	// is dialled (checkAddress); nil applies them with no exception. It also
	// re-verifies a target's pinned TLS certificate just before a desktop
	// connection (ADR 0012), the gateway enforcing the RDP pin itself, which
	// a nil Prober cannot do.
	Prober      *target.Prober
	DialTimeout time.Duration
	// CloseTimeout bounds each write that closes a session once its client
	// may have gone: the row's end, the recording's size and digest. Zero
	// means closeTimeout.
	CloseTimeout time.Duration
	// Draining reports that the gateway is about to restart: no new session
	// starts, live ones run on until the drain ends them.
	Draining func() bool
	// GuacdAddr returns the guacd host:port that relays RDP and VNC; empty
	// (or nil) disables desktop sessions. A function so the runtime setting
	// applies to the next session without a restart.
	GuacdAddr func() string
	// DockerPath is the docker CLI used to spawn database session containers
	// (ADR 0017); empty means "docker" on PATH.
	DockerPath string
	// DBMaxSessions caps the database sessions running at once on this
	// gateway, each two containers and a network; 0 lifts the cap.
	DBMaxSessions int
	// DBProxyImage returns the image run as the MySQL/MariaDB relay sidecar,
	// normally the gateway's own; a function so the runtime setting applies
	// to the next session.
	DBProxyImage func() string
	// AppsMaxSessions caps the application sessions running at once
	// (ADR 0034), each a browser container; 0 lifts the cap. BrowserImage
	// returns the image the browser runs in; StateDir is where the browser's
	// seccomp profile is written for the daemon.
	AppsMaxSessions int
	BrowserImage    func() string
	StateDir        string
	// StartKeepalive is how often the socket hears a nop while an
	// application's containers start; zero means every three seconds.
	StartKeepalive time.Duration
	// ASGs and Cloud enable autoscaling-group targets and EC2 Instance Connect.
	ASGs  *asg.Repo
	Cloud asg.ProviderFactory
	// Files holds live SSH sessions that permit SFTP file transfer (ADR 0016);
	// initialised in Register.
	Files *fileRegistry
}

// Register mounts the routes. Every REST route here is for accounts that may
// connect (user or admin); an auditor-only account is review-only and gets
// 403 before any policy is consulted (ADR 0006). The WebSocket routes sit
// outside the CSRF middleware's mutating-method check because they are GETs;
// the ticket, which only POST /connect issues, is their only credential, and
// each route redeems only a ticket issued for its own protocol.
func (h *Handler) Register(mux *http.ServeMux) {
	if h.Files == nil {
		h.Files = newFileRegistry()
	}
	mux.Handle("GET /api/v1/me/targets", auth.RequireConnect(http.HandlerFunc(h.myTargets)))
	mux.Handle("POST /api/v1/connect", auth.RequireConnect(http.HandlerFunc(h.connect)))
	mux.Handle("GET /api/v1/me/autoscaling-groups/{id}/instances", auth.RequireConnect(http.HandlerFunc(h.myInstances)))
	mux.Handle("POST /api/v1/sessions/{id}/failover", auth.RequireConnect(http.HandlerFunc(h.failover)))
	// SSH file transfer over the terminal session's SFTP channel (ADR 0016).
	mux.Handle("GET /api/v1/sessions/{id}/files", auth.RequireConnect(http.HandlerFunc(h.listFiles)))
	mux.Handle("GET /api/v1/sessions/{id}/files/content", auth.RequireConnect(http.HandlerFunc(h.downloadFile)))
	mux.Handle("POST /api/v1/sessions/{id}/files/content", auth.RequireConnect(http.HandlerFunc(h.uploadFile)))
	mux.HandleFunc("GET /ws/terminal", h.terminal)
	mux.HandleFunc("GET /ws/desktop", h.desktop)
	mux.HandleFunc("GET /ws/winrm", h.winrm)
	mux.HandleFunc("GET /ws/database", h.database)
}

// reachableTarget is what a user sees in their target list.
type reachableTarget struct {
	Kind         string            `json:"kind"` // target | asg | application
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	OSFamily     target.OSFamily   `json:"os_family"`
	Tags         map[string]string `json:"tags"`
	Capabilities []target.Protocol `json:"capabilities"`
	Allowed      []string          `json:"allowed_protocols"`
	// RequiresApproval lists the allowed protocols that are approval-gated
	// (ADR 0018): the user requests access rather than connecting directly.
	RequiresApproval []string `json:"requires_approval,omitempty"`
	// OwnLogin lists the allowed protocols on which the user may sign in with
	// their own login instead of the target's (ADR 0036, sign_in own): the
	// portal offers "Use my own login" beside them.
	OwnLogin     []string `json:"own_login,omitempty"`
	HostKeyReady bool     `json:"host_key_ready"`
	// PrivateIP is shown only when the target's address is a private (RFC1918 /
	// ULA) IP, to help users tell their machines apart. A public address or a
	// hostname is never surfaced to users; empty then.
	PrivateIP    string `json:"private_ip,omitempty"`
	Engine       string `json:"engine,omitempty"` // database targets (ADR 0017)
	HealthyCount int    `json:"healthy_count,omitempty"`
	InstanceCnt  int    `json:"instance_count,omitempty"`
}

func (h *Handler) myTargets(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	pols, err := h.Policies.ForUser(r.Context(), p.User.ID)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	out := []reachableTarget{}
	if len(pols) == 0 {
		httpx.WriteJSON(w, http.StatusOK, httpx.Page[reachableTarget]{Items: out})
		return
	}
	now := time.Now()
	after := ""
	for {
		batch, next, err := h.Targets.List(r.Context(), after, 500, target.ListFilter{})
		if err != nil {
			httpx.Internal(w, r, h.Log, err)
			return
		}
		for _, t := range batch {
			if t.Status != "active" {
				continue
			}
			if t.IsApplication() {
				// An application (ADR 0034) opens in an isolated browser
				// through a ticket like a desktop; nothing of it is probed.
				allowed, needApproval, _ := reach(pols, policy.TargetRef{Kind: t.Kind(), ID: t.ID, Tags: t.Tags}, []target.Protocol{target.HTTP}, now)
				if len(allowed) == 0 {
					continue
				}
				out = append(out, reachableTarget{
					Kind: "application", ID: t.ID, Name: t.Name, OSFamily: t.OSFamily, Tags: t.Tags, Capabilities: []target.Protocol{},
					Allowed: allowed, RequiresApproval: needApproval, HostKeyReady: true,
				})
				continue
			}
			protos := target.Protocols
			// A database is reached over database alone (ADR 0017), and only
			// when the gateway can broker its engine. A tag policy that grants
			// ssh to every target tagged env=prod covers the prod database
			// too; offering ssh on it listed a button connect then refused
			// (2026-10-30, ADR 0036).
			if t.IsDatabase() {
				if !target.ServableEngine(t.Engine) {
					continue
				}
				protos = []target.Protocol{target.Database}
			}
			allowed, needApproval, ownLogin := reach(pols, policy.TargetRef{Kind: t.Kind(), ID: t.ID, Tags: t.Tags}, protos, now)
			if len(allowed) == 0 {
				continue
			}
			// A private IP is safe to show (not routable from where users sit, so
			// it cannot be used to bypass the gateway) and helps users identify a
			// machine; a public address or hostname is withheld.
			privateIP := ""
			if a, err := netip.ParseAddr(t.Address); err == nil && a.IsPrivate() {
				privateIP = t.Address
			}
			out = append(out, reachableTarget{
				Kind: "target", ID: t.ID, Name: t.Name, OSFamily: t.OSFamily, Tags: t.Tags, Capabilities: t.Capabilities,
				Allowed: allowed, RequiresApproval: needApproval, OwnLogin: ownLogin, HostKeyReady: t.HostKeyStatus == target.HostKeyTrusted, PrivateIP: privateIP, Engine: t.Engine,
			})
		}
		if next == "" {
			break
		}
		after = next
	}
	if h.ASGs != nil {
		groups, err := h.ASGs.List(r.Context(), true)
		if err != nil {
			httpx.Internal(w, r, h.Log, err)
			return
		}
		for _, g := range groups {
			allowed, needApproval, ownLogin := reach(pols, policy.TargetRef{Kind: protocol.KindAutoscaling, ASGID: g.ID, Tags: g.Tags}, g.Capabilities, now)
			if len(allowed) == 0 {
				continue
			}
			all, _ := h.ASGs.Instances(r.Context(), g.ID, false)
			healthy := 0
			live := 0
			for _, in := range all {
				if in.TerminatedAt != nil {
					continue
				}
				live++
				if in.Healthy {
					healthy++
				}
			}
			out = append(out, reachableTarget{
				Kind: "asg", ID: g.ID, Name: g.Name, OSFamily: g.OSFamily, Tags: g.Tags, Capabilities: g.Capabilities,
				Allowed: allowed, RequiresApproval: needApproval, OwnLogin: ownLogin, HostKeyReady: true, HealthyCount: healthy, InstanceCnt: live,
			})
		}
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.Page[reachableTarget]{Items: out})
}

// reach returns the protocols of protos the policies allow on ref, the ones
// of those that need an approved request first (ADR 0018), and the ones on
// which the user may sign in with their own login (ADR 0036).
func reach(pols []*policy.Policy, ref policy.TargetRef, protos []target.Protocol, now time.Time) (allowed, needApproval, ownLogin []string) {
	for _, proto := range protos {
		d := policy.Evaluate(pols, ref, string(proto), now)
		if !d.Allowed {
			continue
		}
		allowed = append(allowed, string(proto))
		if d.RequireApproval {
			needApproval = append(needApproval, string(proto))
		}
		if d.SignInOwn {
			ownLogin = append(ownLogin, string(proto))
		}
	}
	return allowed, needApproval, ownLogin
}

type connectRequest struct {
	TargetID      string          `json:"target_id"`
	ASGID         string          `json:"asg_id"`
	ASGInstanceID string          `json:"asg_instance_id"`
	Protocol      string          `json:"protocol"`
	Credential    *userCredential `json:"credential,omitempty"`
}

type connectResponse struct {
	Ticket        string    `json:"ticket"`
	ExpiresAt     time.Time `json:"expires_at"`
	Path          string    `json:"ws_path"`
	ASGID         string    `json:"asg_id,omitempty"`
	ASGInstanceID string    `json:"asg_instance_id,omitempty"`
	InstanceLabel string    `json:"instance_label,omitempty"`
}

// userCredential is what a user_supplied credential mode asks for: a
// username with a password, or, over SSH, with the user's own private key
// and its passphrase when it has one.
type userCredential struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key,omitempty"`
	Passphrase string `json:"private_key_passphrase,omitempty"`
}

// Bounds on a key a user brings: an RSA 16384-bit key in PEM is under 13 KiB.
const (
	maxUserKey        = 16 << 10
	maxUserPassphrase = 1 << 10
)

func (h *Handler) connect(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	actor := audit.Actor{UserID: p.User.ID, IP: auth.ClientIP(r)}
	var req connectRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.BadRequest(w, r, err.Error())
		return
	}
	deny := func(status int, code, msg string) {
		h.record(r, actor.Event(audit.SessionConnect, "target", req.TargetID, audit.Failure, map[string]string{"protocol": req.Protocol, "reason": code}))
		httpx.WriteError(w, r, status, code, msg)
	}
	if h.draining() {
		deny(http.StatusServiceUnavailable, "restarting", restartingMsg)
		return
	}
	proto := target.Protocol(req.Protocol)
	if !target.ValidProtocol(proto) {
		httpx.BadRequest(w, r, "unknown protocol")
		return
	}
	switch proto {
	case target.SSH, target.WinRM, target.Database:
		// database sessions are brokered through an ephemeral container (ADR 0017);
		// like SSH, reachability is resolved when the ticket is redeemed.
	case target.RDP, target.VNC, target.HTTP:
		// An application (ADR 0034) is a desktop session too: its browser
		// runs in a container beside the gateway and is streamed by guacd.
		if h.guacd() == "" {
			deny(http.StatusNotImplemented, "protocol_unavailable", "desktop sessions are not configured on this gateway")
			return
		}
	default:
		deny(http.StatusNotImplemented, "protocol_unavailable", "protocol not available")
		return
	}
	var (
		ep  *endpoint
		err error
	)
	switch {
	case req.ASGInstanceID != "":
		ep, err = h.resolveInstance(r.Context(), req.ASGInstanceID)
	case req.ASGID != "":
		ep, err = h.pickInstance(r.Context(), req.ASGID)
	default:
		ep, err = h.resolveTarget(r.Context(), req.TargetID)
	}
	if err != nil {
		switch {
		case errors.Is(err, target.ErrNotFound), errors.Is(err, asg.ErrNotFound):
			deny(http.StatusNotFound, "not_found", "target not found")
		case errors.Is(err, errNoHealthyInstances):
			deny(http.StatusConflict, "no_healthy_instances", "the autoscaling group has no healthy instances right now")
		default:
			httpx.Internal(w, r, h.Log, err)
		}
		return
	}
	res, code, msg, err := h.issueTicket(r.Context(), p, auth.ClientIP(r), ep, proto, req.Credential, "")
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	if code != "" {
		deny(codeStatus(code), code, msg)
		return
	}
	h.record(r, actor.Event(audit.SessionConnect, "target", ep.LiveKey, audit.Success, map[string]any{"protocol": req.Protocol, "asg_id": ep.ASGID, "instance": ep.CloudInstanceID}))
	httpx.WriteJSON(w, http.StatusOK, res)
}

// admits applies the access policies to userID reaching ep over proto: when
// a ticket is issued, and again when it is redeemed, so a policy, a group
// membership or an approval revoked in between is not outrun. It returns
// the allowing decision, or the code and message of a refusal. The gate is
// the one the applications proxy passes too (access.Gate).
func (h *Handler) admits(ctx context.Context, userID string, ep *endpoint, proto target.Protocol) (policy.Decision, string, string, error) {
	return h.gate().Admit(ctx, userID, ep.policyRef(), string(proto), time.Now())
}

// issueTicket runs policy, pinning and credential checks for an endpoint and
// issues a connect ticket. A non-empty code is a user-facing refusal.

func (h *Handler) issueTicket(ctx context.Context, p *auth.Principal, ip string, ep *endpoint, proto target.Protocol, uc *userCredential, failoverFrom string) (*connectResponse, string, string, error) {
	if h.draining() {
		return nil, "restarting", restartingMsg, nil
	}
	if !ep.Active {
		if ep.ASGInstanceID != "" {
			return nil, "instance_unhealthy", "the instance is no longer healthy", nil
		}
		return nil, "target_disabled", "target is disabled", nil
	}
	if ep.ASGID != "" && proto == target.Database {
		return nil, "protocol_unavailable", "database access is configured per endpoint, not per autoscaling group", nil
	}
	d, code, msg, err := h.admits(ctx, p.User.ID, ep, proto)
	if err != nil || code != "" {
		return nil, code, msg, err
	}
	switch proto {
	case target.SSH:
		if !ep.HostKeyTrusted || ep.HostKeyFingerprint == "" {
			if ep.ASGID != "" {
				return nil, "host_key_unverified", "the instance's host key has not been verified yet; try again after the next sync", nil
			}
			return nil, "host_key_untrusted", "the target's host key has not been trusted by an admin", nil
		}
	case target.RDP:
		if ep.TLSFingerprint == "" {
			return nil, "certificate_unpinned", "the target's RDP certificate has not been captured; probe it first", nil
		}
	case target.WinRM:
		if ep.port(target.WinRM) == 5985 {
			return nil, "tls_required", "winrm over plain HTTP is not allowed; use the HTTPS listener (5986)", nil
		}
		if ep.WinRMTLSFingerprint == "" {
			return nil, "certificate_unpinned", "the target's WinRM certificate has not been captured; probe it first", nil
		}
	case target.Database:
		if ep.Engine == "" {
			return nil, "not_a_database", "target is not a database", nil
		}
		if !target.ServableEngine(ep.Engine) {
			return nil, "engine_unavailable", ep.Engine + " database access ships in a later release", nil
		}
	case target.HTTP:
		// An application (ADR 0034) opens in a browser of its own; the
		// application's sign-in, if any, is the user's, so no credential is
		// attached and none is required.
		if ep.AppUpstream == "" {
			return nil, "not_an_application", "target is not an application", nil
		}
		return h.issueCredentialless(p, ep, proto, d, ip, failoverFrom)
	}
	// How the person signs in (ADR 0036): the target's slot decides when a
	// deciding grant lets it; the person's own login is asked for when every
	// deciding grant says so, and used when they bring it where a grant
	// allows it. Their own login needs nothing bound to the slot.
	own := !d.SignInTarget || (uc != nil && d.SignInOwn)
	credID := ep.Credentials[proto]
	var cred *credential.Credential
	if own {
		cred, credID = &credential.Credential{Mode: credential.ModeUserSupplied}, ""
	} else {
		if credID == "" {
			return nil, "no_credential", "no credential is configured for " + string(proto) + " on this target", nil
		}
		var err error
		if cred, err = h.Vault.Get(ctx, credID); err != nil {
			return nil, "", "", err
		}
	}
	grant := ticket.Grant{
		UserID: p.User.ID, Username: p.User.Username, SessionID: p.Session.ID,
		TargetID: ep.TargetID, ASGID: ep.ASGID, ASGInstanceID: ep.ASGInstanceID,
		Protocol: string(proto), CredentialID: credID, PolicyID: d.Policy.ID,
		IdleTimeout: d.IdleTimeout, MaxSession: d.MaxSession, RetentionDays: retentionDays(ep, d),
		AllowClipboard: d.AllowClipboard, AllowFileTransfer: d.AllowFileTransfer, AllowDevTools: d.AllowDevTools,
		ClientIP: ip, FailoverFrom: failoverFrom,
	}
	switch cred.Mode {
	case credential.ModeVaulted:
		if cred.Type == credential.TypeEC2InstanceConnect && (ep.ASGID == "" || h.Cloud == nil) {
			return nil, "credential_mode_unavailable", "ec2 instance connect only applies to autoscaling instances", nil
		}
		if cred.Type == credential.TypeSSHCA {
			// A certificate authority may be limited to named login users
			// (ADR 0022). Decide here, before a ticket exists, so the user
			// gets a plain answer rather than a broken socket.
			// The caller audits the refusal as session.connect with this
			// reason, like every other code.
			loginUser := caLoginUser(cred, p.User.Username)
			if !cred.PermitsPrincipal(loginUser) {
				return nil, "login_user_not_permitted", "this certificate authority does not issue certificates for login user " + loginUser, nil
			}
		}
	case credential.ModeUserSupplied:
		if uc == nil || uc.Username == "" || (uc.Password == "" && uc.PrivateKey == "") {
			return nil, "credential_required", "this target needs your username and password", nil
		}
		grant.Username = uc.Username
		if uc.PrivateKey == "" {
			grant.UserSecret = []byte(uc.Password)
			break
		}
		// The user's own key (2026-10-30). It signs in over SSH alone; RDP,
		// VNC, WinRM and databases take a password. It is unlocked here, so
		// a wrong passphrase is a plain answer rather than a broken socket,
		// and the ticket carries it for its thirty seconds, never stored.
		if proto != target.SSH {
			return nil, "credential_required", "a private key signs in over SSH only; give your password", nil
		}
		if len(uc.PrivateKey) > maxUserKey || len(uc.Passphrase) > maxUserPassphrase {
			return nil, "credential_invalid", "the private key is too large", nil
		}
		key, err := credential.UnlockPrivateKey(uc.PrivateKey, uc.Passphrase)
		switch {
		case errors.Is(err, credential.ErrPassphrase):
			return nil, "credential_invalid", "the key is encrypted, and its passphrase is missing or wrong", nil
		case err != nil:
			return nil, "credential_invalid", "that is not a private key this gateway can read (OpenSSH, PKCS#8 or PKCS#1)", nil
		}
		grant.UserKey = key
	default:
		return nil, "credential_mode_unavailable", "credential mode not supported yet", nil
	}
	tok, err := h.Tickets.Issue(grant)
	if err != nil {
		return nil, "", "", err
	}
	return &connectResponse{Ticket: tok, ExpiresAt: time.Now().Add(ticket.TTL), Path: ticketPathFor(proto),
		ASGID: ep.ASGID, ASGInstanceID: ep.ASGInstanceID, InstanceLabel: ep.Label}, "", "", nil
}

// issueCredentialless issues a ticket for a protocol that carries no
// credential: an application session, whose browser has nothing to sign in
// with on the user's behalf.
func (h *Handler) issueCredentialless(p *auth.Principal, ep *endpoint, proto target.Protocol, d policy.Decision, ip, failoverFrom string) (*connectResponse, string, string, error) {
	grant := ticket.Grant{
		UserID: p.User.ID, Username: p.User.Username, SessionID: p.Session.ID,
		TargetID: ep.TargetID, ASGID: ep.ASGID, ASGInstanceID: ep.ASGInstanceID,
		Protocol: string(proto), PolicyID: d.Policy.ID,
		IdleTimeout: d.IdleTimeout, MaxSession: d.MaxSession, RetentionDays: retentionDays(ep, d),
		AllowClipboard: d.AllowClipboard, AllowFileTransfer: d.AllowFileTransfer, AllowDevTools: d.AllowDevTools,
		ClientIP: ip, FailoverFrom: failoverFrom,
	}
	tok, err := h.Tickets.Issue(grant)
	if err != nil {
		return nil, "", "", err
	}
	return &connectResponse{Ticket: tok, ExpiresAt: time.Now().Add(ticket.TTL), Path: ticketPathFor(proto)}, "", "", nil
}

func codeStatus(code string) int {
	switch code {
	case "policy_denied", "mfa_required_by_policy", "approval_required", "login_user_not_permitted":
		return http.StatusForbidden
	case "credential_required", "credential_invalid":
		return http.StatusUnprocessableEntity
	case "protocol_unavailable", "credential_mode_unavailable", "engine_unavailable":
		return http.StatusNotImplemented
	case "not_found":
		return http.StatusNotFound
	default:
		return http.StatusConflict
	}
}

// terminal redeems a ticket and runs the SSH bridge for its lifetime.
func (h *Handler) terminal(w http.ResponseWriter, r *http.Request) {
	ip := auth.ClientIP(r)
	g, ok := h.redeem(w, r)
	if !ok {
		return
	}
	defer g.Wipe()
	// The policy allowed the ticket's protocol, not this one: a ticket for
	// RDP must not open an SSH shell with the RDP credential.
	if target.Protocol(g.Protocol) != target.SSH {
		httpx.WriteError(w, r, http.StatusBadRequest, "bad_request", "ticket is not for ssh")
		return
	}
	cols, rows := termSize(r)

	ep, err := h.resolveGrant(r.Context(), g)
	if err != nil || !ep.Active || !ep.HostKeyTrusted || ep.HostKeyFingerprint == "" {
		httpx.WriteError(w, r, http.StatusConflict, "target_unavailable", "target is no longer available")
		return
	}

	// Resolve credential material before upgrading, so a vault failure is a
	// plain HTTP error rather than a broken socket.
	a := sshgw.Auth{Username: g.Username}
	switch {
	case len(g.UserKey) > 0:
		a.PrivateKey = g.UserKey
	case len(g.UserSecret) > 0:
		a.Password = string(g.UserSecret)
	default:
		// Decide on the credential's type before touching the vault: EC2
		// Instance Connect stores no secret, so Vault.Open would fail with
		// ErrNoSecret and the key-push flow below would never run.
		cred, err := h.Vault.Get(r.Context(), g.CredentialID)
		if err != nil {
			h.Log.Error("open credential", "id", g.CredentialID, "err", err)
			httpx.WriteError(w, r, http.StatusConflict, "credential_unavailable", "credential could not be opened")
			return
		}
		if cred.Type == credential.TypeEC2InstanceConnect {
			// Push a one-minute public key through the cloud API; nothing is
			// stored anywhere. Requires the ec2-instance-connect package on
			// the instance, which stock Amazon Linux and Ubuntu AMIs ship.
			if ep.Group == nil || h.Cloud == nil {
				httpx.WriteError(w, r, http.StatusConflict, "credential_unavailable", "instance connect needs an autoscaling instance")
				return
			}
			provider, err := h.Cloud(r.Context(), ep.Group)
			if err != nil {
				h.Log.Error("cloud provider", "asg", ep.Group.Name, "err", err)
				httpx.WriteError(w, r, http.StatusConflict, "credential_unavailable", "cloud access failed")
				return
			}
			pubLine, privPEM, err := ephemeralSSHKey()
			if err != nil {
				httpx.Internal(w, r, h.Log, err)
				return
			}
			osUser := cred.Username
			if osUser == "" {
				osUser = "ec2-user"
			}
			if err := provider.SendSSHPublicKey(r.Context(), ep.CloudInstanceID, ep.AvailabilityZone, osUser, []byte(pubLine)); err != nil {
				h.Log.Warn("instance connect push failed", "instance", ep.CloudInstanceID, "err", err)
				httpx.WriteError(w, r, http.StatusConflict, "credential_unavailable", "instance connect refused the key; check the role's permissions")
				return
			}
			a.Username, a.PrivateKey = osUser, privPEM
			break
		}
		opened, err := h.Vault.Open(r.Context(), g.CredentialID)
		if err != nil {
			h.Log.Error("open credential", "id", g.CredentialID, "err", err)
			httpx.WriteError(w, r, http.StatusConflict, "credential_unavailable", "credential could not be opened")
			return
		}
		defer opened.Close()
		switch opened.Type {
		case credential.TypeSSHCA:
			// Certificate authority mode: mint a fresh, minutes-long user
			// certificate for this session. The gateway stores no user key.
			// The allowlist was checked when the ticket was issued; the
			// certificate carries that one principal and a key id naming
			// the Zanskar user, which sshd logs on the target (ADR 0022).
			loginUser := caLoginUser(&opened.Credential, g.Username)
			if !opened.PermitsPrincipal(loginUser) {
				httpx.WriteError(w, r, http.StatusForbidden, "login_user_not_permitted", "this certificate authority does not issue certificates for login user "+loginUser)
				return
			}
			certLine, keyPEM, err := sshca.IssueForSession(opened.PrivateKey, sshca.CertParams{
				Principals: []string{loginUser}, Validity: opened.CertificateTTL(), KeyID: sshca.SessionKeyID(g.Username, loginUser)})
			if err != nil {
				h.Log.Error("mint ssh certificate", "id", g.CredentialID, "err", err)
				httpx.WriteError(w, r, http.StatusConflict, "credential_unavailable", "could not issue a session certificate")
				return
			}
			a.Username = loginUser
			a.PrivateKey = []byte(keyPEM)
			a.Certificate = []byte(certLine)
		default:
			a.Username, a.Password, a.PrivateKey = opened.Username, opened.Password, opened.PrivateKey
		}
	}

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return // Accept already wrote the error
	}
	defer ws.CloseNow()
	ws.SetReadLimit(1 << 20)

	run, ok := h.startRun(r, ws, g, ep, ip)
	if !ok {
		return
	}

	timeout := h.DialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	fp := ep.HostKeyFingerprint
	// Checked here, after the upgrade, so the user is told why. The bridge
	// then dials the checked address, not the name: a second lookup could
	// answer with somewhere else. The host key pin does not depend on the
	// name.
	dialIP, err := h.checkAddress(r, g, ep)
	if err != nil {
		msg := "could not connect to the target"
		if errors.Is(err, target.ErrAddressForbidden) {
			msg = addressRefusedMsg
		}
		run.end(session.EndError, msg)
		return
	}
	client, err := sshgw.Dial(r.Context(), sshgw.Endpoint{Address: dialIP.String(), Port: ep.port(target.SSH), HostKeyFingerprint: fp, HostKeyTrusted: true}, a, timeout)
	if err != nil {
		reason, msg := session.EndError, "could not connect to the target"
		switch {
		case errors.Is(err, sshgw.ErrHostKeyMismatch):
			msg = "host key mismatch; connection refused"
			h.record(r, run.actor.Event(audit.TargetHostKeyMismatch, "target", ep.LiveKey, audit.Failure, map[string]string{"expected": fp}))
		case errors.Is(err, sshgw.ErrAuthFailed):
			msg = "authentication to the target failed"
		}
		h.Log.Warn("ssh dial failed", "target", ep.LiveKey, "err", err)
		run.end(reason, msg)
		return
	}
	defer func() { _ = client.Close() }()

	// Expose this session's SSH connection for SFTP file transfer while it is
	// open, when the policy allows it (ADR 0016).
	if g.AllowFileTransfer {
		h.Files.add(run.s.ID, &fileSession{client: client, userID: g.UserID, targetKey: ep.LiveKey})
		defer h.Files.remove(run.s.ID)
	}

	rec, recRow, ok := run.asciicast(sessionLabel(ep), cols, rows)
	if !ok {
		return
	}
	ctx, done := run.live()
	defer done()

	lim := sshgw.Limits{Idle: g.IdleTimeout, Max: g.MaxSession, SessionID: run.s.ID, AllowFiles: g.AllowFileTransfer}
	// The registry made the tap that shadowing watchers subscribe to (ADR
	// 0006); the bridge has to write to it or they see nothing. Assigned only
	// when present: a nil *Tap in the interface would be dereferenced.
	if tap := h.Registry.Tap(run.s.ID); tap != nil {
		lim.Tap = tap
	}
	reason, berr := sshgw.Bridge(ctx, h.Log, client, ws, rec, cols, rows, lim)
	run.finish(rec, recRow, reason, berr)
}

const restartingMsg = "the gateway is restarting to apply a configuration change; try again in a minute"

// draining reports whether a restart is in progress.
func (h *Handler) draining() bool { return h.Draining != nil && h.Draining() }

// redeem turns a ticket into its grant for a bridge, refusing while the
// gateway drains: a ticket issued just before the drain began must not start
// a session the drain would miss.
func (h *Handler) redeem(w http.ResponseWriter, r *http.Request) (*ticket.Grant, bool) {
	if h.draining() {
		httpx.WriteError(w, r, http.StatusServiceUnavailable, "restarting", restartingMsg)
		return nil, false
	}
	// The browser sends the cookie of its sign-in with the upgrade; the
	// ticket is redeemed only by the sign-in that asked for it (L9).
	sessionID := ""
	p, signedIn := auth.FromContext(r.Context())
	if signedIn {
		sessionID = p.Session.ID
	}
	g, err := h.Tickets.Redeem(r.URL.Query().Get("ticket"), auth.ClientIP(r), sessionID)
	if err != nil {
		httpx.WriteError(w, r, http.StatusUnauthorized, "invalid_ticket", "invalid or expired ticket")
		return nil, false
	}
	// The role gate RequireConnect applied when the ticket was issued is
	// applied again here, with the roles the account holds now: a role
	// change inside the ticket's thirty seconds ends nothing (there is no
	// session yet) and must not let a review-only account start one.
	if !signedIn || !p.User.CanConnect() {
		g.Wipe()
		httpx.WriteError(w, r, http.StatusForbidden, "review_only", "this account is review-only; the user role is required to reach targets")
		return nil, false
	}
	// Up to 30 seconds have passed since the policies allowed this: ask
	// them again. Where the target itself is gone, the handler says so.
	if ep, err := h.resolveGrant(r.Context(), g); err == nil {
		_, code, msg, err := h.admits(r.Context(), g.UserID, ep, target.Protocol(g.Protocol))
		if err != nil {
			g.Wipe()
			httpx.Internal(w, r, h.Log, err)
			return nil, false
		}
		if code != "" {
			g.Wipe()
			httpx.WriteError(w, r, codeStatus(code), code, msg)
			return nil, false
		}
	}
	return g, true
}

// retentionDays resolves the recording retention for a session: the
// target's override, else the allowing policy's, else 0 for the global
// retention policy (QA finding R12).
func retentionDays(ep *endpoint, d policy.Decision) int {
	if ep.RetentionDays > 0 {
		return ep.RetentionDays
	}
	return d.RetentionDays
}

// retentionUntil fixes a new recording's retention from its grant.
func retentionUntil(g *ticket.Grant) *time.Time {
	if g.RetentionDays <= 0 {
		return nil
	}
	t := time.Now().UTC().AddDate(0, 0, g.RetentionDays)
	return &t
}

// guacd is the effective guacd address, empty when desktops are off.
func (h *Handler) guacd() string {
	if h.GuacdAddr == nil {
		return ""
	}
	return h.GuacdAddr()
}

func (h *Handler) record(r *http.Request, e audit.Event) {
	auth.Recorder{Audit: h.Audit, Log: h.Log}.Record(r, e)
}

// caLoginUser is the login user a certificate authority signs for: the
// credential's username when it names one, otherwise the Zanskar username,
// so each person reaches the target as themselves.
func caLoginUser(c *credential.Credential, zanskarUser string) string {
	if c.Username != "" {
		return c.Username
	}
	return zanskarUser
}
