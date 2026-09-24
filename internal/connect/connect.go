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
	"strconv"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/asg"
	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/credential"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/gateway/sshgw"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/recording"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/sshca"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/ticket"
)

// Handler wires the connect flow.
type Handler struct {
	Targets     *target.Repo
	Policies    *policy.Repo
	Vault       *credential.Vault
	Sessions    *session.Repo
	Tickets     *ticket.Store
	Registry    *gateway.Registry
	Storage     recording.Storage
	Audit       *audit.Log
	Log         *slog.Logger
	MFAEnrolled func(ctx context.Context, userID string) (bool, error)
	// Prober re-verifies a target's pinned TLS certificate just before a
	// desktop connection (ADR 0012); the gateway enforces the RDP pin itself.
	Prober      *target.Prober
	DialTimeout time.Duration
	// GuacdAddr enables RDP and VNC; empty disables desktop sessions.
	GuacdAddr string
	// DockerPath is the docker CLI used to spawn database session containers
	// (ADR 0017); empty means "docker" on PATH.
	DockerPath string
	// ASGs and Cloud enable autoscaling-group targets and EC2 Instance Connect.
	ASGs  *asg.Repo
	Cloud asg.ProviderFactory
	// Files holds live SSH sessions that permit SFTP file transfer (ADR 0016);
	// initialised in Register.
	Files *fileRegistry
}

// Register mounts the routes. The WebSocket route sits outside the CSRF
// middleware's mutating-method check because it is a GET; the ticket is its
// only credential.
func (h *Handler) Register(mux *http.ServeMux) {
	if h.Files == nil {
		h.Files = newFileRegistry()
	}
	mux.Handle("GET /api/v1/me/targets", auth.RequireAuth(http.HandlerFunc(h.myTargets)))
	mux.Handle("POST /api/v1/connect", auth.RequireAuth(http.HandlerFunc(h.connect)))
	mux.Handle("GET /api/v1/me/autoscaling-groups/{id}/instances", auth.RequireAuth(http.HandlerFunc(h.myInstances)))
	mux.Handle("POST /api/v1/sessions/{id}/failover", auth.RequireAuth(http.HandlerFunc(h.failover)))
	// SSH file transfer over the terminal session's SFTP channel (ADR 0016).
	mux.Handle("GET /api/v1/sessions/{id}/files", auth.RequireAuth(http.HandlerFunc(h.listFiles)))
	mux.Handle("GET /api/v1/sessions/{id}/files/content", auth.RequireAuth(http.HandlerFunc(h.downloadFile)))
	mux.Handle("POST /api/v1/sessions/{id}/files/content", auth.RequireAuth(http.HandlerFunc(h.uploadFile)))
	mux.HandleFunc("GET /ws/terminal", h.terminal)
	mux.HandleFunc("GET /ws/desktop", h.desktop)
	mux.HandleFunc("GET /ws/winrm", h.winrm)
	mux.HandleFunc("GET /ws/database", h.database)
}

// reachableTarget is what a user sees in their target list.
type reachableTarget struct {
	Kind         string            `json:"kind"` // target | asg
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	OSFamily     target.OSFamily   `json:"os_family"`
	Tags         map[string]string `json:"tags"`
	Capabilities []target.Protocol `json:"capabilities"`
	Allowed      []string          `json:"allowed_protocols"`
	HostKeyReady bool              `json:"host_key_ready"`
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
		h.fail(w, r, err)
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
		batch, next, err := h.Targets.List(r.Context(), after, 500, nil)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		for _, t := range batch {
			if t.Status != "active" {
				continue
			}
			ref := policy.TargetRef{ID: t.ID, Tags: t.Tags}
			var allowed []string
			for _, proto := range target.Protocols {
				if policy.Evaluate(pols, ref, string(proto), now).Allowed {
					allowed = append(allowed, string(proto))
				}
			}
			// database is not in target.Protocols (it is not probed); offer it
			// for database targets the policy permits (ADR 0017).
			if t.IsDatabase() && policy.Evaluate(pols, ref, string(target.Database), now).Allowed {
				allowed = append(allowed, string(target.Database))
			}
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
				Allowed: allowed, HostKeyReady: t.HostKeyStatus == target.HostKeyTrusted, PrivateIP: privateIP, Engine: t.Engine,
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
			h.fail(w, r, err)
			return
		}
		for _, g := range groups {
			ref := policy.TargetRef{ASGID: g.ID, Tags: g.Tags}
			var allowed []string
			for _, proto := range g.Capabilities {
				if policy.Evaluate(pols, ref, string(proto), now).Allowed {
					allowed = append(allowed, string(proto))
				}
			}
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
				Allowed: allowed, HostKeyReady: true, HealthyCount: healthy, InstanceCnt: live,
			})
		}
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.Page[reachableTarget]{Items: out})
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

// userCredential is what a user_supplied credential mode asks for.
type userCredential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *Handler) connect(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	actor := audit.Actor{UserID: p.User.ID, IP: auth.ClientIP(r)}
	var req connectRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	deny := func(status int, code, msg string) {
		h.record(r, actor.Event("session.connect", "target", req.TargetID, audit.Failure, map[string]string{"protocol": req.Protocol, "reason": code}))
		httpx.WriteError(w, status, code, msg)
	}
	proto := target.Protocol(req.Protocol)
	if !target.ValidProtocol(proto) {
		httpx.BadRequest(w, "unknown protocol")
		return
	}
	switch proto {
	case target.SSH, target.WinRM, target.Database:
		// database sessions are brokered through an ephemeral container (ADR 0017);
		// like SSH, reachability is resolved when the ticket is redeemed.
	case target.RDP, target.VNC:
		if h.GuacdAddr == "" {
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
			h.fail(w, r, err)
		}
		return
	}
	res, code, msg, err := h.issueTicket(r.Context(), p, auth.ClientIP(r), ep, proto, req.Credential, "")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if code != "" {
		deny(codeStatus(code), code, msg)
		return
	}
	h.record(r, actor.Event("session.connect", "target", ep.LiveKey, audit.Success, map[string]any{"protocol": req.Protocol, "asg_id": ep.ASGID, "instance": ep.CloudInstanceID}))
	httpx.WriteJSON(w, http.StatusOK, res)
}

// issueTicket runs policy, pinning and credential checks for an endpoint and
// issues a connect ticket. A non-empty code is a user-facing refusal.
func (h *Handler) issueTicket(ctx context.Context, p *auth.Principal, ip string, ep *endpoint, proto target.Protocol, uc *userCredential, failoverFrom string) (*connectResponse, string, string, error) {
	if !ep.Active {
		if ep.ASGInstanceID != "" {
			return nil, "instance_unhealthy", "the instance is no longer healthy", nil
		}
		return nil, "target_disabled", "target is disabled", nil
	}
	if ep.ASGID != "" && proto != target.SSH {
		return nil, "protocol_unavailable", "autoscaling groups support ssh in this release", nil
	}
	pols, err := h.Policies.ForUser(ctx, p.User.ID)
	if err != nil {
		return nil, "", "", err
	}
	id, asgID, tags := ep.policyRef()
	d := policy.Evaluate(pols, policy.TargetRef{ID: id, ASGID: asgID, Tags: tags}, string(proto), time.Now())
	if !d.Allowed {
		return nil, "policy_denied", d.Reason, nil
	}
	if d.RequireMFA && h.MFAEnrolled != nil {
		enrolled, err := h.MFAEnrolled(ctx, p.User.ID)
		if err != nil {
			return nil, "", "", err
		}
		if !enrolled {
			return nil, "mfa_required_by_policy", "this policy requires an enrolled authenticator", nil
		}
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
	}
	credID := ep.Credentials[proto]
	if credID == "" {
		return nil, "no_credential", "no credential is configured for " + string(proto) + " on this target", nil
	}
	cred, err := h.Vault.Get(ctx, credID)
	if err != nil {
		return nil, "", "", err
	}
	grant := ticket.Grant{
		UserID: p.User.ID, Username: p.User.Username, SessionID: p.Session.ID,
		TargetID: ep.TargetID, ASGID: ep.ASGID, ASGInstanceID: ep.ASGInstanceID,
		Protocol: string(proto), CredentialID: credID, PolicyID: d.Policy.ID,
		IdleTimeout: d.IdleTimeout, MaxSession: d.MaxSession,
		AllowClipboard: d.AllowClipboard, AllowFileTransfer: d.AllowFileTransfer,
		ClientIP: ip, FailoverFrom: failoverFrom,
	}
	switch cred.Mode {
	case credential.ModeVaulted:
		if cred.Type == credential.TypeEC2InstanceConnect && (ep.ASGID == "" || h.Cloud == nil) {
			return nil, "credential_mode_unavailable", "ec2 instance connect only applies to autoscaling instances", nil
		}
	case credential.ModeUserSupplied:
		if uc == nil || uc.Username == "" || uc.Password == "" {
			return nil, "credential_required", "this target needs your username and password", nil
		}
		grant.Username = uc.Username
		grant.UserSecret = []byte(uc.Password)
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

func codeStatus(code string) int {
	switch code {
	case "policy_denied", "mfa_required_by_policy":
		return http.StatusForbidden
	case "credential_required":
		return http.StatusUnprocessableEntity
	case "protocol_unavailable", "credential_mode_unavailable":
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
	g, err := h.Tickets.Redeem(r.URL.Query().Get("ticket"), ip)
	if err != nil {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_ticket", "invalid or expired ticket")
		return
	}
	defer zero(g.UserSecret)
	cols, _ := strconv.Atoi(r.URL.Query().Get("cols"))
	rows, _ := strconv.Atoi(r.URL.Query().Get("rows"))

	ep, err := h.resolveGrant(r.Context(), g)
	if err != nil || !ep.Active || !ep.HostKeyTrusted || ep.HostKeyFingerprint == "" {
		httpx.WriteError(w, http.StatusConflict, "target_unavailable", "target is no longer available")
		return
	}

	// Resolve credential material before upgrading, so a vault failure is a
	// plain HTTP error rather than a broken socket.
	a := sshgw.Auth{Username: g.Username}
	switch {
	case len(g.UserSecret) > 0:
		a.Password = string(g.UserSecret)
	default:
		// Decide on the credential's type before touching the vault: EC2
		// Instance Connect stores no secret, so Vault.Open would fail with
		// ErrNoSecret and the key-push flow below would never run.
		cred, err := h.Vault.Get(r.Context(), g.CredentialID)
		if err != nil {
			h.Log.Error("open credential", "id", g.CredentialID, "err", err)
			httpx.WriteError(w, http.StatusConflict, "credential_unavailable", "credential could not be opened")
			return
		}
		if cred.Type == credential.TypeEC2InstanceConnect {
			// Push a one-minute public key through the cloud API; nothing is
			// stored anywhere. Requires the ec2-instance-connect package on
			// the instance, which stock Amazon Linux and Ubuntu AMIs ship.
			if ep.Group == nil || h.Cloud == nil {
				httpx.WriteError(w, http.StatusConflict, "credential_unavailable", "instance connect needs an autoscaling instance")
				return
			}
			provider, err := h.Cloud(r.Context(), ep.Group)
			if err != nil {
				h.Log.Error("cloud provider", "asg", ep.Group.Name, "err", err)
				httpx.WriteError(w, http.StatusConflict, "credential_unavailable", "cloud access failed")
				return
			}
			pubLine, privPEM, err := ephemeralSSHKey()
			if err != nil {
				h.fail(w, r, err)
				return
			}
			osUser := cred.Username
			if osUser == "" {
				osUser = "ec2-user"
			}
			if err := provider.SendSSHPublicKey(r.Context(), ep.CloudInstanceID, ep.AvailabilityZone, osUser, []byte(pubLine)); err != nil {
				h.Log.Warn("instance connect push failed", "instance", ep.CloudInstanceID, "err", err)
				httpx.WriteError(w, http.StatusConflict, "credential_unavailable", "instance connect refused the key; check the role's permissions")
				return
			}
			a.Username, a.PrivateKey = osUser, privPEM
			break
		}
		opened, err := h.Vault.Open(r.Context(), g.CredentialID)
		if err != nil {
			h.Log.Error("open credential", "id", g.CredentialID, "err", err)
			httpx.WriteError(w, http.StatusConflict, "credential_unavailable", "credential could not be opened")
			return
		}
		defer opened.Close()
		switch opened.Type {
		case credential.TypeSSHCA:
			// Certificate authority mode: mint a fresh, minutes-long user
			// certificate for this session. The gateway stores no user key.
			loginUser := opened.Username
			if loginUser == "" {
				loginUser = g.Username
			}
			certLine, keyPEM, err := sshca.IssueForSession(opened.PrivateKey, loginUser, 5*time.Minute)
			if err != nil {
				h.Log.Error("mint ssh certificate", "id", g.CredentialID, "err", err)
				httpx.WriteError(w, http.StatusConflict, "credential_unavailable", "could not issue a session certificate")
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

	// Persist the session first so even a failed dial leaves a trace.
	s := &session.Session{UserID: g.UserID, PolicyID: g.PolicyID, TargetID: ep.TargetID, ASGID: ep.ASGID, ASGInstanceID: ep.ASGInstanceID,
		Protocol: g.Protocol, CredentialID: g.CredentialID, ClientIP: ip, UserAgent: r.UserAgent(), FailoverFromSessionID: g.FailoverFrom}
	if err := h.Sessions.Start(r.Context(), s); err != nil {
		h.Log.Error("start session", "err", err)
		_ = ws.Close(websocket.StatusInternalError, "could not start session")
		return
	}
	if g.FailoverFrom != "" {
		_ = h.Sessions.End(context.Background(), g.FailoverFrom, session.EndFailover)
	}
	actor := audit.Actor{UserID: g.UserID, IP: ip}
	endWith := func(reason, msg string) {
		_ = h.Sessions.End(context.Background(), s.ID, reason)
		h.record(r, actor.Event("session.end", "access_session", s.ID, audit.Success, map[string]string{"reason": reason, "target_id": ep.LiveKey}))
		if msg != "" {
			_ = ws.Close(websocket.StatusPolicyViolation, msg)
		}
	}

	timeout := h.DialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	fp := ep.HostKeyFingerprint
	client, err := sshgw.Dial(r.Context(), sshgw.Endpoint{Address: ep.Address, Port: ep.port(target.SSH), HostKeyFingerprint: fp, HostKeyTrusted: true}, a, timeout)
	if err != nil {
		reason, msg := session.EndError, "could not connect to the target"
		switch {
		case errors.Is(err, sshgw.ErrHostKeyMismatch):
			msg = "host key mismatch; connection refused"
			h.record(r, actor.Event("target.hostkey.mismatch", "target", ep.LiveKey, audit.Failure, map[string]string{"expected": fp}))
		case errors.Is(err, sshgw.ErrAuthFailed):
			msg = "authentication to the target failed"
		}
		h.Log.Warn("ssh dial failed", "target", ep.LiveKey, "err", err)
		endWith(reason, msg)
		return
	}
	defer func() { _ = client.Close() }()

	// Expose this session's SSH connection for SFTP file transfer while it is
	// open, when the policy allows it (ADR 0016).
	if g.AllowFileTransfer {
		h.Files.add(s.ID, &fileSession{client: client, userID: g.UserID, targetKey: ep.LiveKey})
		defer h.Files.remove(s.ID)
	}

	rec, uri, err := recording.NewAsciicast(r.Context(), h.Storage, s.ID+".cast", recording.Header{Width: cols, Height: rows, Title: sessionLabel(ep),
		Env: map[string]string{"ZANSKAR_SESSION": s.ID}})
	if err != nil {
		h.Log.Error("start recording", "err", err)
		endWith(session.EndError, "recording could not be started; session refused")
		return
	}
	recRow := &session.Recording{SessionID: s.ID, Format: "asciicast", StorageURI: uri}
	if err := h.Sessions.CreateRecording(r.Context(), recRow); err != nil {
		h.Log.Error("register recording", "err", err)
		_, _, _ = rec.Close()
		endWith(session.EndError, "recording could not be registered; session refused")
		return
	}
	h.record(r, actor.Event("session.start", "access_session", s.ID, audit.Success, map[string]any{"target_id": ep.LiveKey, "protocol": g.Protocol, "policy_id": g.PolicyID, "recording_id": recRow.ID}))

	ctx := h.Registry.Add(r.Context(), gateway.Live{SessionID: s.ID, UserID: g.UserID, TargetID: ep.LiveKey, Protocol: g.Protocol})
	defer h.Registry.Remove(s.ID)

	reason, berr := sshgw.Bridge(ctx, h.Log, client, ws, rec, cols, rows, sshgw.Limits{Idle: g.IdleTimeout, Max: g.MaxSession, SessionID: s.ID, AllowFiles: g.AllowFileTransfer})
	size, sum, cerr := rec.Close()
	if cerr != nil {
		h.Log.Error("close recording", "session", s.ID, "err", cerr)
	}
	if err := h.Sessions.FinishRecording(context.Background(), recRow.ID, size, sum); err != nil {
		h.Log.Error("finish recording", "session", s.ID, "err", err)
	}
	if berr != nil {
		h.Log.Warn("bridge ended with error", "session", s.ID, "err", berr)
		if reason == "" || reason == "error" {
			reason = session.EndError
		}
	}
	endWith(reason, "")
	_ = ws.Close(websocket.StatusNormalClosure, reason)
}

func (h *Handler) record(r *http.Request, e audit.Event) {
	if h.Audit == nil {
		return
	}
	if _, err := h.Audit.Record(context.WithoutCancel(r.Context()), e); err != nil {
		h.Log.Error("audit record failed", "action", e.Action, "err", err)
	}
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	h.Log.Error("connect handler", "path", r.URL.Path, "err", err)
	httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
