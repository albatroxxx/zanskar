// SPDX-License-Identifier: Apache-2.0

// Package connect is where a user's request to reach a target is decided
// and, if allowed, turned into a live bridge. POST /connect evaluates policy
// and issues a ticket; GET /ws/terminal redeems the ticket and runs the
// session. Nothing about the target (address, credential) ever reaches the
// browser.
package connect

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/coder/websocket"

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
	DialTimeout time.Duration
	// GuacdAddr enables RDP and VNC; empty disables desktop sessions.
	GuacdAddr string
}

// Register mounts the routes. The WebSocket route sits outside the CSRF
// middleware's mutating-method check because it is a GET; the ticket is its
// only credential.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/me/targets", auth.RequireAuth(http.HandlerFunc(h.myTargets)))
	mux.Handle("POST /api/v1/connect", auth.RequireAuth(http.HandlerFunc(h.connect)))
	mux.HandleFunc("GET /ws/terminal", h.terminal)
	mux.HandleFunc("GET /ws/desktop", h.desktop)
	mux.HandleFunc("GET /ws/winrm", h.winrm)
}

// reachableTarget is what a user sees in their target list.
type reachableTarget struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	OSFamily     target.OSFamily   `json:"os_family"`
	Tags         map[string]string `json:"tags"`
	Capabilities []target.Protocol `json:"capabilities"`
	Allowed      []string          `json:"allowed_protocols"`
	HostKeyReady bool              `json:"host_key_ready"`
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
			if len(allowed) == 0 {
				continue
			}
			out = append(out, reachableTarget{
				ID: t.ID, Name: t.Name, OSFamily: t.OSFamily, Tags: t.Tags, Capabilities: t.Capabilities,
				Allowed: allowed, HostKeyReady: t.HostKeyStatus == target.HostKeyTrusted,
			})
		}
		if next == "" {
			break
		}
		after = next
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.Page[reachableTarget]{Items: out})
}

type connectRequest struct {
	TargetID   string `json:"target_id"`
	Protocol   string `json:"protocol"`
	Credential *struct {
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"credential,omitempty"`
}

type connectResponse struct {
	Ticket    string    `json:"ticket"`
	ExpiresAt time.Time `json:"expires_at"`
	Path      string    `json:"ws_path"`
	SessionID string    `json:"-"`
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
	case target.SSH, target.WinRM:
	case target.RDP, target.VNC:
		if h.GuacdAddr == "" {
			deny(http.StatusNotImplemented, "protocol_unavailable", "desktop sessions are not configured on this gateway")
			return
		}
	default:
		deny(http.StatusNotImplemented, "protocol_unavailable", "protocol not available")
		return
	}
	t, err := h.Targets.Get(r.Context(), req.TargetID)
	if err != nil {
		if errors.Is(err, target.ErrNotFound) {
			deny(http.StatusNotFound, "not_found", "target not found")
			return
		}
		h.fail(w, r, err)
		return
	}
	if t.Status != "active" {
		deny(http.StatusConflict, "target_disabled", "target is disabled")
		return
	}
	pols, err := h.Policies.ForUser(r.Context(), p.User.ID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	d := policy.Evaluate(pols, policy.TargetRef{ID: t.ID, Tags: t.Tags}, req.Protocol, time.Now())
	if !d.Allowed {
		deny(http.StatusForbidden, "policy_denied", d.Reason)
		return
	}
	if d.RequireMFA && h.MFAEnrolled != nil {
		enrolled, err := h.MFAEnrolled(r.Context(), p.User.ID)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		if !enrolled {
			deny(http.StatusForbidden, "mfa_required_by_policy", "this policy requires an enrolled authenticator")
			return
		}
	}
	if proto == target.SSH && t.HostKeyStatus != target.HostKeyTrusted {
		deny(http.StatusConflict, "host_key_untrusted", "the target's host key has not been trusted by an admin")
		return
	}
	if proto == target.RDP && (t.TLSFingerprint == nil || *t.TLSFingerprint == "") {
		deny(http.StatusConflict, "certificate_unpinned", "the target's RDP certificate has not been captured; probe it first")
		return
	}
	if proto == target.WinRM {
		if t.Port(target.WinRM) == 5985 {
			deny(http.StatusConflict, "tls_required", "winrm over plain HTTP is not allowed; use the HTTPS listener (5986)")
			return
		}
		if t.WinRMTLSFingerprint == nil || *t.WinRMTLSFingerprint == "" {
			deny(http.StatusConflict, "certificate_unpinned", "the target's WinRM certificate has not been captured; probe it first")
			return
		}
	}
	credID, ok := t.Credentials[proto]
	if !ok || credID == "" {
		deny(http.StatusConflict, "no_credential", "no credential is configured for "+req.Protocol+" on this target")
		return
	}
	cred, err := h.Vault.Get(r.Context(), credID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	grant := ticket.Grant{
		UserID: p.User.ID, Username: p.User.Username, SessionID: p.Session.ID,
		TargetID: t.ID, Protocol: req.Protocol, CredentialID: credID, PolicyID: d.Policy.ID,
		IdleTimeout: d.IdleTimeout, MaxSession: d.MaxSession,
		AllowClipboard: d.AllowClipboard, AllowFileTransfer: d.AllowFileTransfer,
		ClientIP: auth.ClientIP(r),
	}
	switch cred.Mode {
	case credential.ModeVaulted:
	case credential.ModeUserSupplied:
		if req.Credential == nil || req.Credential.Username == "" || req.Credential.Password == "" {
			deny(http.StatusUnprocessableEntity, "credential_required", "this target needs your username and password")
			return
		}
		grant.Username = req.Credential.Username
		grant.UserSecret = []byte(req.Credential.Password)
	default:
		deny(http.StatusNotImplemented, "credential_mode_unavailable", "credential mode not supported yet")
		return
	}
	tok, err := h.Tickets.Issue(grant)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, actor.Event("session.connect", "target", t.ID, audit.Success, map[string]any{"protocol": req.Protocol, "policy_id": d.Policy.ID, "credential_id": credID}))
	httpx.WriteJSON(w, http.StatusOK, connectResponse{Ticket: tok, ExpiresAt: time.Now().Add(ticket.TTL), Path: ticketPathFor(proto)})
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

	t, err := h.Targets.Get(r.Context(), g.TargetID)
	if err != nil || t.HostKeyStatus != target.HostKeyTrusted || t.Status != "active" {
		httpx.WriteError(w, http.StatusConflict, "target_unavailable", "target is no longer available")
		return
	}

	// Resolve credential material before upgrading, so a vault failure is a
	// plain HTTP error rather than a broken socket.
	a := sshgw.Auth{Username: g.Username}
	if len(g.UserSecret) > 0 {
		a.Password = string(g.UserSecret)
	} else {
		opened, err := h.Vault.Open(r.Context(), g.CredentialID)
		if err != nil {
			h.Log.Error("open credential", "id", g.CredentialID, "err", err)
			httpx.WriteError(w, http.StatusConflict, "credential_unavailable", "credential could not be opened")
			return
		}
		defer opened.Close()
		if opened.Type == credential.TypeSSHCA {
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
		} else {
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
	s := &session.Session{UserID: g.UserID, PolicyID: g.PolicyID, TargetID: t.ID, Protocol: g.Protocol, CredentialID: g.CredentialID, ClientIP: ip, UserAgent: r.UserAgent()}
	if err := h.Sessions.Start(r.Context(), s); err != nil {
		h.Log.Error("start session", "err", err)
		_ = ws.Close(websocket.StatusInternalError, "could not start session")
		return
	}
	actor := audit.Actor{UserID: g.UserID, IP: ip}
	endWith := func(reason, msg string) {
		_ = h.Sessions.End(context.Background(), s.ID, reason)
		h.record(r, actor.Event("session.end", "access_session", s.ID, audit.Success, map[string]string{"reason": reason, "target_id": t.ID}))
		if msg != "" {
			_ = ws.Close(websocket.StatusPolicyViolation, msg)
		}
	}

	timeout := h.DialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	fp := ""
	if t.HostKeyFingerprint != nil {
		fp = *t.HostKeyFingerprint
	}
	client, err := sshgw.Dial(r.Context(), sshgw.Endpoint{Address: t.Address, Port: t.Port(target.SSH), HostKeyFingerprint: fp, HostKeyTrusted: true}, a, timeout)
	if err != nil {
		reason, msg := session.EndError, "could not connect to the target"
		switch {
		case errors.Is(err, sshgw.ErrHostKeyMismatch):
			msg = "host key mismatch; connection refused"
			h.record(r, actor.Event("target.hostkey.mismatch", "target", t.ID, audit.Failure, map[string]string{"expected": fp}))
		case errors.Is(err, sshgw.ErrAuthFailed):
			msg = "authentication to the target failed"
		}
		h.Log.Warn("ssh dial failed", "target", t.ID, "err", err)
		endWith(reason, msg)
		return
	}
	defer func() { _ = client.Close() }()

	rec, uri, err := recording.NewAsciicast(r.Context(), h.Storage, s.ID+".cast", recording.Header{Width: cols, Height: rows, Title: t.Name,
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
	h.record(r, actor.Event("session.start", "access_session", s.ID, audit.Success, map[string]any{"target_id": t.ID, "protocol": g.Protocol, "policy_id": g.PolicyID, "recording_id": recRow.ID}))

	ctx := h.Registry.Add(r.Context(), gateway.Live{SessionID: s.ID, UserID: g.UserID, TargetID: t.ID, Protocol: g.Protocol})
	defer h.Registry.Remove(s.ID)

	reason, berr := sshgw.Bridge(ctx, h.Log, client, ws, rec, cols, rows, sshgw.Limits{Idle: g.IdleTimeout, Max: g.MaxSession})
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
