// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/user"
)

// ErrNoExternalIdentity signals that no external identity provider (LDAP)
// authenticated the given credentials, so the caller falls through to failure.
var ErrNoExternalIdentity = errors.New("auth: no external identity matched")

// ExternalAuthenticator authenticates a username/password against external
// identity providers (LDAP/AD) and returns the resolved local user. It is
// implemented outside this package (internal/idp) to avoid an import cycle.
type ExternalAuthenticator interface {
	Login(ctx context.Context, username, password, ip string) (*user.User, error)
}

// Handler serves /api/v1/auth/*.
type Handler struct {
	Users    *user.Repo
	Sessions *Sessions
	TOTP     *TOTP
	Audit    *audit.Log
	Log      *slog.Logger

	// MaxFailures failed passwords lock the account for LockFor.
	MaxFailures int
	LockFor     time.Duration
	// MFAAttempts wrong codes end the pending session.
	MFAAttempts int
	// RequireMFA keeps a session partial until an authenticator is enrolled.
	RequireMFA bool
	// ExternalLogin, when set, authenticates users against LDAP providers
	// after local password authentication does not apply.
	ExternalLogin ExternalAuthenticator

	loginLimiter *ipLimiter
	mfaMu        sync.Mutex
	mfaAttempts  map[string]int
}

// mfaFailure counts a wrong code and reports whether the session must end.
func (h *Handler) mfaFailure(sessionID string) bool {
	h.mfaMu.Lock()
	defer h.mfaMu.Unlock()
	h.mfaAttempts[sessionID]++
	if h.mfaAttempts[sessionID] >= h.MFAAttempts {
		delete(h.mfaAttempts, sessionID)
		return true
	}
	return false
}

func (h *Handler) mfaClear(sessionID string) {
	h.mfaMu.Lock()
	delete(h.mfaAttempts, sessionID)
	h.mfaMu.Unlock()
}

// NewHandler applies defaults.
func NewHandler(users *user.Repo, sessions *Sessions, totp *TOTP, auditLog *audit.Log, log *slog.Logger) *Handler {
	return &Handler{
		Users: users, Sessions: sessions, TOTP: totp, Audit: auditLog, Log: log,
		MaxFailures: 5, LockFor: 15 * time.Minute, MFAAttempts: 5,
		loginLimiter: newIPLimiter(20, 10),
		mfaAttempts:  map[string]int{},
	}
}

// Register mounts the routes. The middleware chain (Authenticate, CSRF) must
// wrap the mux these are registered on.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/login", h.login)
	mux.Handle("POST /api/v1/auth/logout", RequirePartialAuth(http.HandlerFunc(h.logout)))
	mux.Handle("GET /api/v1/auth/me", RequireAuth(http.HandlerFunc(h.me)))
	mux.Handle("POST /api/v1/auth/mfa/totp/verify", RequirePartialAuth(http.HandlerFunc(h.totpVerify)))
	// Enroll and confirm accept a partial session so a deployment that
	// requires MFA can make enrollment the first thing a new user does.
	mux.Handle("POST /api/v1/auth/mfa/totp/enroll", RequirePartialAuth(http.HandlerFunc(h.totpEnroll)))
	mux.Handle("POST /api/v1/auth/mfa/totp/confirm", RequirePartialAuth(http.HandlerFunc(h.totpConfirm)))
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Status    string     `json:"status"` // ok | mfa_required
	User      *user.User `json:"user,omitempty"`
	CSRFToken string     `json:"csrf_token,omitempty"`
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	ip := ClientIP(r)
	actor := audit.Actor{IP: ip}
	if !h.loginLimiter.Allow(ip) {
		h.record(r, actor.Event("user.login", "user", "", audit.Failure, map[string]string{"reason": "rate_limited"}))
		WriteError(w, http.StatusTooManyRequests, "rate_limited", "too many attempts; try again later")
		return
	}
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" || len(req.Password) > user.MaxPasswordLen {
		WriteError(w, http.StatusBadRequest, "bad_request", "username and password required")
		return
	}
	attempted := truncate(req.Username, 64)

	u, err := h.Users.GetByUsername(r.Context(), req.Username)
	if err != nil {
		if !errors.Is(err, user.ErrNotFound) {
			h.serverError(w, r, err)
			return
		}
		// No local user: a first-time LDAP user is provisioned on login, so
		// try external providers before rejecting.
		if h.ExternalLogin != nil {
			if eu, eerr := h.ExternalLogin.Login(r.Context(), req.Username, req.Password, ip); eerr == nil {
				_ = h.Users.RecordLoginSuccess(r.Context(), eu.ID)
				actor.UserID = eu.ID
				h.completeLogin(w, r, eu, actor)
				return
			} else if !errors.Is(eerr, ErrNoExternalIdentity) {
				h.Log.Warn("external login error", "err", eerr)
			}
		}
		user.BurnPasswordCheck(req.Password)
		h.record(r, actor.Event("user.login", "user", "", audit.Failure, map[string]string{"reason": "unknown_user", "username": attempted}))
		WriteError(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}
	actor.UserID = u.ID
	// Local password path: only when the account carries a password hash.
	if u.PasswordHash != "" {
		if u.IsLocked(time.Now()) {
			user.BurnPasswordCheck(req.Password)
			h.record(r, actor.Event("user.login", "user", u.ID, audit.Failure, map[string]string{"reason": "locked"}))
			WriteError(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
			return
		}
		if !user.VerifyPassword(u.PasswordHash, req.Password) {
			locked, lerr := h.Users.RecordLoginFailure(r.Context(), u.ID, h.MaxFailures, h.LockFor)
			if lerr != nil {
				h.Log.Error("record login failure", "err", lerr)
			}
			details := map[string]any{"reason": "bad_password"}
			if locked {
				details["locked_for"] = h.LockFor.String()
			}
			h.record(r, actor.Event("user.login", "user", u.ID, audit.Failure, details))
			WriteError(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
			return
		}
		if user.NeedsRehash(u.PasswordHash) {
			if nh, err := user.HashPassword(req.Password); err == nil {
				_ = h.Users.SetPasswordHash(r.Context(), u.ID, nh)
			}
		}
		if err := h.Users.RecordLoginSuccess(r.Context(), u.ID); err != nil {
			h.serverError(w, r, err)
			return
		}
		h.completeLogin(w, r, u, actor)
		return
	}

	// External path: the local user has no password (provisioned from an IdP),
	// so try LDAP providers with the supplied credentials.
	if h.ExternalLogin != nil {
		eu, eerr := h.ExternalLogin.Login(r.Context(), req.Username, req.Password, ip)
		if eerr == nil {
			_ = h.Users.RecordLoginSuccess(r.Context(), eu.ID)
			actor.UserID = eu.ID
			h.completeLogin(w, r, eu, actor)
			return
		}
		if !errors.Is(eerr, ErrNoExternalIdentity) {
			h.Log.Warn("external login error", "err", eerr)
		}
	}
	user.BurnPasswordCheck(req.Password)
	h.record(r, actor.Event("user.login", "user", u.ID, audit.Failure, map[string]string{"reason": "no_password_no_external"}))
	WriteError(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
}

// completeLogin issues the session and returns the appropriate MFA status.
func (h *Handler) completeLogin(w http.ResponseWriter, r *http.Request, u *user.User, actor audit.Actor) {
	ip := ClientIP(r)
	enrolled, err := h.TOTP.Enrolled(r.Context(), u.ID)
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	full := enrolled || !h.RequireMFA
	token, sess, err := h.Sessions.Create(r.Context(), u.ID, ip, r.UserAgent(), full && !enrolled)
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	h.Sessions.SetCookie(w, token)
	if !enrolled && h.RequireMFA {
		h.record(r, actor.Event("user.login", "user", u.ID, audit.Success, map[string]string{"stage": "password", "next": "mfa_enrollment", "session_id": sess.ID}))
		WriteJSON(w, http.StatusOK, loginResponse{Status: "mfa_enrollment_required", CSRFToken: h.Sessions.CSRFToken(sess.ID)})
		return
	}
	if enrolled {
		h.record(r, actor.Event("user.login", "user", u.ID, audit.Success, map[string]string{"stage": "password", "session_id": sess.ID}))
		WriteJSON(w, http.StatusOK, loginResponse{Status: "mfa_required", CSRFToken: h.Sessions.CSRFToken(sess.ID)})
		return
	}
	h.record(r, actor.Event("user.login", "user", u.ID, audit.Success, map[string]string{"stage": "complete", "mfa": "none", "session_id": sess.ID}))
	WriteJSON(w, http.StatusOK, loginResponse{Status: "ok", User: u, CSRFToken: h.Sessions.CSRFToken(sess.ID)})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	p, _ := FromContext(r.Context())
	if err := h.Sessions.Revoke(r.Context(), p.Session.ID); err != nil {
		h.serverError(w, r, err)
		return
	}
	h.Sessions.ClearCookie(w)
	h.record(r, h.actor(r).Event("user.logout", "user", p.User.ID, audit.Success, map[string]string{"session_id": p.Session.ID}))
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	p, _ := FromContext(r.Context())
	enrolled, err := h.TOTP.Enrolled(r.Context(), p.User.ID)
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"user":         p.User,
		"csrf_token":   h.Sessions.CSRFToken(p.Session.ID),
		"mfa_enrolled": enrolled,
		"session": map[string]any{
			"id": p.Session.ID, "created_at": p.Session.CreatedAt, "expires_at": p.Session.ExpiresAt,
		},
	})
}

type codeRequest struct {
	Code string `json:"code"`
}

func (h *Handler) totpVerify(w http.ResponseWriter, r *http.Request) {
	p, _ := FromContext(r.Context())
	if p.Session.MFAVerified {
		WriteJSON(w, http.StatusOK, loginResponse{Status: "ok", User: p.User, CSRFToken: h.Sessions.CSRFToken(p.Session.ID)})
		return
	}
	var req codeRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	usedRecovery, err := h.TOTP.Verify(r.Context(), p.User.ID, req.Code)
	if err != nil {
		if errors.Is(err, ErrTOTPBadCode) || errors.Is(err, ErrTOTPNotEnrolled) {
			details := map[string]any{"reason": "bad_code", "session_id": p.Session.ID}
			if h.mfaFailure(p.Session.ID) {
				_ = h.Sessions.Revoke(r.Context(), p.Session.ID)
				h.Sessions.ClearCookie(w)
				details["session_ended"] = true
			}
			h.record(r, h.actor(r).Event("user.mfa.verify", "user", p.User.ID, audit.Failure, details))
			WriteError(w, http.StatusUnauthorized, "invalid_code", "invalid code")
			return
		}
		h.serverError(w, r, err)
		return
	}
	h.mfaClear(p.Session.ID)
	if err := h.Sessions.MarkMFAVerified(r.Context(), p.Session.ID); err != nil {
		h.serverError(w, r, err)
		return
	}
	method := "totp"
	if usedRecovery {
		method = "recovery_code"
	}
	h.record(r, h.actor(r).Event("user.login", "user", p.User.ID, audit.Success, map[string]string{"stage": "complete", "mfa": method, "session_id": p.Session.ID}))
	WriteJSON(w, http.StatusOK, loginResponse{Status: "ok", User: p.User, CSRFToken: h.Sessions.CSRFToken(p.Session.ID)})
}

func (h *Handler) totpEnroll(w http.ResponseWriter, r *http.Request) {
	p, _ := FromContext(r.Context())
	enr, err := h.TOTP.Enroll(r.Context(), p.User.ID, p.User.Username)
	if err != nil {
		if errors.Is(err, ErrTOTPBadCode) || strings.Contains(err.Error(), "already") {
			WriteError(w, http.StatusConflict, "already_enrolled", "an authenticator is already enrolled")
			return
		}
		h.serverError(w, r, err)
		return
	}
	h.record(r, h.actor(r).Event("user.mfa.enroll", "user", p.User.ID, audit.Success, nil))
	WriteJSON(w, http.StatusOK, enr)
}

func (h *Handler) totpConfirm(w http.ResponseWriter, r *http.Request) {
	p, _ := FromContext(r.Context())
	var req codeRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	codes, err := h.TOTP.Confirm(r.Context(), p.User.ID, strings.TrimSpace(req.Code))
	if err != nil {
		switch {
		case errors.Is(err, ErrTOTPBadCode):
			h.record(r, h.actor(r).Event("user.mfa.confirm", "user", p.User.ID, audit.Failure, nil))
			WriteError(w, http.StatusUnauthorized, "invalid_code", "invalid code")
		case errors.Is(err, ErrTOTPNotEnrolled):
			WriteError(w, http.StatusConflict, "not_enrolled", "start enrollment first")
		default:
			h.serverError(w, r, err)
		}
		return
	}
	// A freshly confirmed authenticator counts as a verified second factor
	// for this session: the user just proved possession of it.
	if !p.Session.MFAVerified {
		if err := h.Sessions.MarkMFAVerified(r.Context(), p.Session.ID); err != nil {
			h.serverError(w, r, err)
			return
		}
	}
	h.record(r, h.actor(r).Event("user.mfa.confirm", "user", p.User.ID, audit.Success, nil))
	WriteJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes, "status": "ok", "csrf_token": h.Sessions.CSRFToken(p.Session.ID)})
}

// ---- helpers

func (h *Handler) actor(r *http.Request) audit.Actor {
	a := audit.Actor{IP: ClientIP(r)}
	if p, ok := FromContext(r.Context()); ok {
		a.UserID = p.User.ID
	}
	return a
}

func (h *Handler) record(r *http.Request, e audit.Event) {
	if h.Audit == nil {
		return
	}
	if _, err := h.Audit.Record(r.Context(), e); err != nil {
		h.Log.Error("audit record failed", "action", e.Action, "err", err)
	}
}

func (h *Handler) serverError(w http.ResponseWriter, r *http.Request, err error) {
	h.Log.Error("auth handler", "path", r.URL.Path, "err", err)
	WriteError(w, http.StatusInternalServerError, "internal", "internal error")
}

func decodeJSON(r *http.Request, v any) error {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		return errors.New("content-type must be application/json")
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("malformed JSON body")
	}
	return nil
}
