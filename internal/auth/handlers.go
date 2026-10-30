// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash/fnv"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/httpx"
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

	// MaxFailures wrong passwords and wrong second-factor codes, counted
	// together until a sign-in completes, lock the account against new
	// sign-ins for LockFor.
	MaxFailures int
	LockFor     time.Duration
	// MFAAttempts wrong codes end the pending session.
	MFAAttempts int
	// ProviderLogout, when set, names the page at a single sign-on provider
	// that ends the provider's session for a session signing out (ADR
	// 0035), or "" when there is none. It is read after the session is
	// revoked.
	ProviderLogout func(r *http.Request, sessionID string) string
	// RequireMFA keeps a session partial until an authenticator is enrolled.
	// It is read at every sign-in so the runtime setting applies live; nil
	// means not required.
	RequireMFA func() bool
	// ExternalLogin, when set, authenticates users against LDAP providers
	// after local password authentication does not apply.
	ExternalLogin ExternalAuthenticator

	loginLimiter *ipLimiter
	// stepUpLimiter bounds code attempts per session on the step-up route.
	stepUpLimiter *ipLimiter
	// stepUpMu guards stepUpFails: wrong step-up codes per session, which
	// close the route for that session after MFAAttempts of them (as the
	// console command line does) rather than charging the account budget,
	// which a stolen cookie could use to lock its owner out.
	stepUpMu    sync.Mutex
	stepUpFails map[string]*stepUpState
	mfaMu       sync.Mutex
	mfaAttempts map[string]int
	// codeChecks runs second-factor checks one at a time per account.
	codeChecks accountLocks
}

// accountLockStripes is how many locks accountLocks spreads accounts over.
const accountLockStripes = 64

// accountLocks serialises work per account. It is striped rather than one
// lock per account so it needs no bookkeeping: two accounts that share a
// stripe only wait out each other's few milliseconds.
type accountLocks [accountLockStripes]sync.Mutex

// lock takes the lock for userID and returns its unlock.
func (l *accountLocks) lock(userID string) (unlock func()) {
	h := fnv.New32a()
	_, _ = h.Write([]byte(userID))
	m := &l[h.Sum32()%accountLockStripes]
	m.Lock()
	return m.Unlock
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
		loginLimiter:  newIPLimiter(20, 10),
		stepUpLimiter: newIPLimiter(10, 5),
		mfaAttempts:   map[string]int{},
		stepUpFails:   map[string]*stepUpState{},
	}
}

// stepUpState counts a session's wrong step-up codes and says until when
// the route is closed to it.
type stepUpState struct {
	fails       int
	closedUntil time.Time
}

// stepUpClosed reports whether the session's step-up route is closed. Stale
// entries are dropped as they are met, so the map tracks only sessions that
// are guessing now.
func (h *Handler) stepUpClosed(sessionID string, now time.Time) bool {
	h.stepUpMu.Lock()
	defer h.stepUpMu.Unlock()
	st, ok := h.stepUpFails[sessionID]
	if !ok {
		return false
	}
	if !st.closedUntil.IsZero() && now.Before(st.closedUntil) {
		return true
	}
	if !st.closedUntil.IsZero() {
		delete(h.stepUpFails, sessionID)
	}
	return false
}

// stepUpFailed counts a wrong code and reports whether that closed the
// route for the session.
func (h *Handler) stepUpFailed(sessionID string, now time.Time) (closed bool) {
	h.stepUpMu.Lock()
	defer h.stepUpMu.Unlock()
	if len(h.stepUpFails) > maxLimiterKeys {
		for id, st := range h.stepUpFails {
			if !st.closedUntil.IsZero() && !now.Before(st.closedUntil) {
				delete(h.stepUpFails, id)
			}
		}
	}
	st := h.stepUpFails[sessionID]
	if st == nil {
		st = &stepUpState{}
		h.stepUpFails[sessionID] = st
	}
	st.fails++
	if st.fails >= h.MFAAttempts {
		st.fails, st.closedUntil = 0, now.Add(h.LockFor)
		return true
	}
	return false
}

// stepUpSucceeded forgets the session's wrong codes.
func (h *Handler) stepUpSucceeded(sessionID string) {
	h.stepUpMu.Lock()
	delete(h.stepUpFails, sessionID)
	h.stepUpMu.Unlock()
}

// Register mounts the routes. The middleware chain (Authenticate, CSRF) must
// wrap the mux these are registered on.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/login", h.login)
	mux.Handle("POST /api/v1/auth/logout", RequirePartialAuth(http.HandlerFunc(h.logout)))
	// /auth/me admits a partial (MFA-incomplete) session so a page reload during
	// second-factor setup can recover the pending step and CSRF token instead of
	// stranding the session; the handler withholds the profile until MFA is done.
	mux.Handle("GET /api/v1/auth/me", RequirePartialAuth(http.HandlerFunc(h.me)))
	mux.Handle("POST /api/v1/auth/password", RequirePartialAuth(http.HandlerFunc(h.changePassword)))
	mux.Handle("POST /api/v1/auth/mfa/totp/verify", RequirePartialAuth(http.HandlerFunc(h.totpVerify)))
	// A signed-in session proves its authenticator again for the actions the
	// console guards with a recent code (ADR 0032).
	mux.Handle("POST /api/v1/auth/mfa/step-up", RequireAuth(http.HandlerFunc(h.stepUp)))
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
	if ok, first := h.loginLimiter.Take(limiterKey(ip)); !ok {
		// One row per run of refusals from an address, not one per attempt:
		// an unauthenticated flood must not grow the hash-chained log, and
		// queue every other event behind its writer, without bound (L11).
		if first {
			h.record(r, actor.Event(audit.UserLogin, "user", "", audit.Failure, map[string]string{"reason": "rate_limited"}))
		}
		httpx.WriteError(w, r, http.StatusTooManyRequests, "rate_limited", "too many attempts; try again later")
		return
	}
	var req loginRequest
	if err := httpx.DecodeJSONLimit(r, &req, signInBodyLimit); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" || len(req.Password) > user.MaxPasswordLen {
		httpx.WriteError(w, r, http.StatusBadRequest, "bad_request", "username and password required")
		return
	}
	// What was typed into the username box is never stored: a password typed
	// there by mistake would sit in the insert-only audit chain for good. A
	// short hash of it still lets an auditor see one name being sprayed.
	attempted := usernameHash(req.Username)

	u, err := h.Users.GetByUsername(r.Context(), req.Username)
	if err != nil {
		if !errors.Is(err, user.ErrNotFound) {
			httpx.Internal(w, r, h.Log, err)
			return
		}
		// No local user: a first-time LDAP user is provisioned on login, so
		// try external providers before rejecting.
		if h.ExternalLogin != nil {
			if eu, eerr := h.ExternalLogin.Login(r.Context(), req.Username, req.Password, ip); eerr == nil {
				actor.UserID = eu.ID
				h.completeLogin(w, r, eu, actor)
				return
			} else if !errors.Is(eerr, ErrNoExternalIdentity) {
				h.Log.Warn("external login error", "err", eerr)
			}
		}
		if !h.hashing(w, r, func() { user.BurnPasswordCheck(req.Password) }) {
			return
		}
		h.record(r, actor.Event(audit.UserLogin, "user", "", audit.Failure, map[string]string{"reason": "unknown_user", "username_hash": attempted}))
		httpx.WriteError(w, r, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}
	actor.UserID = u.ID
	// Local password path: only when the account carries a password hash.
	if u.PasswordHash != "" {
		if u.IsLocked(time.Now()) {
			if !h.hashing(w, r, func() { user.BurnPasswordCheck(req.Password) }) {
				return
			}
			h.record(r, actor.Event(audit.UserLogin, "user", u.ID, audit.Failure, map[string]string{"reason": "locked"}))
			httpx.WriteError(w, r, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
			return
		}
		var (
			match  bool
			rehash string
		)
		if !h.hashing(w, r, func() {
			match = user.VerifyPassword(u.PasswordHash, req.Password)
			if match && user.NeedsRehash(u.PasswordHash) {
				if nh, err := user.HashPassword(req.Password); err == nil {
					rehash = nh
				}
			}
		}) {
			return
		}
		if !match {
			locked, lerr := h.Users.RecordLoginFailure(r.Context(), u.ID, h.MaxFailures, h.LockFor)
			if lerr != nil {
				h.Log.Error("record login failure", "err", lerr)
			}
			details := map[string]any{"reason": "bad_password"}
			if locked {
				details["locked_for"] = h.LockFor.String()
			}
			h.record(r, actor.Event(audit.UserLogin, "user", u.ID, audit.Failure, details))
			httpx.WriteError(w, r, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
			return
		}
		if rehash != "" {
			_ = h.Users.SetPasswordHash(r.Context(), u.ID, rehash, u.MustResetOnLogin)
		}
		h.completeLogin(w, r, u, actor)
		return
	}

	// External path: the local user has no password (provisioned from an IdP),
	// so try LDAP providers with the supplied credentials. The account's own
	// lock applies here as to a local password: wrong directory passwords
	// count against it, and while it is locked the directory is not asked,
	// so a sprayer cannot drive the directory's own lockout through the
	// gateway. Each kind of refusal is audited as what it was.
	if h.ExternalLogin != nil {
		if u.IsLocked(time.Now()) {
			if !h.hashing(w, r, func() { user.BurnPasswordCheck(req.Password) }) {
				return
			}
			h.record(r, actor.Event(audit.UserLogin, "user", u.ID, audit.Failure, map[string]string{"reason": "locked"}))
			httpx.WriteError(w, r, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
			return
		}
		eu, eerr := h.ExternalLogin.Login(r.Context(), req.Username, req.Password, ip)
		if eerr == nil {
			actor.UserID = eu.ID
			h.completeLogin(w, r, eu, actor)
			return
		}
		details := map[string]any{"reason": "directory_unavailable"}
		if errors.Is(eerr, ErrNoExternalIdentity) {
			details["reason"] = "external_bad_credentials"
			locked, lerr := h.Users.RecordLoginFailure(r.Context(), u.ID, h.MaxFailures, h.LockFor)
			if lerr != nil {
				h.Log.Error("record login failure", "err", lerr)
			}
			if locked {
				details["locked_for"] = h.LockFor.String()
			}
		} else {
			h.Log.Warn("external login error", "err", eerr)
		}
		h.record(r, actor.Event(audit.UserLogin, "user", u.ID, audit.Failure, details))
		httpx.WriteError(w, r, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}
	if !h.hashing(w, r, func() { user.BurnPasswordCheck(req.Password) }) {
		return
	}
	h.record(r, actor.Event(audit.UserLogin, "user", u.ID, audit.Failure, map[string]string{"reason": "no_password_no_external"}))
	httpx.WriteError(w, r, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
}

// usernameHash is the first 16 hex characters of the SHA-256 of the typed
// username, lower-cased: enough to correlate attempts, never the text.
func usernameHash(username string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(username))))
	return hex.EncodeToString(sum[:8])
}

// hashing runs fn, which computes password hashes, in a passwordHashing
// slot (M10). When none comes free in time it answers 503 busy and returns
// false, and the caller stops there: the attempt was not checked, so it is
// neither counted nor audited.
func (h *Handler) hashing(w http.ResponseWriter, r *http.Request, fn func()) bool {
	leave, ok := passwordHashing.enter(r.Context())
	if !ok {
		httpx.WriteError(w, r, http.StatusServiceUnavailable, "busy", "too many sign-ins at once; try again in a moment")
		return false
	}
	defer leave()
	fn()
	return true
}

// replaceSession ends the session the request arrived with, when it had
// one: a browser that signs in again holds one cookie, and the token it
// held before must not stay valid for whoever else may hold it (S1 L5).
// It is called once the new sign-in has been accepted, before its session
// is issued. ReplaceSession is the same for other sign-in handlers.
func (h *Handler) replaceSession(r *http.Request) {
	ReplaceSession(r, h.Sessions, h.Audit, h.Log)
}

// ReplaceSession revokes the session the request carries, if any, and
// audits it as a sign-out with the reason "replaced".
func ReplaceSession(r *http.Request, sessions *Sessions, auditLog *audit.Log, log *slog.Logger) {
	p, ok := FromContext(r.Context())
	if !ok || p == nil || p.Session == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), recordTimeout)
	defer cancel()
	if err := sessions.Revoke(ctx, p.Session.ID); err != nil {
		log.Error("revoke the session a new sign-in replaces", "err", err)
		return
	}
	Recorder{Audit: auditLog, Log: log}.Record(r, ActorFor(r).Event(audit.UserLogout, "user", p.User.ID, audit.Success,
		map[string]string{"session_id": p.Session.ID, "reason": "replaced"}))
}

// completeLogin issues the session and returns the appropriate MFA status.
func (h *Handler) completeLogin(w http.ResponseWriter, r *http.Request, u *user.User, actor audit.Actor) {
	ip := ClientIP(r)
	h.replaceSession(r)
	enrolled, err := h.TOTP.Enrolled(r.Context(), u.ID)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	require := h.RequireMFA != nil && h.RequireMFA()
	full := enrolled || !require
	// A password an administrator chose must be replaced before the second
	// factor and before anything else: the session stays partial until the
	// change is done (QA finding R25).
	if u.MustResetOnLogin {
		full = false
	}
	complete := full && !enrolled
	// Only a sign-in that completes clears the account's failure count. One
	// that still owes a second factor or a password change leaves it alone:
	// wrong codes count against the same budget as wrong passwords, and the
	// right password must not hand out a fresh set of guesses at the code
	// (M7). The step that completes the sign-in clears it.
	if complete {
		if err := h.Users.RecordLoginSuccess(r.Context(), u.ID); err != nil {
			httpx.Internal(w, r, h.Log, err)
			return
		}
	}
	token, sess, err := h.Sessions.Create(r.Context(), u.ID, ip, r.UserAgent(), complete)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	h.Sessions.SetCookie(w, token)
	// An account with an authenticator proves it before anything else, the
	// change included: whoever holds only the reset password must not get
	// to choose the next one. An account without one changes first, then
	// enrols.
	if !enrolled && u.MustResetOnLogin {
		h.record(r, actor.Event(audit.UserLogin, "user", u.ID, audit.Success, map[string]string{"stage": "password", "next": "password_change", "session_id": sess.ID}))
		httpx.WriteJSON(w, http.StatusOK, loginResponse{Status: "password_change_required", CSRFToken: h.Sessions.CSRFToken(sess.ID)})
		return
	}
	if !enrolled && require {
		h.record(r, actor.Event(audit.UserLogin, "user", u.ID, audit.Success, map[string]string{"stage": "password", "next": "mfa_enrollment", "session_id": sess.ID}))
		httpx.WriteJSON(w, http.StatusOK, loginResponse{Status: "mfa_enrollment_required", CSRFToken: h.Sessions.CSRFToken(sess.ID)})
		return
	}
	if enrolled {
		h.record(r, actor.Event(audit.UserLogin, "user", u.ID, audit.Success, map[string]string{"stage": "password", "session_id": sess.ID}))
		httpx.WriteJSON(w, http.StatusOK, loginResponse{Status: "mfa_required", CSRFToken: h.Sessions.CSRFToken(sess.ID)})
		return
	}
	h.record(r, actor.Event(audit.UserLogin, "user", u.ID, audit.Success, map[string]string{"stage": "complete", "mfa": "none", "session_id": sess.ID}))
	httpx.WriteJSON(w, http.StatusOK, loginResponse{Status: "ok", User: u, CSRFToken: h.Sessions.CSRFToken(sess.ID)})
}

// actionSelfReset is the audit action for a user replacing their own
// password.
const actionSelfReset = audit.UserPasswordChange

// recordAction builds and records an audit event from its parts. The event
// is built here, from plain parameters, rather than at the call sites:
// CodeQL takes a call whose action argument evaluates to a password-like
// string as a source of secret data, and then reads the audit chain's
// SHA-256 over the event as password hashing, which it is not (the event
// carries no password; the chain hashes every event's JSON for tamper
// evidence). The admin API records the same way.
func (h *Handler) recordAction(r *http.Request, actor audit.Actor, action, objectType, objectID string, outcome audit.Outcome, details any) {
	h.record(r, actor.Event(action, objectType, objectID, outcome, details))
}

// currentPassword checks the password a signed-in user gives again before a
// step a stolen session must not take on its own: changing the password, or
// adding an authenticator. A wrong one counts against the account like a
// wrong sign-in password (L17), and while the account is locked the check is
// refused before any hash is spent, so a session cannot go on guessing. An
// account without a local password has none to give and counts nothing.
// When it returns false it has answered.
func (h *Handler) currentPassword(w http.ResponseWriter, r *http.Request, p *Principal, password, action string) bool {
	actor := ActorFor(r)
	if p.User.IsLocked(time.Now()) {
		h.recordAction(r, actor, action, "user", p.User.ID, audit.Failure, map[string]string{"reason": "locked"})
		httpx.WriteError(w, r, http.StatusTooManyRequests, "too_many_attempts", "too many wrong passwords; try again later")
		return false
	}
	var ok bool
	if p.User.PasswordHash != "" && !h.hashing(w, r, func() { ok = user.VerifyPassword(p.User.PasswordHash, password) }) {
		return false
	}
	if ok {
		return true
	}
	details := map[string]any{"reason": "current_mismatch"}
	if p.User.PasswordHash != "" {
		locked, err := h.Users.RecordLoginFailure(r.Context(), p.User.ID, h.MaxFailures, h.LockFor)
		if err != nil {
			h.Log.Error("record password failure", "err", err)
		}
		if locked {
			details["locked_for"] = h.LockFor.String()
		}
	}
	h.recordAction(r, actor, action, "user", p.User.ID, audit.Failure, details)
	httpx.WriteError(w, r, http.StatusUnauthorized, "invalid_credentials", "the current password is wrong")
	return false
}

// changePassword lets a signed-in user replace their password: the step
// owed after an administrator set one (a partial session), or a change of
// their own (a full session). The current password is required either
// way. Afterwards the sign-in continues where it would have: a second
// factor to verify or enroll, or straight in.
func (h *Handler) changePassword(w http.ResponseWriter, r *http.Request) {
	p, _ := FromContext(r.Context())
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := httpx.DecodeJSONLimit(r, &req, signInBodyLimit); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	actor := ActorFor(r)
	// Only a fully signed-in user, or the session of an account without an
	// authenticator that owes the change, may change the password: a
	// password-only session of an account with an authenticator could
	// otherwise lock its owner out.
	if !p.Session.MFAVerified {
		enrolled, err := h.TOTP.Enrolled(r.Context(), p.User.ID)
		if err != nil {
			httpx.Internal(w, r, h.Log, err)
			return
		}
		if enrolled || !p.User.MustResetOnLogin {
			httpx.WriteError(w, r, http.StatusUnauthorized, "mfa_required", "second factor required")
			return
		}
	}
	if !h.currentPassword(w, r, p, req.CurrentPassword, actionSelfReset) {
		return
	}
	if req.NewPassword == req.CurrentPassword {
		httpx.WriteError(w, r, http.StatusBadRequest, "bad_request", "choose a password you have not used just now")
		return
	}
	if err := user.CheckPasswordPolicy(req.NewPassword); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	var (
		hash string
		err  error
	)
	if !h.hashing(w, r, func() { hash, err = user.HashPassword(req.NewPassword) }) {
		return
	}
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	if err := h.Users.SetPasswordHash(r.Context(), p.User.ID, hash, false); err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	// Every other session of the account ends, since whoever the change is
	// meant to shut out may hold one (M9); this one carries on. The
	// password has changed by now, so the revocation must not depend on the
	// client staying connected. A failure is logged and the change stands,
	// as after an administrator's reset.
	revokeCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), recordTimeout)
	others, err := h.Sessions.RevokeOthersForUser(revokeCtx, p.User.ID, p.Session.ID)
	cancel()
	if err != nil {
		h.Log.Error("revoke other sessions after password change", "err", err)
	}
	// The audit row says whether this was the forced first change or the
	// user's own; a bool, since only the fact matters.
	h.recordAction(r, actor, actionSelfReset, "user", p.User.ID, audit.Success, map[string]any{
		"session_id": p.Session.ID, "was_required": p.User.MustResetOnLogin, "other_sessions_revoked": others,
	})
	wasOwed := p.User.MustResetOnLogin
	p.User.MustResetOnLogin = false
	if p.Session.MFAVerified {
		// A change that was owed was the sign-in's last step (L13).
		if wasOwed && !h.rotate(w, r, p) {
			return
		}
		httpx.WriteJSON(w, http.StatusOK, loginResponse{Status: "ok", User: p.User, CSRFToken: h.Sessions.CSRFToken(p.Session.ID)})
		return
	}
	enrolled, err := h.TOTP.Enrolled(r.Context(), p.User.ID)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	require := h.RequireMFA != nil && h.RequireMFA()
	switch {
	case enrolled:
		httpx.WriteJSON(w, http.StatusOK, loginResponse{Status: "mfa_required", CSRFToken: h.Sessions.CSRFToken(p.Session.ID)})
	case require:
		httpx.WriteJSON(w, http.StatusOK, loginResponse{Status: "mfa_enrollment_required", CSRFToken: h.Sessions.CSRFToken(p.Session.ID)})
	default:
		// The change was the last step owed: the sign-in completes here.
		if err := h.Users.RecordLoginSuccess(r.Context(), p.User.ID); err != nil {
			httpx.Internal(w, r, h.Log, err)
			return
		}
		if err := h.Sessions.MarkMFAVerified(r.Context(), p.Session.ID); err != nil {
			httpx.Internal(w, r, h.Log, err)
			return
		}
		if !h.rotate(w, r, p) {
			return
		}
		httpx.WriteJSON(w, http.StatusOK, loginResponse{Status: "ok", User: p.User, CSRFToken: h.Sessions.CSRFToken(p.Session.ID)})
	}
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	p, _ := FromContext(r.Context())
	if err := h.Sessions.Revoke(r.Context(), p.Session.ID); err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	h.Sessions.ClearCookie(w)
	// A session from a single sign-on provider ends there too (ADR 0035):
	// the answer names the provider's sign-out page for the browser to
	// visit, which sends it back to the sign-in page.
	out := map[string]string{"status": "ok"}
	details := map[string]string{"session_id": p.Session.ID}
	if h.ProviderLogout != nil {
		if to := h.ProviderLogout(r, p.Session.ID); to != "" {
			out["redirect"] = to
			details["provider_sign_out"] = "true"
		}
	}
	h.record(r, ActorFor(r).Event(audit.UserLogout, "user", p.User.ID, audit.Success, details))
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	p, _ := FromContext(r.Context())
	enrolled, err := h.TOTP.Enrolled(r.Context(), p.User.ID)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	// A partial session gets only what the login page needs to resume the
	// owed step after a reload — the pending step and a CSRF token — never
	// the profile or session, which stay behind MFA and behind a password
	// change an administrator's reset made due.
	if !p.Session.MFAVerified || p.User.MustResetOnLogin {
		pending := "verify"
		switch {
		case p.Session.MFAVerified || !enrolled && p.User.MustResetOnLogin:
			pending = "password"
		case !enrolled:
			pending = "enroll"
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"pending":      pending,
			"mfa_enrolled": enrolled,
			"csrf_token":   h.Sessions.CSRFToken(p.Session.ID),
		})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"user":         p.User,
		"csrf_token":   h.Sessions.CSRFToken(p.Session.ID),
		"mfa_enrolled": enrolled,
		"pending":      nil,
		"session": map[string]any{
			"id": p.Session.ID, "created_at": p.Session.CreatedAt, "expires_at": p.Session.ExpiresAt,
		},
	})
}

type codeRequest struct {
	Code string `json:"code"`
}

// passwordChangeOwed refuses the second-factor steps while a password an
// administrator chose is still in place: the change comes first.
func (h *Handler) passwordChangeOwed(w http.ResponseWriter, r *http.Request, p *Principal) bool {
	if p.User.MustResetOnLogin {
		httpx.WriteError(w, r, http.StatusConflict, "password_change_required", "replace the password you were given first")
		return true
	}
	return false
}

// codeVerdict is what one second-factor check came to.
type codeVerdict int

const (
	codeRight   codeVerdict = iota // the code was right
	codeWrong                      // wrong, and counted against the account
	codeLocking                    // wrong, and counting it locked the account
	codeLocked                     // not compared: the account is locked
)

// checkCode compares one second-factor code for an account through check,
// and keeps the account's failure count, which wrong codes share with wrong
// passwords (M7): each wrong code counts, and MaxFailures of them lock the
// account for LockFor. wrong says which of check's errors mean a wrong
// code; any other is returned, with nothing counted. During a sign-in
// (signIn), a locked account's code is not compared at all, just as a
// locked account's password is not, and a right code completes the sign-in
// and clears the count.
//
// Checks for one account run one at a time, and each reads the lock state
// the one before it left: codes sent all at once, from several
// half-finished sign-ins, must not all be compared before the first of them
// is counted.
func (h *Handler) checkCode(ctx context.Context, userID string, signIn bool, check func() error, wrong func(error) bool) (codeVerdict, error) {
	defer h.codeChecks.lock(userID)()
	if signIn {
		u, err := h.Users.GetByID(ctx, userID)
		if err != nil {
			return 0, err
		}
		if u.IsLocked(time.Now()) {
			return codeLocked, nil
		}
	}
	if err := check(); err != nil {
		if !wrong(err) {
			return 0, err
		}
		locked, lerr := h.Users.RecordLoginFailure(ctx, userID, h.MaxFailures, h.LockFor)
		if lerr != nil {
			// The refusal stands; only this failure goes uncounted.
			h.Log.Error("record second-factor failure", "err", lerr)
		}
		if locked {
			return codeLocking, nil
		}
		return codeWrong, nil
	}
	if signIn {
		return codeRight, h.Users.RecordLoginSuccess(ctx, userID)
	}
	return codeRight, nil
}

// endSignIn ends a half-finished sign-in: its session is revoked and the
// cookie cleared. The caller answers sign_in_ended, which sends the console
// back to the password step (#205).
func (h *Handler) endSignIn(w http.ResponseWriter, r *http.Request, p *Principal) {
	h.mfaClear(p.Session.ID)
	_ = h.Sessions.Revoke(r.Context(), p.Session.ID)
	h.Sessions.ClearCookie(w)
}

func (h *Handler) totpVerify(w http.ResponseWriter, r *http.Request) {
	p, _ := FromContext(r.Context())
	if p.Session.MFAVerified {
		httpx.WriteJSON(w, http.StatusOK, loginResponse{Status: "ok", User: p.User, CSRFToken: h.Sessions.CSRFToken(p.Session.ID)})
		return
	}
	var req codeRequest
	if err := httpx.DecodeJSONLimit(r, &req, signInBodyLimit); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	var (
		usedRecovery bool
		refusal      error
	)
	verdict, err := h.checkCode(r.Context(), p.User.ID, true, func() error {
		usedRecovery, refusal = h.TOTP.Verify(r.Context(), p.User.ID, req.Code)
		return refusal
	}, func(err error) bool {
		return errors.Is(err, ErrTOTPBadCode) || errors.Is(err, ErrTOTPNotEnrolled)
	})
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	if verdict != codeRight {
		details := map[string]any{"reason": "bad_code", "session_id": p.Session.ID}
		if errors.Is(refusal, ErrTOTPReused) {
			// A right code seen once already: someone may have read it.
			details["reason"] = "code_reused"
		}
		// MFAAttempts wrong codes end the sign-in, and so does a locked
		// account: no code can complete it now.
		var ended bool
		switch verdict {
		case codeLocked:
			details["reason"], ended = "locked", true
		case codeLocking:
			details["locked_for"], ended = h.LockFor.String(), true
		default:
			ended = h.mfaFailure(p.Session.ID)
		}
		if ended {
			h.endSignIn(w, r, p)
			details["session_ended"] = true
		}
		h.record(r, ActorFor(r).Event(audit.UserMFAVerify, "user", p.User.ID, audit.Failure, details))
		if ended {
			// Its own code, so the console goes back to the password step
			// instead of offering a code box that can no longer work.
			httpx.WriteError(w, r, http.StatusUnauthorized, "sign_in_ended", "too many wrong codes; sign in again")
			return
		}
		httpx.WriteError(w, r, http.StatusUnauthorized, "invalid_code", "invalid code")
		return
	}
	h.mfaClear(p.Session.ID)
	if err := h.Sessions.MarkMFAProved(r.Context(), p.Session.ID); err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	if !p.Session.MFAVerified && !h.rotate(w, r, p) {
		return
	}
	method := "totp"
	if usedRecovery {
		method = "recovery_code"
	}
	h.record(r, ActorFor(r).Event(audit.UserLogin, "user", p.User.ID, audit.Success, map[string]string{"stage": "complete", "mfa": method, "session_id": p.Session.ID}))
	httpx.WriteJSON(w, http.StatusOK, loginResponse{Status: "ok", User: p.User, CSRFToken: h.Sessions.CSRFToken(p.Session.ID)})
}

func (h *Handler) totpEnroll(w http.ResponseWriter, r *http.Request) {
	p, _ := FromContext(r.Context())
	if h.passwordChangeOwed(w, r, p) {
		return
	}
	// From a full session an authenticator takes the password again (L14):
	// a stolen cookie must not enrol the thief's device and lock the owner
	// out of every later sign-in, nor gain the proof that guards the host
	// actions and the command line (ADR 0027, 0032). Enrolling as the step
	// a sign-in owes needs nothing more, the password was given a moment
	// ago. An account an identity provider signs in has no local password
	// to give, so for it the sign-in itself must be recent: within
	// recentSignIn of the session's start, or the person signs in again
	// through the provider first (review finding SEC-3).
	if p.Session.MFAVerified {
		// One already enrolled is refused below whatever is sent, so it is
		// not asked for a password first.
		enrolled, err := h.TOTP.Enrolled(r.Context(), p.User.ID)
		if err != nil {
			httpx.Internal(w, r, h.Log, err)
			return
		}
		if enrolled {
			httpx.WriteError(w, r, http.StatusConflict, "already_enrolled", "an authenticator is already enrolled")
			return
		}
		if p.User.PasswordHash == "" {
			if time.Since(p.Session.CreatedAt) > recentSignIn {
				h.record(r, ActorFor(r).Event(audit.UserMFAEnroll, "user", p.User.ID, audit.Failure, map[string]string{"reason": "reauth_required"}))
				httpx.WriteError(w, r, http.StatusUnauthorized, "reauth_required",
					"sign in again through your identity provider, then add the authenticator within five minutes")
				return
			}
		}
	}
	if p.Session.MFAVerified && p.User.PasswordHash != "" {
		var req struct {
			CurrentPassword string `json:"current_password"`
		}
		if r.ContentLength != 0 {
			if err := httpx.DecodeJSONLimit(r, &req, signInBodyLimit); err != nil {
				httpx.WriteError(w, r, http.StatusBadRequest, "bad_request", err.Error())
				return
			}
		}
		if req.CurrentPassword == "" {
			httpx.WriteError(w, r, http.StatusUnauthorized, "password_required", "enter your current password to add an authenticator")
			return
		}
		if !h.currentPassword(w, r, p, req.CurrentPassword, audit.UserMFAEnroll) {
			return
		}
	}
	enr, err := h.TOTP.Enroll(r.Context(), p.User.ID, p.User.Username)
	if err != nil {
		if errors.Is(err, ErrTOTPAlreadyEnrolled) {
			httpx.WriteError(w, r, http.StatusConflict, "already_enrolled", "an authenticator is already enrolled")
			return
		}
		httpx.Internal(w, r, h.Log, err)
		return
	}
	h.record(r, ActorFor(r).Event(audit.UserMFAEnroll, "user", p.User.ID, audit.Success, nil))
	httpx.WriteJSON(w, http.StatusOK, enr)
}

func (h *Handler) totpConfirm(w http.ResponseWriter, r *http.Request) {
	p, _ := FromContext(r.Context())
	if h.passwordChangeOwed(w, r, p) {
		return
	}
	var req codeRequest
	if err := httpx.DecodeJSONLimit(r, &req, signInBodyLimit); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	// Enrolling as the step a sign-in still owes completes that sign-in. A
	// full session that enrols is not signing in: the lock, which is about
	// new sign-ins, does not stop it (M6), though its wrong codes count.
	signIn := !p.Session.MFAVerified
	var codes []string
	verdict, err := h.checkCode(r.Context(), p.User.ID, signIn, func() (err error) {
		codes, err = h.TOTP.Confirm(r.Context(), p.User.ID, strings.TrimSpace(req.Code))
		return err
	}, func(err error) bool { return errors.Is(err, ErrTOTPBadCode) })
	switch {
	case errors.Is(err, ErrTOTPNotEnrolled):
		httpx.WriteError(w, r, http.StatusConflict, "not_enrolled", "start enrollment first")
		return
	case errors.Is(err, ErrTOTPAlreadyEnrolled):
		httpx.WriteError(w, r, http.StatusConflict, "already_enrolled", "an authenticator is already enrolled")
		return
	case err != nil:
		httpx.Internal(w, r, h.Log, err)
		return
	}
	if verdict != codeRight {
		details := map[string]any{"reason": "bad_code"}
		switch verdict {
		case codeLocked:
			details["reason"] = "locked"
		case codeLocking:
			details["locked_for"] = h.LockFor.String()
		}
		// A half-finished sign-in of a locked account ends, as at verify.
		if signIn && verdict != codeWrong {
			h.endSignIn(w, r, p)
			details["session_ended"] = true
			h.record(r, ActorFor(r).Event(audit.UserMFAConfirm, "user", p.User.ID, audit.Failure, details))
			httpx.WriteError(w, r, http.StatusUnauthorized, "sign_in_ended", "too many wrong codes; sign in again")
			return
		}
		h.record(r, ActorFor(r).Event(audit.UserMFAConfirm, "user", p.User.ID, audit.Failure, details))
		httpx.WriteError(w, r, http.StatusUnauthorized, "invalid_code", "invalid code")
		return
	}
	// A freshly confirmed authenticator counts as a verified second factor
	// for this session: the user just proved possession of it.
	if err := h.Sessions.MarkMFAProved(r.Context(), p.Session.ID); err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	if signIn && !h.rotate(w, r, p) {
		return
	}
	var details map[string]any
	if !signIn {
		// An authenticator added to a full session shuts the account's other
		// sessions, as a password change does (M9): whoever got in first,
		// on a cookie that is not this one, does not keep a seat.
		revokeCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), recordTimeout)
		others, err := h.Sessions.RevokeOthersForUser(revokeCtx, p.User.ID, p.Session.ID)
		cancel()
		if err != nil {
			h.Log.Error("revoke other sessions after enrolment", "err", err)
		}
		details = map[string]any{"other_sessions_revoked": others}
	}
	h.record(r, ActorFor(r).Event(audit.UserMFAConfirm, "user", p.User.ID, audit.Success, details))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes, "status": "ok", "csrf_token": h.Sessions.CSRFToken(p.Session.ID)})
}

// ---- helpers

func (h *Handler) record(r *http.Request, e audit.Event) {
	Recorder{Audit: h.Audit, Log: h.Log}.Record(r, e)
}

// rotate gives the session a new token as its sign-in completes and sends
// it as the cookie (L13). When it returns false it has answered.
func (h *Handler) rotate(w http.ResponseWriter, r *http.Request, p *Principal) bool {
	token, err := h.Sessions.Rotate(r.Context(), p.Session.ID)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return false
	}
	h.Sessions.SetCookie(w, token)
	return true
}

// signInBodyLimit caps the bodies of these endpoints, most of which answer
// callers who have not signed in yet: a name, a password or a code, no more.
const signInBodyLimit = 64 << 10

// recentSignIn is how long after its start a session counts as freshly
// signed in, for an account with no local password to give again before
// adding an authenticator: the same window the host actions give a step-up
// proof (ADR 0032).
const recentSignIn = 5 * time.Minute

// stepUp proves the authenticator again on a full session. It records the
// proof's time on the session, which the host-action handlers read (ADR
// 0032); nothing else about the session changes. Attempts are limited per
// session so a stolen cookie cannot grind codes, and every outcome is
// audited as a second-factor verification with the purpose named.
func (h *Handler) stepUp(w http.ResponseWriter, r *http.Request) {
	p, _ := FromContext(r.Context())
	actor := audit.Actor{UserID: p.User.ID, IP: ClientIP(r)}
	now := time.Now()
	if h.stepUpClosed(p.Session.ID, now) {
		httpx.WriteError(w, r, http.StatusTooManyRequests, "step_up_closed", "too many wrong codes; try again later")
		return
	}
	if ok, first := h.stepUpLimiter.Take(limiterKey(p.Session.ID)); !ok {
		if first {
			h.record(r, actor.Event(audit.UserMFAVerify, "user", p.User.ID, audit.Failure, map[string]string{"purpose": "step_up", "reason": "rate_limited"}))
		}
		httpx.WriteError(w, r, http.StatusTooManyRequests, "rate_limited", "too many attempts; try again later")
		return
	}
	var req codeRequest
	if err := httpx.DecodeJSONLimit(r, &req, signInBodyLimit); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	recovery, err := h.TOTP.Verify(r.Context(), p.User.ID, req.Code)
	switch {
	case errors.Is(err, ErrTOTPNotEnrolled):
		httpx.WriteError(w, r, http.StatusConflict, "mfa_not_enrolled", "enrol an authenticator first; this action asks for a code from it")
		return
	case errors.Is(err, ErrTOTPBadCode):
		reason := "wrong code"
		if errors.Is(err, ErrTOTPReused) {
			reason = "code already used"
		}
		closed := h.stepUpFailed(p.Session.ID, now)
		h.record(r, actor.Event(audit.UserMFAVerify, "user", p.User.ID, audit.Failure, map[string]any{"purpose": "step_up", "reason": reason, "closed": closed}))
		if closed {
			httpx.WriteError(w, r, http.StatusTooManyRequests, "step_up_closed", "too many wrong codes; try again later")
			return
		}
		httpx.WriteError(w, r, http.StatusUnprocessableEntity, "bad_code", "that code is not right")
		return
	case err != nil:
		httpx.Internal(w, r, h.Log, err)
		return
	}
	if err := h.Sessions.MarkMFAProved(r.Context(), p.Session.ID); err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	h.stepUpSucceeded(p.Session.ID)
	h.record(r, actor.Event(audit.UserMFAVerify, "user", p.User.ID, audit.Success, map[string]any{"purpose": "step_up", "recovery_code_used": recovery}))
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"proved": true})
}
