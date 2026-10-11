// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"hash/fnv"
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

	// MaxFailures wrong passwords and wrong second-factor codes, counted
	// together until a sign-in completes, lock the account against new
	// sign-ins for LockFor.
	MaxFailures int
	LockFor     time.Duration
	// MFAAttempts wrong codes end the pending session.
	MFAAttempts int
	// RequireMFA keeps a session partial until an authenticator is enrolled.
	// It is read at every sign-in so the runtime setting applies live; nil
	// means not required.
	RequireMFA func() bool
	// ExternalLogin, when set, authenticates users against LDAP providers
	// after local password authentication does not apply.
	ExternalLogin ExternalAuthenticator

	loginLimiter *ipLimiter
	mfaMu        sync.Mutex
	mfaAttempts  map[string]int
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
		loginLimiter: newIPLimiter(20, 10),
		mfaAttempts:  map[string]int{},
	}
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
				_ = h.Users.SetPasswordHash(r.Context(), u.ID, nh, u.MustResetOnLogin)
			}
		}
		h.completeLogin(w, r, u, actor)
		return
	}

	// External path: the local user has no password (provisioned from an IdP),
	// so try LDAP providers with the supplied credentials.
	if h.ExternalLogin != nil {
		eu, eerr := h.ExternalLogin.Login(r.Context(), req.Username, req.Password, ip)
		if eerr == nil {
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
			h.serverError(w, r, err)
			return
		}
	}
	token, sess, err := h.Sessions.Create(r.Context(), u.ID, ip, r.UserAgent(), complete)
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	h.Sessions.SetCookie(w, token)
	// An account with an authenticator proves it before anything else, the
	// change included: whoever holds only the reset password must not get
	// to choose the next one. An account without one changes first, then
	// enrols.
	if !enrolled && u.MustResetOnLogin {
		h.record(r, actor.Event("user.login", "user", u.ID, audit.Success, map[string]string{"stage": "password", "next": "password_change", "session_id": sess.ID}))
		WriteJSON(w, http.StatusOK, loginResponse{Status: "password_change_required", CSRFToken: h.Sessions.CSRFToken(sess.ID)})
		return
	}
	if !enrolled && require {
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

// actionSelfReset is the audit action for a user replacing their own
// password.
const actionSelfReset = "user.password.change"

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
	if err := decodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "bad_request", err.Error())
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
			h.serverError(w, r, err)
			return
		}
		if enrolled || !p.User.MustResetOnLogin {
			WriteError(w, http.StatusUnauthorized, "mfa_required", "second factor required")
			return
		}
	}
	if p.User.PasswordHash == "" || !user.VerifyPassword(p.User.PasswordHash, req.CurrentPassword) {
		h.recordAction(r, actor, actionSelfReset, "user", p.User.ID, audit.Failure, map[string]string{"reason": "current_mismatch"})
		WriteError(w, http.StatusUnauthorized, "invalid_credentials", "the current password is wrong")
		return
	}
	if req.NewPassword == req.CurrentPassword {
		WriteError(w, http.StatusBadRequest, "bad_request", "choose a password you have not used just now")
		return
	}
	if err := user.CheckPasswordPolicy(req.NewPassword); err != nil {
		WriteError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	hash, err := user.HashPassword(req.NewPassword)
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	if err := h.Users.SetPasswordHash(r.Context(), p.User.ID, hash, false); err != nil {
		h.serverError(w, r, err)
		return
	}
	// The audit row says whether this was the forced first change or the
	// user's own; a bool, since only the fact matters.
	h.recordAction(r, actor, actionSelfReset, "user", p.User.ID, audit.Success, map[string]any{"session_id": p.Session.ID, "was_required": p.User.MustResetOnLogin})
	p.User.MustResetOnLogin = false
	if p.Session.MFAVerified {
		WriteJSON(w, http.StatusOK, loginResponse{Status: "ok", User: p.User, CSRFToken: h.Sessions.CSRFToken(p.Session.ID)})
		return
	}
	enrolled, err := h.TOTP.Enrolled(r.Context(), p.User.ID)
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	require := h.RequireMFA != nil && h.RequireMFA()
	switch {
	case enrolled:
		WriteJSON(w, http.StatusOK, loginResponse{Status: "mfa_required", CSRFToken: h.Sessions.CSRFToken(p.Session.ID)})
	case require:
		WriteJSON(w, http.StatusOK, loginResponse{Status: "mfa_enrollment_required", CSRFToken: h.Sessions.CSRFToken(p.Session.ID)})
	default:
		// The change was the last step owed: the sign-in completes here.
		if err := h.Users.RecordLoginSuccess(r.Context(), p.User.ID); err != nil {
			h.serverError(w, r, err)
			return
		}
		if err := h.Sessions.MarkMFAVerified(r.Context(), p.Session.ID); err != nil {
			h.serverError(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, loginResponse{Status: "ok", User: p.User, CSRFToken: h.Sessions.CSRFToken(p.Session.ID)})
	}
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	p, _ := FromContext(r.Context())
	if err := h.Sessions.Revoke(r.Context(), p.Session.ID); err != nil {
		h.serverError(w, r, err)
		return
	}
	h.Sessions.ClearCookie(w)
	h.record(r, ActorFor(r).Event("user.logout", "user", p.User.ID, audit.Success, map[string]string{"session_id": p.Session.ID}))
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	p, _ := FromContext(r.Context())
	enrolled, err := h.TOTP.Enrolled(r.Context(), p.User.ID)
	if err != nil {
		h.serverError(w, r, err)
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
		WriteJSON(w, http.StatusOK, map[string]any{
			"pending":      pending,
			"mfa_enrolled": enrolled,
			"csrf_token":   h.Sessions.CSRFToken(p.Session.ID),
		})
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
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
func (h *Handler) passwordChangeOwed(w http.ResponseWriter, p *Principal) bool {
	if p.User.MustResetOnLogin {
		WriteError(w, http.StatusConflict, "password_change_required", "replace the password you were given first")
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
		WriteJSON(w, http.StatusOK, loginResponse{Status: "ok", User: p.User, CSRFToken: h.Sessions.CSRFToken(p.Session.ID)})
		return
	}
	var req codeRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "bad_request", err.Error())
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
		h.serverError(w, r, err)
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
		h.record(r, ActorFor(r).Event("user.mfa.verify", "user", p.User.ID, audit.Failure, details))
		if ended {
			// Its own code, so the console goes back to the password step
			// instead of offering a code box that can no longer work.
			WriteError(w, http.StatusUnauthorized, "sign_in_ended", "too many wrong codes; sign in again")
			return
		}
		WriteError(w, http.StatusUnauthorized, "invalid_code", "invalid code")
		return
	}
	h.mfaClear(p.Session.ID)
	if err := h.Sessions.MarkMFAProved(r.Context(), p.Session.ID); err != nil {
		h.serverError(w, r, err)
		return
	}
	method := "totp"
	if usedRecovery {
		method = "recovery_code"
	}
	h.record(r, ActorFor(r).Event("user.login", "user", p.User.ID, audit.Success, map[string]string{"stage": "complete", "mfa": method, "session_id": p.Session.ID}))
	WriteJSON(w, http.StatusOK, loginResponse{Status: "ok", User: p.User, CSRFToken: h.Sessions.CSRFToken(p.Session.ID)})
}

func (h *Handler) totpEnroll(w http.ResponseWriter, r *http.Request) {
	p, _ := FromContext(r.Context())
	if h.passwordChangeOwed(w, p) {
		return
	}
	enr, err := h.TOTP.Enroll(r.Context(), p.User.ID, p.User.Username)
	if err != nil {
		if errors.Is(err, ErrTOTPAlreadyEnrolled) {
			WriteError(w, http.StatusConflict, "already_enrolled", "an authenticator is already enrolled")
			return
		}
		h.serverError(w, r, err)
		return
	}
	h.record(r, ActorFor(r).Event("user.mfa.enroll", "user", p.User.ID, audit.Success, nil))
	WriteJSON(w, http.StatusOK, enr)
}

func (h *Handler) totpConfirm(w http.ResponseWriter, r *http.Request) {
	p, _ := FromContext(r.Context())
	if h.passwordChangeOwed(w, p) {
		return
	}
	var req codeRequest
	if err := decodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, "bad_request", err.Error())
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
		WriteError(w, http.StatusConflict, "not_enrolled", "start enrollment first")
		return
	case errors.Is(err, ErrTOTPAlreadyEnrolled):
		WriteError(w, http.StatusConflict, "already_enrolled", "an authenticator is already enrolled")
		return
	case err != nil:
		h.serverError(w, r, err)
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
			h.record(r, ActorFor(r).Event("user.mfa.confirm", "user", p.User.ID, audit.Failure, details))
			WriteError(w, http.StatusUnauthorized, "sign_in_ended", "too many wrong codes; sign in again")
			return
		}
		h.record(r, ActorFor(r).Event("user.mfa.confirm", "user", p.User.ID, audit.Failure, details))
		WriteError(w, http.StatusUnauthorized, "invalid_code", "invalid code")
		return
	}
	// A freshly confirmed authenticator counts as a verified second factor
	// for this session: the user just proved possession of it.
	if err := h.Sessions.MarkMFAProved(r.Context(), p.Session.ID); err != nil {
		h.serverError(w, r, err)
		return
	}
	h.record(r, ActorFor(r).Event("user.mfa.confirm", "user", p.User.ID, audit.Success, nil))
	WriteJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes, "status": "ok", "csrf_token": h.Sessions.CSRFToken(p.Session.ID)})
}

// ---- helpers

func (h *Handler) record(r *http.Request, e audit.Event) {
	Recorder{Audit: h.Audit, Log: h.Log}.Record(r, e)
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
