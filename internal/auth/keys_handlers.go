// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/httpx"
)

// Security keys and passkeys as a second factor (ADR 0028). A key proves
// what a code proves, at the same three places: the sign-in's second step
// (keyVerify), a step-up (stepUp, with a credential), and the console
// command line's unlock (the cli package). Each answer finishes a challenge
// keyBegin started for the same session and purpose.

// registerKeyRoutes mounts the key routes beside the code routes.
func (h *Handler) registerKeyRoutes(mux *http.ServeMux) {
	// Begin admits a partial session: a sign-in's second step, and the
	// enrolment a sign-in owes, start here.
	mux.Handle("POST /api/v1/auth/mfa/webauthn/begin", RequirePartialAuth(http.HandlerFunc(h.keyBegin)))
	mux.Handle("POST /api/v1/auth/mfa/webauthn/verify", RequirePartialAuth(http.HandlerFunc(h.keyVerify)))
	mux.Handle("POST /api/v1/auth/mfa/webauthn/register", RequirePartialAuth(http.HandlerFunc(h.keyRegister)))
	mux.Handle("GET /api/v1/auth/mfa/webauthn/keys", RequireAuth(http.HandlerFunc(h.keysList)))
	mux.Handle("PATCH /api/v1/auth/mfa/webauthn/keys/{id}", RequireAuth(http.HandlerFunc(h.keyRename)))
	mux.Handle("DELETE /api/v1/auth/mfa/webauthn/keys/{id}", RequireAuth(http.HandlerFunc(h.keyRemove)))
	mux.Handle("POST /api/v1/auth/mfa/recovery-codes", RequireAuth(http.HandlerFunc(h.recoveryCodes)))
}

// keyBegin starts a ceremony: registering a key, or asking the account's
// keys for a sign-in, a step-up or the command line. It answers the options
// the browser passes to navigator.credentials.
func (h *Handler) keyBegin(w http.ResponseWriter, r *http.Request) {
	p, _ := FromContext(r.Context())
	var req struct {
		Purpose         string `json:"purpose"`
		CurrentPassword string `json:"current_password"`
	}
	if err := httpx.DecodeJSONLimit(r, &req, signInBodyLimit); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	var (
		options any
		err     error
	)
	switch req.Purpose {
	case PurposeSignIn:
		if p.Session.MFAVerified {
			httpx.WriteError(w, r, http.StatusConflict, "already_signed_in", "this sign-in is complete")
			return
		}
		options, err = h.Factors.Keys.BeginAssertion(r.Context(), p.Session.ID, p.User.ID, PurposeSignIn)
	case PurposeStepUp, PurposeCLI:
		if !p.Session.MFAVerified {
			httpx.WriteError(w, r, http.StatusForbidden, "sign_in_incomplete", "finish signing in first")
			return
		}
		options, err = h.Factors.Keys.BeginAssertion(r.Context(), p.Session.ID, p.User.ID, req.Purpose)
	case PurposeRegister:
		if !h.mayAddKey(w, r, p, req.CurrentPassword, true) {
			return
		}
		options, err = h.Factors.Keys.BeginRegistration(r.Context(), p.Session.ID, p.User)
	default:
		httpx.WriteError(w, r, http.StatusBadRequest, "bad_request", "purpose is register, sign_in, step_up or cli")
		return
	}
	switch {
	case errors.Is(err, ErrKeysOff), errors.Is(err, ErrNoKeys):
		keyNotAsked(w, r, err, h.Factors.Keys.Off())
		return
	case errors.Is(err, ErrTooManyKeys):
		httpx.WriteError(w, r, http.StatusConflict, "too_many_keys", "ten keys at most; remove one first")
		return
	case err != nil:
		httpx.Internal(w, r, h.Log, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, options)
}

// mayAddKey says whether the session may register a key now, and answers
// when it may not. The rules are an authenticator app's (totpEnroll), so a
// stolen session cannot add a thief's key: as the enrolment a sign-in owes,
// only while the account has no second factor yet; from a full session
// with no factor, after the password again (or a recent sign-in, for an
// account a provider signs in); and beside a factor the account has,
// after a fresh proof of it (step-up). begin says whether this is the
// ceremony's start, where the password is given.
func (h *Handler) mayAddKey(w http.ResponseWriter, r *http.Request, p *Principal, password string, begin bool) bool {
	if h.passwordChangeOwed(w, r, p) {
		return false
	}
	enrolled, err := h.Factors.Enrolled(r.Context(), p.User.ID)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return false
	}
	switch {
	case !p.Session.MFAVerified && enrolled:
		httpx.WriteError(w, r, http.StatusForbidden, "verify_first", "prove your second factor first")
		return false
	case !p.Session.MFAVerified:
		return true
	case enrolled:
		if !p.StepUpFresh() {
			httpx.WriteError(w, r, http.StatusForbidden, "step_up_required", "prove your second factor first: adding a key asks for a recent one")
			return false
		}
		return true
	case !begin:
		// The password was given when the ceremony began, which is bound
		// to this session.
		return true
	case p.User.PasswordHash == "":
		if time.Since(p.Session.CreatedAt) > recentSignIn {
			h.record(r, ActorFor(r).Event(audit.UserKeyRegister, "user", p.User.ID, audit.Failure, map[string]string{"reason": "reauth_required"}))
			httpx.WriteError(w, r, http.StatusUnauthorized, "reauth_required",
				"sign in again through your identity provider, then add the key within five minutes")
			return false
		}
		return true
	case password == "":
		httpx.WriteError(w, r, http.StatusUnauthorized, "password_required", "enter your current password to add a key")
		return false
	default:
		return h.currentPassword(w, r, p, password, audit.UserKeyRegister)
	}
}

// keyVerify is a sign-in's second step answered with a key: the partial
// session becomes full, as a right code makes it. A key that is refused
// counts as a wrong code, against the same limits.
func (h *Handler) keyVerify(w http.ResponseWriter, r *http.Request) {
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
	var refusal error
	verdict, err := h.checkCode(r.Context(), p.User.ID, true, func() error {
		_, refusal = h.Factors.Keys.FinishAssertion(r.Context(), p.Session.ID, p.User.ID, PurposeSignIn, req.Credential)
		return refusal
	}, func(err error) bool { return errors.Is(err, ErrKeyBad) })
	switch {
	case errors.Is(err, ErrNoCeremony), errors.Is(err, ErrKeysOff), errors.Is(err, ErrNoKeys):
		keyNotAsked(w, r, err, h.Factors.Keys.Off())
		return
	case err != nil:
		httpx.Internal(w, r, h.Log, err)
		return
	}
	if verdict != codeRight {
		reason := "bad_key"
		if errors.Is(refusal, ErrKeyCloned) {
			// A copy of the key may exist.
			reason = "key_counter_went_back"
		}
		h.secondFactorRefused(w, r, p, verdict, reason)
		return
	}
	h.secondFactorPassed(w, r, p, "webauthn")
}

// keyRegister finishes registering a key. As the enrolment a sign-in owes,
// it completes the sign-in; beside a full session it signs the account's
// other sessions out, as a new authenticator app does (M9). A first second
// factor brings the recovery codes, shown once.
func (h *Handler) keyRegister(w http.ResponseWriter, r *http.Request) {
	p, _ := FromContext(r.Context())
	var req struct {
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := httpx.DecodeJSONLimit(r, &req, signInBodyLimit); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if !h.mayAddKey(w, r, p, "", false) {
		return
	}
	signIn := !p.Session.MFAVerified
	if signIn && p.User.IsLocked(time.Now()) {
		// A half-finished sign-in of a locked account ends, as at a code.
		h.endSignIn(w, r, p)
		h.record(r, ActorFor(r).Event(audit.UserKeyRegister, "user", p.User.ID, audit.Failure, map[string]any{"reason": "locked", "session_ended": true}))
		httpx.WriteError(w, r, http.StatusUnauthorized, "sign_in_ended", "too many wrong codes; sign in again")
		return
	}
	firstFactor, err := h.Factors.Enrolled(r.Context(), p.User.ID)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	firstFactor = !firstFactor
	key, codes, err := h.Factors.AddKey(r.Context(), p.Session.ID, p.User, req.Name, req.Credential)
	switch {
	case errors.Is(err, ErrKeyName):
		httpx.WriteError(w, r, http.StatusBadRequest, "bad_name", "a key's name is 1 to 64 characters")
		return
	case errors.Is(err, ErrTooManyKeys):
		httpx.WriteError(w, r, http.StatusConflict, "too_many_keys", "ten keys at most; remove one first")
		return
	case errors.Is(err, ErrKeyTaken):
		httpx.WriteError(w, r, http.StatusConflict, "key_taken", "this key is registered already")
		return
	case errors.Is(err, ErrNoCeremony), errors.Is(err, ErrKeysOff):
		keyNotAsked(w, r, err, h.Factors.Keys.Off())
		return
	case errors.Is(err, ErrKeyBad):
		h.record(r, ActorFor(r).Event(audit.UserKeyRegister, "user", p.User.ID, audit.Failure, map[string]string{"reason": "key not accepted"}))
		httpx.WriteError(w, r, http.StatusUnprocessableEntity, "bad_key", "that key was not accepted")
		return
	case err != nil:
		httpx.Internal(w, r, h.Log, err)
		return
	}
	details := map[string]any{"key_id": key.ID, "name": key.Name, "synced": key.Synced, "first_factor": firstFactor}
	if signIn || firstFactor {
		// The person just used the key, which proves it for this session.
		if err := h.Sessions.MarkMFAProved(r.Context(), p.Session.ID); err != nil {
			httpx.Internal(w, r, h.Log, err)
			return
		}
	}
	if signIn {
		if err := h.Users.RecordLoginSuccess(r.Context(), p.User.ID); err != nil {
			httpx.Internal(w, r, h.Log, err)
			return
		}
		if !h.rotate(w, r, p) {
			return
		}
	} else {
		revokeCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), recordTimeout)
		others, err := h.Sessions.RevokeOthersForUser(revokeCtx, p.User.ID, p.Session.ID)
		cancel()
		if err != nil {
			h.Log.Error("revoke other sessions after a key was added", "err", err)
		}
		details["other_sessions_revoked"] = others
	}
	h.record(r, ActorFor(r).Event(audit.UserKeyRegister, "user", p.User.ID, audit.Success, details))
	if signIn {
		h.record(r, ActorFor(r).Event(audit.UserLogin, "user", p.User.ID, audit.Success, map[string]string{"stage": "complete", "mfa": "webauthn", "session_id": p.Session.ID}))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"key": key, "recovery_codes": codes, "status": "ok", "csrf_token": h.Sessions.CSRFToken(p.Session.ID)})
}

// keysList is the person's own keys, and why keys are off here, if they are.
func (h *Handler) keysList(w http.ResponseWriter, r *http.Request) {
	p, _ := FromContext(r.Context())
	keys, err := h.Factors.Keys.List(r.Context(), p.User.ID)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	app, err := h.Factors.TOTP.Enrolled(r.Context(), p.User.ID)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": keys, "app": app, "keys_off": h.Factors.Keys.Off()})
}

// keyRename names one of the person's keys again.
func (h *Handler) keyRename(w http.ResponseWriter, r *http.Request) {
	p, _ := FromContext(r.Context())
	var req struct {
		Name string `json:"name"`
	}
	if err := httpx.DecodeJSONLimit(r, &req, signInBodyLimit); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	id := r.PathValue("id")
	switch err := h.Factors.Keys.Rename(r.Context(), p.User.ID, id, req.Name); {
	case errors.Is(err, ErrKeyName):
		httpx.WriteError(w, r, http.StatusBadRequest, "bad_name", "a key's name is 1 to 64 characters")
		return
	case errors.Is(err, ErrKeyNotFound):
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "no such key")
		return
	case err != nil:
		httpx.Internal(w, r, h.Log, err)
		return
	}
	h.record(r, ActorFor(r).Event(audit.UserKeyRename, "user", p.User.ID, audit.Success, map[string]string{"key_id": id}))
	w.WriteHeader(http.StatusNoContent)
}

// keyRemove removes one of the person's keys, after a fresh proof of a
// second factor. The last factor of an account that must have one stays.
func (h *Handler) keyRemove(w http.ResponseWriter, r *http.Request) {
	p, _ := FromContext(r.Context())
	if !p.StepUpFresh() {
		httpx.WriteError(w, r, http.StatusForbidden, "step_up_required", "prove your second factor first: removing a key asks for a recent one")
		return
	}
	id := r.PathValue("id")
	mustKeep := h.RequireMFA != nil && h.RequireMFA()
	name, err := h.Factors.RemoveKey(r.Context(), p.User.ID, id, mustKeep)
	switch {
	case errors.Is(err, ErrKeyNotFound):
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "no such key")
		return
	case errors.Is(err, ErrLastFactor):
		httpx.WriteError(w, r, http.StatusConflict, "last_factor", "this is your only second factor")
		return
	case err != nil:
		httpx.Internal(w, r, h.Log, err)
		return
	}
	h.record(r, ActorFor(r).Event(audit.UserKeyRemove, "user", p.User.ID, audit.Success, map[string]string{"key_id": id, "name": name}))
	w.WriteHeader(http.StatusNoContent)
}

// recoveryCodes replaces the person's recovery codes, after a fresh proof
// of a second factor; the old codes stop working at once.
func (h *Handler) recoveryCodes(w http.ResponseWriter, r *http.Request) {
	p, _ := FromContext(r.Context())
	if !p.StepUpFresh() {
		httpx.WriteError(w, r, http.StatusForbidden, "step_up_required", "prove your second factor first: new codes ask for a recent one")
		return
	}
	codes, err := h.Factors.NewRecoveryCodes(r.Context(), p.User.ID)
	switch {
	case errors.Is(err, ErrTOTPNotEnrolled):
		httpx.WriteError(w, r, http.StatusConflict, "mfa_not_enrolled", "add a second factor first")
		return
	case err != nil:
		httpx.Internal(w, r, h.Log, err)
		return
	}
	h.record(r, ActorFor(r).Event(audit.UserMFARecoveryCodes, "user", p.User.ID, audit.Success, nil))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}
