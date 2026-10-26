// SPDX-License-Identifier: Apache-2.0

package apps

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/protocol"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/user"
)

// enter answers the hand-off: the state the browser carries must be the one
// this host gave it, the code must have been issued for this application,
// this state and this client, and the policies are asked once more, as a
// ticket is asked again when redeemed. Then the session opens: a row like
// any other session's, the cookie for this host, and the registry entry that
// lets an administrator or a policy change end it.
func (h *Handler) enter(w http.ResponseWriter, r *http.Request, label string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	if h.draining() {
		h.page(w, http.StatusServiceUnavailable, "Restarting", restartingMsg, true)
		return
	}
	q := r.URL.Query()
	state := q.Get("state")
	sc, err := r.Cookie(stateCookieName)
	clearCookie(w, stateCookieName)
	if err != nil || !validState(state) || subtle.ConstantTimeCompare([]byte(sc.Value), []byte(state)) != 1 {
		h.refused(w, r, label, "state")
		return
	}
	g, ok := h.store().redeem(q.Get("code"), label, state, auth.ClientIP(r))
	if !ok {
		h.refused(w, r, label, "code")
		return
	}
	actor := audit.Actor{UserID: g.UserID, IP: auth.ClientIP(r)}
	refuse := func(reason string, status int, title, body string) {
		h.record(r, actor.Event(audit.SessionConnect, "target", g.TargetID, audit.Failure, map[string]any{"protocol": protocol.HTTP, "reason": reason, "label": label}))
		h.page(w, status, title, body, true)
	}
	t, err := h.Targets.GetByLabel(ctx, label)
	if err != nil || t.ID != g.TargetID || !t.IsApplication() || t.Status != target.StatusActive {
		refuse("target_unavailable", http.StatusConflict, "Application unavailable", "This application is not available right now. Open it again from Zanskar.")
		return
	}
	d, code, msg, err := h.Gate.Admit(ctx, g.UserID, policy.TargetRef{ID: t.ID, Tags: t.Tags}, protocol.HTTP, time.Now())
	if err != nil {
		h.log().Error("application admission", "err", err)
		h.page(w, http.StatusInternalServerError, "Try again", "The gateway could not decide your access; try again in a moment.", true)
		return
	}
	if code != "" {
		refuse(code, http.StatusForbidden, "Access refused", msg+".")
		return
	}
	// The upstream's address is checked before the session exists: a name
	// that now resolves somewhere the gateway must never connect to refuses
	// the session, not its first request.
	if _, err := h.Prober.Resolve(ctx, t.Address); err != nil {
		if errors.Is(err, target.ErrAddressForbidden) {
			refuse("address_forbidden", http.StatusBadGateway, "Application unavailable", "The gateway does not connect to this application's address; an administrator must correct it.")
			return
		}
		h.log().Warn("application address lookup failed", "app", logSafe(label), "err", err)
		h.page(w, http.StatusBadGateway, "Application unavailable", "The application's address could not be looked up. Try again in a moment.", true)
		return
	}
	s := &session.Session{UserID: g.UserID, PolicyID: d.Policy.ID, TargetID: t.ID, Protocol: protocol.HTTP, ClientIP: auth.ClientIP(r), UserAgent: r.UserAgent()}
	if err := h.Sessions.Start(ctx, s); err != nil {
		h.log().Error("start application session", "err", err)
		h.page(w, http.StatusInternalServerError, "Try again", "The gateway could not open the session; try again in a moment.", true)
		return
	}
	tok, err := randomToken()
	if err != nil {
		h.page(w, http.StatusInternalServerError, "Try again", "The gateway could not open the session; try again in a moment.", true)
		return
	}
	row := &Row{TokenHash: hashToken(tok), SessionID: s.ID, AuthSessionID: g.AuthSessionID, UserID: g.UserID, TargetID: t.ID, Idle: d.IdleTimeout}
	if d.MaxSession > 0 {
		exp := time.Now().Add(d.MaxSession).UTC()
		row.ExpiresAt = &exp
	}
	if err := h.Repo.Create(ctx, row); err != nil {
		h.log().Error("store application session", "err", err)
		_ = h.Sessions.End(ctx, s.ID, session.EndError)
		h.page(w, http.StatusInternalServerError, "Try again", "The gateway could not open the session; try again in a moment.", true)
		return
	}
	h.record(r, actor.Event(audit.AppSessionStart, "access_session", s.ID, audit.Success, map[string]any{"target_id": t.ID, "protocol": protocol.HTTP, "policy_id": d.Policy.ID, "label": label}))
	h.track(s.ID, g.UserID, t.ID, d.Policy.ID, auth.ClientIP(r))
	setCookie(w, cookieName, tok, cookieTTL)
	w.Header().Set("Cache-Control", "no-store")
	// Where to land came with the code, decided by the console (safePath):
	// a path on this host, never anything this request said.
	http.Redirect(w, r, g.Next, http.StatusSeeOther)
}

// refused answers a hand-off that does not check out. The log says which
// check failed; the person is only told to start again.
func (h *Handler) refused(w http.ResponseWriter, r *http.Request, label, what string) {
	h.log().Info("application hand-off refused", "request_id", requestID(r), "app", logSafe(label), "check", what, "remote", auth.ClientIP(r))
	h.page(w, http.StatusForbidden, "Link expired", "The link to this application has expired or was not meant for this browser. Open it again from Zanskar.", true)
}

// signout ends the browser's session on this application and clears its
// cookie. The console's own sign-in is untouched.
func (h *Handler) signout(w http.ResponseWriter, r *http.Request, label string) {
	if c, err := r.Cookie(cookieName); err == nil && c.Value != "" {
		if row, err := h.Repo.Lookup(r.Context(), hashToken(c.Value)); err == nil && row.EndedAt == nil && row.Target.Label == label {
			h.end(row, session.EndUserExit)
		}
	}
	clearCookie(w, cookieName)
	h.page(w, http.StatusOK, "Signed out", "You left this application. Open it again from Zanskar when you need it.", true)
}

// verdict says why the session must end now, as an access_sessions end
// reason, or "" while it may go on. The same rules serve every request and
// the sweeper: the application must still be served under this label, the
// account must stand, the sign-in the session came from must be alive, and
// the admitting policy's maximum and idle limits must hold.
func (h *Handler) verdict(row *Row, label string, now time.Time) string {
	switch {
	case row.Target.Deleted || !row.Target.Active || row.Target.Label != label:
		return session.EndTargetLost
	case row.UserStatus == string(user.StatusDisabled) || row.UserStatus == string(user.StatusLocked):
		return session.EndAdminTerminated
	case row.AuthRevoked || now.After(row.AuthExpiresAt) || now.Sub(row.AuthLastSeenAt) > h.authIdle():
		return session.EndUserExit
	case row.ExpiresAt != nil && now.After(*row.ExpiresAt):
		return session.EndMaxDuration
	case row.Idle > 0 && now.Sub(row.LastSeenAt) > row.Idle:
		return session.EndIdleTimeout
	}
	return ""
}

func (h *Handler) authIdle() time.Duration {
	if h.Auth != nil && h.Auth.IdleTTL > 0 {
		return h.Auth.IdleTTL
	}
	return 60 * time.Minute
}

// touch records activity once a minute at most, on the application session
// and on the sign-in behind it, so neither goes idle under a person at work.
func (h *Handler) touch(ctx context.Context, row *Row, now time.Time) {
	if now.Sub(row.LastSeenAt) < time.Minute {
		return
	}
	if err := h.Repo.Touch(ctx, row.TokenHash, now); err != nil {
		h.log().Error("touch application session", "err", err)
	}
	if h.Auth != nil && now.Sub(row.AuthLastSeenAt) > time.Minute {
		if err := h.Auth.Touch(ctx, row.AuthSessionID); err != nil {
			h.log().Error("touch sign-in", "err", err)
		}
	}
}

// tracked is a session's registry entry: cancel stops the goroutine waiting
// on it when the proxy ends the session itself, once makes the end happen a
// single time whichever side gets there first.
type tracked struct {
	cancel context.CancelFunc
	once   sync.Once
}

// track puts the session in the registry, where an administrator's
// terminate, a policy change or a drain end it as they end any bridge, and
// waits for that so the row and the audit trail follow.
func (h *Handler) track(sessionID, userID, targetID, policyID, clientIP string) {
	if h.Registry == nil {
		return
	}
	parent, cancel := context.WithCancel(context.Background())
	ctx := h.Registry.Add(parent, gateway.Live{SessionID: sessionID, UserID: userID, TargetID: targetID, Protocol: protocol.HTTP, PolicyID: policyID})
	tr := &tracked{cancel: cancel}
	h.live.Store(sessionID, tr)
	go func() {
		<-ctx.Done()
		if parent.Err() != nil {
			return // the proxy ended it and writes the end itself
		}
		reason, _ := gateway.CancelReason(ctx)
		tr.once.Do(func() { h.finish(sessionID, userID, targetID, clientIP, reason) })
	}()
}

// end closes a session the proxy found over: its registry entry, its row,
// the cookie's link and the audit event.
func (h *Handler) end(row *Row, reason string) {
	if v, ok := h.live.Load(row.SessionID); ok {
		tr := v.(*tracked)
		tr.cancel()
		tr.once.Do(func() { h.finish(row.SessionID, row.UserID, row.TargetID, row.ClientIP, reason) })
		return
	}
	h.finish(row.SessionID, row.UserID, row.TargetID, row.ClientIP, reason)
}

// forget drops the registry entry and the goroutine waiting on it for a
// session that ended elsewhere, whose end was written by whoever ended it:
// an administrator's terminate, or another gateway on the same database.
func (h *Handler) forget(sessionID string) {
	if v, ok := h.live.LoadAndDelete(sessionID); ok {
		v.(*tracked).cancel()
	}
	if h.Registry != nil {
		h.Registry.Remove(sessionID)
	}
}

// finish writes a session's end, detached from any request that found it.
func (h *Handler) finish(sessionID, userID, targetID, clientIP, reason string) {
	h.live.Delete(sessionID)
	if h.Registry != nil {
		h.Registry.Remove(sessionID)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := h.Sessions.End(ctx, sessionID, reason); err != nil {
		h.log().Error("end application session", "session", sessionID, "err", err)
	}
	if err := h.Repo.DeleteBySession(ctx, sessionID); err != nil {
		h.log().Error("forget application cookie", "session", sessionID, "err", err)
	}
	if h.Audit != nil {
		e := audit.Actor{UserID: userID, IP: clientIP}.Event(audit.AppSessionEnd, "access_session", sessionID, audit.Success, map[string]any{"reason": reason, "target_id": targetID, "protocol": protocol.HTTP})
		if _, err := h.Audit.Record(ctx, e); err != nil {
			h.log().Error("audit application session end", "session", sessionID, "err", err)
		}
	}
}

// Resume puts the application sessions still open in the database back in
// the registry after a start, so they can be ended like any other; the proxy
// serves them from their rows either way. A cookie whose session has ended
// is forgotten.
func (h *Handler) Resume(ctx context.Context) error {
	rows, err := h.Repo.List(ctx)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.EndedAt != nil {
			_ = h.Repo.Delete(ctx, row.TokenHash)
			h.forget(row.SessionID)
			continue
		}
		h.track(row.SessionID, row.UserID, row.TargetID, row.PolicyID, row.ClientIP)
	}
	return nil
}

// Sweep ends the sessions whose terms ran out while no request came: idle,
// past the policy's maximum, or whose sign-in ended. It returns how many it
// ended.
func (h *Handler) Sweep(ctx context.Context) (int, error) {
	rows, err := h.Repo.List(ctx)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	n := 0
	for _, row := range rows {
		if row.EndedAt != nil {
			_ = h.Repo.Delete(ctx, row.TokenHash)
			h.forget(row.SessionID)
			continue
		}
		if reason := h.verdict(row, row.Target.Label, now); reason != "" {
			h.end(row, reason)
			n++
		}
	}
	return n, nil
}

// Run sweeps every interval until ctx ends.
func (h *Handler) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := h.Sweep(ctx); err != nil {
				h.log().Error("application session sweep", "err", err)
			} else if n > 0 {
				h.log().Info("application sessions ended by the sweep", "count", n)
			}
		}
	}
}

func (h *Handler) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}
