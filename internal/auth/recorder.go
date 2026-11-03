// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/httpx"
)

// recordTimeout bounds one audit insert once it no longer follows the
// request's own deadline, so a stuck database cannot pin the handler's
// goroutine for good.
const recordTimeout = 5 * time.Second

// ActorFor identifies the caller of r for the audit log: the client address
// always, the user only when the request carries a principal. Routes behind
// RequireAuth always have one; sign-in and sign-out paths may not, and a
// missing principal must never turn an audit row into a panic.
func ActorFor(r *http.Request) audit.Actor {
	a := audit.Actor{IP: ClientIP(r)}
	if p, ok := FromContext(r.Context()); ok {
		a.UserID = p.User.ID
	}
	return a
}

// Recorder writes audit events for HTTP handlers. Every handler package used
// to carry its own copy of this, and most of them opened the audit
// transaction on r.Context(). net/http cancels that context when the client
// connection drops, so a client that disconnected after the mutation
// committed but before the audit insert left the mutation unaudited, with
// nothing but a log line to show for it. The Recorder detaches the insert
// from the request's cancellation while keeping its values (principal,
// client address), and bounds it with recordTimeout instead.
type Recorder struct {
	Audit *audit.Log
	Log   *slog.Logger
}

// Record stores e. It is a no-op when no audit log is configured. A failure
// is logged with the action and the matched route, never with the event's
// details, which may quote what the caller sent.
func (rc Recorder) Record(r *http.Request, e audit.Event) {
	if rc.Audit == nil {
		return
	}
	// A change made with an API token names the token beside its owner
	// (ADR 0044).
	if p, ok := FromContext(r.Context()); ok && p.TokenID != "" {
		e.Details = withDetail(e.Details, "api_token", p.TokenID)
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), recordTimeout)
	defer cancel()
	if _, err := rc.Audit.Record(ctx, e); err != nil {
		log := rc.Log
		if log == nil {
			log = slog.Default()
		}
		log.Error("audit record failed", "action", e.Action, "route", httpx.Route(r), "err", err)
	}
}

// withDetail sets key to value in an event's details, a JSON object or none.
// Details that are not an object are kept as they are.
func withDetail(details json.RawMessage, key string, value any) json.RawMessage {
	m := map[string]any{}
	if len(details) > 0 {
		if err := json.Unmarshal(details, &m); err != nil || m == nil {
			return details
		}
	}
	m[key] = value
	b, err := json.Marshal(m)
	if err != nil {
		return details
	}
	return b
}
