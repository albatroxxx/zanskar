// SPDX-License-Identifier: Apache-2.0

package idp

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/user"
)

// Lifecycle carries out, for one account, what its provider says about the
// person (ADR 0035): they left, or were disabled or deleted there; or they
// came back. The listing sync and the SCIM endpoint share it, so both
// disable, end sessions and record the same way.
type Lifecycle struct {
	Users    *user.Repo
	Sessions SessionRevoker
	Revoker  gateway.Revoker
	Audit    *audit.Log
	Log      *slog.Logger
}

// ErrLastAdmin is returned when a provider would disable the last active
// administrator, which nothing does: everyone would be locked out.
var ErrLastAdmin = errors.New("idp: the last active administrator is never disabled")

// Leave disables an active account whose person has left the provider and
// marks it, so that their return enables it again; their browser sessions
// and live target sessions end, and the change is recorded. via names the
// channel ("directory_sync", "scim"). disabled is false, with no error, for
// an account that was not active: an administrator's status stands.
func (l *Lifecycle) Leave(ctx context.Context, p *Opened, u *user.User, actor audit.Actor, via, reason string, at time.Time) (disabled bool, live int, err error) {
	if u.Status != user.StatusActive {
		return false, 0, nil
	}
	if u.HasRole(user.RoleAdmin) {
		n, err := l.Users.CountAdmins(ctx)
		if err != nil {
			return false, 0, err
		}
		if n <= 1 {
			return false, 0, ErrLastAdmin
		}
	}
	ok, err := l.Users.DisableRemoved(ctx, u.ID, at.UTC())
	if err != nil || !ok {
		return false, 0, err
	}
	d := map[string]any{"username": u.Username, "status": user.StatusDisabled, "previous_status": user.StatusActive,
		"via": via, "idp": p.ID, "idp_name": p.Name, "reason": reason}
	if l.Sessions != nil {
		if n, err := l.Sessions.RevokeAllForUser(ctx, u.ID); err != nil {
			l.Log.Error("end the sessions of an account the provider took away", "user_id", u.ID, "err", err)
		} else {
			d["sessions_revoked"] = n
		}
	}
	if l.Revoker != nil {
		live = l.Revoker.UserRevoked(u.ID)
		d["live_sessions_ended"] = live
	}
	u.Status = user.StatusDisabled
	l.record(ctx, actor.Event(audit.UserUpdate, "user", u.ID, audit.Success, d))
	return true, live, nil
}

// Return enables an account the provider's sync or SCIM disabled, now that
// the person is back. It reports false for any other account: one an
// administrator disabled stays disabled.
func (l *Lifecycle) Return(ctx context.Context, p *Opened, u *user.User, actor audit.Actor, via, reason string) (bool, error) {
	if u.Status != user.StatusDisabled || u.DirectoryRemovedAt == nil {
		return false, nil
	}
	ok, err := l.Users.EnableReturned(ctx, u.ID)
	if err != nil || !ok {
		return false, err
	}
	u.Status, u.DirectoryRemovedAt = user.StatusActive, nil
	l.record(ctx, actor.Event(audit.UserUpdate, "user", u.ID, audit.Success, map[string]any{
		"username": u.Username, "status": user.StatusActive, "previous_status": user.StatusDisabled,
		"via": via, "idp": p.ID, "idp_name": p.Name, "reason": reason}))
	return true, nil
}

func (l *Lifecycle) record(ctx context.Context, e audit.Event) {
	if l.Audit == nil {
		return
	}
	if _, err := l.Audit.Record(context.WithoutCancel(ctx), e); err != nil {
		l.Log.Error("record an account's lifecycle", "action", e.Action, "err", err)
	}
}
