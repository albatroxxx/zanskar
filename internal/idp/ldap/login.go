// SPDX-License-Identifier: Apache-2.0

package ldap

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/idp"
	"github.com/albatroxxx/zanskar/internal/user"
)

// ErrNoMatch means no enabled LDAP provider authenticated the credentials.
// The caller treats this as an ordinary login failure, not a server error.
var ErrNoMatch = errors.New("ldap: no provider matched")

// recordTimeout bounds the user.link insert once it no longer follows the
// sign-in's own deadline (the same bound auth.Recorder uses).
const recordTimeout = 5 * time.Second

// Login authenticates a username and password against every enabled LDAP
// provider in turn and, on the first success, provisions and returns the local
// user. It satisfies the shape auth.ExternalAuthenticator expects; the caller
// maps ErrNoMatch onto auth's own sentinel.
type Login struct {
	Repo        *idp.Repo
	Auth        *Authenticator
	Provisioner *idp.Provisioner
	// Audit records the user.link event when a sign-in adopts a pre-created
	// account; the caller records the sign-in itself. Nil records nothing.
	Audit *audit.Log
	// Log reports a user.link record that failed; nil means slog.Default.
	Log *slog.Logger
}

// NewLogin builds an LDAP login helper.
func NewLogin(repo *idp.Repo, prov *idp.Provisioner, auditLog *audit.Log, log *slog.Logger) *Login {
	return &Login{Repo: repo, Auth: &Authenticator{}, Provisioner: prov, Audit: auditLog, Log: log}
}

// Login tries each enabled LDAP provider. Invalid credentials against one
// provider fall through to the next; a non-credential error (directory
// unreachable, misconfiguration) is remembered and surfaced only if no
// provider authenticates the user. ip is the client address, for the
// user.link event of a sign-in that adopts a pre-created account.
func (l *Login) Login(ctx context.Context, username, password, ip string) (*user.User, error) {
	providers, err := l.Repo.List(ctx, true)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, p := range providers {
		if p.Type != idp.TypeLDAP {
			continue
		}
		op, err := l.Repo.Open(ctx, p.ID)
		if err != nil {
			lastErr = err
			continue
		}
		id, err := l.Auth.Authenticate(ctx, op.Config.LDAP, username, password)
		if err != nil {
			if !errors.Is(err, ErrInvalidCredentials) {
				lastErr = err
			}
			continue
		}
		res, err := l.Provisioner.Resolve(ctx, op, *id)
		if err != nil {
			return nil, err
		}
		for _, e := range res.Events(ip, op, *id) {
			l.record(ctx, e)
		}
		return res.User, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrNoMatch
}

// record stores e detached from ctx's cancellation, as auth.Recorder does for
// HTTP handlers: the link is already written, so its record must not depend
// on the client still waiting for the answer.
func (l *Login) record(ctx context.Context, e audit.Event) {
	if l.Audit == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	defer cancel()
	if _, err := l.Audit.Record(ctx, e); err != nil {
		log := l.Log
		if log == nil {
			log = slog.Default()
		}
		log.Error("audit record failed", "action", e.Action, "err", err)
	}
}
