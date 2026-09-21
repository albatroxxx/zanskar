// SPDX-License-Identifier: Apache-2.0

package ldap

import (
	"context"
	"errors"

	"github.com/albatroxxx/zanskar/internal/idp"
	"github.com/albatroxxx/zanskar/internal/user"
)

// ErrNoMatch means no enabled LDAP provider authenticated the credentials.
// The caller treats this as an ordinary login failure, not a server error.
var ErrNoMatch = errors.New("ldap: no provider matched")

// Login authenticates a username and password against every enabled LDAP
// provider in turn and, on the first success, provisions and returns the local
// user. It satisfies the shape auth.ExternalAuthenticator expects; the caller
// maps ErrNoMatch onto auth's own sentinel.
type Login struct {
	Repo        *idp.Repo
	Auth        *Authenticator
	Provisioner *idp.Provisioner
}

// NewLogin builds an LDAP login helper.
func NewLogin(repo *idp.Repo, prov *idp.Provisioner) *Login {
	return &Login{Repo: repo, Auth: &Authenticator{}, Provisioner: prov}
}

// Login tries each enabled LDAP provider. Invalid credentials against one
// provider fall through to the next; a non-credential error (directory
// unreachable, misconfiguration) is remembered and surfaced only if no
// provider authenticates the user.
func (l *Login) Login(ctx context.Context, username, password, _ string) (*user.User, error) {
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
		u, err := l.Provisioner.Resolve(ctx, op, *id)
		if err != nil {
			return nil, err
		}
		return u, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrNoMatch
}
