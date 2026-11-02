// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"

	"github.com/albatroxxx/zanskar/internal/group"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/user"
)

// reviewDirectory names the people behind a policy's subjects for an access
// review (ADR 0040). The policy package cannot import group, which imports
// it. A user or group that is gone reads as nobody.
type reviewDirectory struct {
	users  *user.Repo
	groups *group.Repo
}

func (d reviewDirectory) UserName(ctx context.Context, id string) (string, error) {
	u, err := d.users.GetByID(ctx, id)
	if errors.Is(err, user.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

func (d reviewDirectory) Group(ctx context.Context, id string) (string, []policy.Person, error) {
	g, err := d.groups.Get(ctx, id)
	if errors.Is(err, group.ErrNotFound) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	members, err := d.groups.Members(ctx, id)
	if err != nil {
		return "", nil, err
	}
	out := make([]policy.Person, len(members))
	for i, m := range members {
		out[i] = policy.Person{UserID: m.UserID, Username: m.Username}
	}
	return g.Name, out, nil
}
