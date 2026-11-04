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
	members, err := d.groups.MemberUsers(ctx, id)
	if err != nil {
		return "", nil, err
	}
	// A review-only account (auditor alone) is refused even when a policy
	// names it (user.CanConnect), so the policy gives it nothing to review:
	// listing it showed a person who "never used" access they cannot have
	// (2026-11-04).
	out := make([]policy.Person, 0, len(members))
	for _, m := range members {
		if m.CanConnect() {
			out = append(out, policy.Person{UserID: m.ID, Username: m.Username})
		}
	}
	return g.Name, out, nil
}
