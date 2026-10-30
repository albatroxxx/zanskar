// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"

	"github.com/albatroxxx/zanskar/internal/asg"
	"github.com/albatroxxx/zanskar/internal/target"
)

// policyInventory tells the policy handler what the ids a grant names are
// (ADR 0036), so a grant naming a target of another kind, or one retired,
// is refused when it is written. The policy package cannot import target or
// asg, which import it.
type policyInventory struct {
	targets *target.Repo
	groups  *asg.Repo
}

func (i policyInventory) TargetKind(ctx context.Context, id string) (string, bool, error) {
	t, err := i.targets.Get(ctx, id)
	if errors.Is(err, target.ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return t.Kind(), true, nil
}

func (i policyInventory) GroupExists(ctx context.Context, id string) (bool, error) {
	_, err := i.groups.Get(ctx, id)
	if errors.Is(err, asg.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}
