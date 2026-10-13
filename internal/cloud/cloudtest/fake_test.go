// SPDX-License-Identifier: Apache-2.0

package cloudtest

import (
	"context"
	"errors"
	"testing"

	"github.com/albatroxxx/zanskar/internal/cloud"
)

func TestFakeCheck(t *testing.T) {
	ctx := context.Background()
	f := NewFake()
	chk, err := f.Check(ctx, "web")
	if err != nil || chk.GroupFound || chk.AssumedARN == "" {
		t.Fatalf("missing group: %+v %v", chk, err)
	}
	f.Set("web", cloud.Instance{ID: "i-1"}, cloud.Instance{ID: "i-2"})
	if chk, err = f.Check(ctx, "web"); err != nil || !chk.GroupFound || chk.InstanceCount != 2 {
		t.Fatalf("found: %+v %v", chk, err)
	}
	f.Err = errors.New("denied")
	if _, err = f.Check(ctx, "web"); !errors.Is(err, cloud.ErrAssumeRole) {
		t.Fatalf("assume failure: %v", err)
	}
}
