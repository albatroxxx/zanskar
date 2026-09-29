// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"context"
	"fmt"
	"sync"
)

// Fake is an in-memory Provider for tests and local demos.
type Fake struct {
	mu       sync.Mutex
	Groups   map[string]*GroupSnapshot
	Console  map[string][]string // instance id -> fingerprints
	SentKeys []SentKey
	Err      error // returned by every call when set
}

// SentKey records a SendSSHPublicKey call.
type SentKey struct {
	InstanceID, AZ, OSUser string
	PublicKey              []byte
}

// NewFake returns an empty fake.
func NewFake() *Fake {
	return &Fake{Groups: map[string]*GroupSnapshot{}, Console: map[string][]string{}}
}

// Set replaces a group's snapshot.
func (f *Fake) Set(name string, instances ...Instance) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Groups[name] = &GroupSnapshot{Name: name, Instances: instances, DesiredCapacity: len(instances)}
}

// Check implements Provider: Err fails the assume step; a missing group is
// reported as not found.
func (f *Fake) Check(ctx context.Context, name string) (*AccessCheck, error) {
	f.mu.Lock()
	err := f.Err
	f.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAssumeRole, err)
	}
	out := &AccessCheck{AssumedARN: "arn:aws:sts::123456789012:assumed-role/fake/zanskar-gateway"}
	snap, err := f.DescribeGroup(ctx, name)
	if err == nil {
		out.GroupFound, out.InstanceCount = true, len(snap.Instances)
	}
	return out, nil
}

// DescribeGroup implements Provider.
func (f *Fake) DescribeGroup(_ context.Context, name string) (*GroupSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return nil, f.Err
	}
	g, ok := f.Groups[name]
	if !ok {
		return nil, ErrGroupNotFound
	}
	cp := *g
	cp.Instances = append([]Instance(nil), g.Instances...)
	return &cp, nil
}

// ConsoleHostKeys implements Provider.
func (f *Fake) ConsoleHostKeys(_ context.Context, instanceID string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return nil, f.Err
	}
	fps := f.Console[instanceID]
	if len(fps) == 0 {
		return nil, ErrNoConsoleKeys
	}
	return append([]string(nil), fps...), nil
}

// SendSSHPublicKey implements Provider.
func (f *Fake) SendSSHPublicKey(_ context.Context, instanceID, az, osUser string, publicKey []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return f.Err
	}
	f.SentKeys = append(f.SentKeys, SentKey{InstanceID: instanceID, AZ: az, OSUser: osUser, PublicKey: append([]byte(nil), publicKey...)})
	return nil
}
