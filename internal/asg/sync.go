// SPDX-License-Identifier: Apache-2.0

package asg

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/cloud"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/target"
)

// ProviderFactory returns the cloud provider for a group. Implementations
// should cache by group id so temporary credentials are reused.
type ProviderFactory func(ctx context.Context, g *Group) (cloud.Provider, error)

// Syncer polls enrolled groups and keeps asg_instances current (ADR 0011).
// Health is the conjunction of the group's lifecycle state, the load
// balancer's verdict, and the gateway's own reachability probe. When an
// instance leaves the healthy pool, every live session on it is ended with
// the target_lost cause so the browser offers failover.
type Syncer struct {
	Repo      *Repo
	Providers ProviderFactory
	Prober    *target.Prober
	Registry  *gateway.Registry
	Audit     *audit.Log
	Log       *slog.Logger
	// ProbeTimeout bounds each instance probe. Default 5 s.
	ProbeTimeout time.Duration

	mu      sync.Mutex
	running map[string]bool
}

// Summary reports one poll.
type Summary struct {
	Seen, Healthy, Joined, Left, Retired int
	HostKeyMismatches                    int
}

// SyncGroup performs one poll of g.
func (s *Syncer) SyncGroup(ctx context.Context, g *Group) (Summary, error) {
	var sum Summary
	s.mu.Lock()
	if s.running == nil {
		s.running = map[string]bool{}
	}
	if s.running[g.ID] {
		s.mu.Unlock()
		return sum, errors.New("asg: sync already running for this group")
	}
	s.running[g.ID] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.running, g.ID)
		s.mu.Unlock()
	}()

	provider, err := s.Providers(ctx, g)
	if err != nil {
		_ = s.Repo.RecordSync(ctx, g.ID, err)
		return sum, err
	}
	snap, err := provider.DescribeGroup(ctx, g.ExternalName)
	if err != nil {
		_ = s.Repo.RecordSync(ctx, g.ID, err)
		return sum, err
	}

	previous := map[string]*Instance{}
	if rows, err := s.Repo.Instances(ctx, g.ID, false); err == nil {
		for _, in := range rows {
			previous[in.InstanceID] = in
		}
	}

	timeout := s.ProbeTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	var keep []string
	for _, ci := range snap.Instances {
		sum.Seen++
		keep = append(keep, ci.ID)
		in := &Instance{GroupID: g.ID, InstanceID: ci.ID, PrivateIP: ci.PrivateIP, PublicIP: ci.PublicIP, AvailabilityZone: ci.AvailabilityZone,
			LifecycleState: ci.LifecycleState, LBHealth: ci.LBHealth, ProbeHealth: "unknown"}
		if !ci.LaunchedAt.IsZero() {
			l := ci.LaunchedAt
			in.LaunchedAt = &l
		}
		prev := previous[ci.ID]
		if cloud.Healthy(ci) {
			s.probe(ctx, provider, g, in, prev, timeout, &sum)
		} else {
			in.ProbeHealth = "unhealthy"
		}
		stored, isNew, err := s.Repo.UpsertInstance(ctx, in)
		if err != nil {
			_ = s.Repo.RecordSync(ctx, g.ID, err)
			return sum, err
		}
		if stored.Healthy {
			sum.Healthy++
		}
		switch {
		case isNew:
			sum.Joined++
			s.record(ctx, "asg.instance.joined", g, stored, map[string]any{"healthy": stored.Healthy, "host_key_source": stored.HostKeySource})
		case prev != nil && prev.Healthy && !stored.Healthy:
			sum.Retired++
			s.record(ctx, "asg.instance.unhealthy", g, stored, map[string]any{"lifecycle": stored.LifecycleState, "lb": stored.LBHealth, "probe": stored.ProbeHealth})
			s.retire(stored)
		}
	}
	gone, err := s.Repo.MarkTerminated(ctx, g.ID, keep)
	if err != nil {
		_ = s.Repo.RecordSync(ctx, g.ID, err)
		return sum, err
	}
	for _, in := range gone {
		sum.Left++
		s.record(ctx, "asg.instance.left", g, in, nil)
		s.retire(in)
	}
	return sum, s.Repo.RecordSync(ctx, g.ID, nil)
}

// probe checks reachability of the group's capability ports and pins the
// SSH host key: verified against the serial console when the cloud publishes
// it, trust-on-first-use otherwise. A console/observed mismatch is treated
// as unhealthy and audited; the key is never pinned in that case.
func (s *Syncer) probe(ctx context.Context, provider cloud.Provider, g *Group, in, prev *Instance, timeout time.Duration, sum *Summary) {
	addr := g.Address(in)
	if addr == "" || s.Prober == nil {
		in.ProbeHealth = "unhealthy"
		return
	}
	ports := map[target.Protocol]int{}
	for _, p := range g.Capabilities {
		ports[p] = g.Port(p)
	}
	res, err := s.Prober.Probe(ctx, addr, ports, timeout)
	if err != nil {
		in.ProbeHealth = "unhealthy"
		return
	}
	healthy := true
	for _, p := range g.Capabilities {
		if !res.Reachable[p] {
			healthy = false
		}
	}
	in.ProbeHealth = "unhealthy"
	if healthy {
		in.ProbeHealth = "healthy"
	}
	if prev != nil && prev.HostKeyFingerprint != "" {
		// Already pinned: a different key on the same instance is a red flag.
		if res.SSHHostKey != nil && res.SSHHostKey.Fingerprint != prev.HostKeyFingerprint {
			in.ProbeHealth = "unhealthy"
			sum.HostKeyMismatches++
			s.record(ctx, "asg.instance.hostkey.changed", g, prev, map[string]any{"pinned": prev.HostKeyFingerprint, "observed": res.SSHHostKey.Fingerprint})
		}
		in.HostKeyFingerprint, in.HostKeySource = prev.HostKeyFingerprint, prev.HostKeySource
		return
	}
	if res.SSHHostKey == nil || res.SSHHostKey.Fingerprint == "" {
		return
	}
	observed := res.SSHHostKey.Fingerprint
	consoleKeys, cerr := provider.ConsoleHostKeys(ctx, in.InstanceID)
	switch cerr {
	case nil:
		for _, fp := range consoleKeys {
			if fp == observed {
				in.HostKeyFingerprint, in.HostKeySource = observed, "console"
				return
			}
		}
		// The console published keys and none match what we saw: MITM or a
		// rebuilt instance reusing an id. Refuse to pin.
		in.ProbeHealth = "unhealthy"
		sum.HostKeyMismatches++
		s.record(ctx, "asg.instance.hostkey.mismatch", g, in, map[string]any{"console": consoleKeys, "observed": observed})
	default:
		in.HostKeyFingerprint, in.HostKeySource = observed, "tofu"
	}
}

func (s *Syncer) retire(in *Instance) {
	if s.Registry == nil {
		return
	}
	if n := s.Registry.TerminateTarget(in.ID, gateway.ErrTargetLost); n > 0 && s.Log != nil {
		s.Log.Info("ended sessions on retired instance", "instance", in.InstanceID, "sessions", n)
	}
}

func (s *Syncer) record(ctx context.Context, action string, g *Group, in *Instance, details map[string]any) {
	if s.Audit == nil {
		return
	}
	if details == nil {
		details = map[string]any{}
	}
	details["asg"] = g.Name
	details["instance_id"] = in.InstanceID
	if _, err := s.Audit.Record(ctx, audit.Actor{IP: "sync"}.Event(action, "asg_instance", in.ID, audit.Success, details)); err != nil && s.Log != nil {
		s.Log.Error("audit record failed", "action", action, "err", err)
	}
}

// Run polls every active group on its own interval until ctx ends. Groups
// added later are picked up within one scheduler tick (10 s).
func (s *Syncer) Run(ctx context.Context) {
	next := map[string]time.Time{}
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		groups, err := s.Repo.List(ctx, true)
		if err != nil {
			if s.Log != nil {
				s.Log.Error("list autoscaling groups", "err", err)
			}
		}
		now := time.Now()
		for _, g := range groups {
			if t, ok := next[g.ID]; ok && now.Before(t) {
				continue
			}
			next[g.ID] = now.Add(time.Duration(g.PollIntervalSeconds) * time.Second)
			sum, err := s.SyncGroup(ctx, g)
			if s.Log != nil {
				if err != nil {
					s.Log.Warn("asg sync failed", "asg", g.Name, "err", err)
				} else {
					s.Log.Debug("asg sync", "asg", g.Name, "seen", sum.Seen, "healthy", sum.Healthy, "joined", sum.Joined, "left", sum.Left)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// AWSProviders is a ProviderFactory for AWS that caches one provider per
// group and rebuilds it when the group's role or region changes.
func AWSProviders() ProviderFactory {
	var mu sync.Mutex
	type entry struct {
		key string
		p   cloud.Provider
	}
	cache := map[string]entry{}
	return func(ctx context.Context, g *Group) (cloud.Provider, error) {
		key := fmt.Sprintf("%s|%s|%s", g.Region, g.RoleARN, g.ExternalID)
		mu.Lock()
		defer mu.Unlock()
		if e, ok := cache[g.ID]; ok && e.key == key {
			return e.p, nil
		}
		p, err := cloud.NewAWS(ctx, cloud.AWSAccess{Region: g.Region, RoleARN: g.RoleARN, ExternalID: g.ExternalID})
		if err != nil {
			return nil, err
		}
		cache[g.ID] = entry{key: key, p: p}
		return p, nil
	}
}
