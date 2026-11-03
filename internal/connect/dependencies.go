// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/albatroxxx/zanskar/internal/gateway/apprelay"
	"github.com/albatroxxx/zanskar/internal/gateway/containers"
	"github.com/albatroxxx/zanskar/internal/target"
)

// refusalsEvery is how often a session's relay log is read for what its
// proxy refused.
const refusalsEvery = 30 * time.Second

// collectRefusals reads the relay's log every refusalsEvery while the
// session lives, and once more through the function returned, which the
// caller runs as the session ends, before the container is removed; what
// the proxy refused as a dependency is kept on the application for the
// console to offer (ADR 0037, amended 2026-11-03, later). The gateway owns
// the container through the Docker CLI, so the log is read as `docker logs
// --since`; a line is taken once, by its own time.
func (h *Handler) collectRefusals(ctx context.Context, relay, targetID string) (last func()) {
	var mu sync.Mutex
	since := time.Now().Add(-time.Minute)
	var seen time.Time
	read := func() {
		mu.Lock()
		defer mu.Unlock()
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		out, err := containers.Output(cctx, h.DockerPath, nil, "logs", "--since", since.UTC().Format(time.RFC3339Nano), relay)
		if err != nil {
			h.Log.Debug("application relay log not read", "target", targetID, "err", err)
			return
		}
		since = time.Now().Add(-5 * time.Second)
		var rs []target.Refusal
		for _, x := range apprelay.ParseRefusals(strings.NewReader(out)) {
			if !x.At.After(seen) {
				continue
			}
			rs = append(rs, target.Refusal{Host: x.Host, Port: x.Port, Why: x.Why, What: x.What, From: x.From, Count: x.Count, FirstSeen: x.At, LastSeen: x.At})
		}
		if len(rs) == 0 {
			return
		}
		seen = rs[len(rs)-1].LastSeen
		if err := h.Targets.RecordRefusals(cctx, targetID, rs); err != nil {
			h.Log.Warn("application dependency refusals not kept", "target", targetID, "err", err)
		}
	}
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(refusalsEvery)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				read()
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(done)
			read()
		})
	}
}

// privateNetworks and privateHosts are an application's private allowances
// as the relay's table takes them; nil for none.
func privateNetworks(p *target.AppPrivate) []string {
	if p == nil {
		return nil
	}
	return p.Networks
}

func privateHosts(p *target.AppPrivate) []string {
	if p == nil {
		return nil
	}
	return p.Hosts
}
