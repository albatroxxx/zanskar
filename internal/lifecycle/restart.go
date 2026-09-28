// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/albatroxxx/zanskar/internal/gateway"
)

// Wait limits for a drain.
const (
	DefaultWait = 15 * time.Minute
	MaxWait     = 4 * time.Hour
)

// Drain describes a restart in progress.
type Drain struct {
	RequestedAt time.Time `json:"requested_at"`
	RequestedBy string    `json:"requested_by"`
	Deadline    time.Time `json:"deadline"`
	WaitMinutes int       `json:"wait_minutes"`
}

// Controller restarts the process on request: it stops new sessions from
// starting, waits for the live ones to end (or ends them at the deadline)
// and then stops serving so the supervisor starts a fresh process, which
// reads the environment file again.
type Controller struct {
	Registry *gateway.Registry
	Log      *slog.Logger
	// Exit stops the server; serve wires it to cancel the serving context.
	// The process then exits 0 and systemd (Restart=always), Docker or the
	// pod's restart policy bring it back.
	Exit func()
	// Poll is how often the drain re-checks the registry; tests shorten it.
	Poll time.Duration

	mu     sync.Mutex
	drain  *Drain
	cancel context.CancelFunc
}

// Draining reports whether a restart is in progress. connect refuses new
// sessions while it is.
func (c *Controller) Draining() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.drain != nil
}

// Current returns the drain in progress, or nil.
func (c *Controller) Current() *Drain {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.drain == nil {
		return nil
	}
	d := *c.drain
	return &d
}

// Restart begins a drain that ends in a restart. wait is how long to let
// live sessions finish before ending them; zero ends them now. A second
// call while one is in progress replaces its deadline.
func (c *Controller) Restart(by string, wait time.Duration) Drain {
	if wait < 0 {
		wait = 0
	}
	if wait > MaxWait {
		wait = MaxWait
	}
	c.mu.Lock()
	if c.cancel != nil {
		c.cancel()
	}
	now := time.Now().UTC()
	d := Drain{RequestedAt: now, RequestedBy: by, Deadline: now.Add(wait), WaitMinutes: int(wait / time.Minute)}
	c.drain = &d
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.mu.Unlock()
	go c.run(ctx, d)
	return d
}

// Cancel abandons the drain; sessions may start again.
func (c *Controller) Cancel() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.drain == nil {
		return false
	}
	c.cancel()
	c.drain, c.cancel = nil, nil
	return true
}

func (c *Controller) run(ctx context.Context, d Drain) {
	poll := c.Poll
	if poll <= 0 {
		poll = time.Second
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for c.Registry.Count() > 0 && time.Now().Before(d.Deadline) {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
	if ctx.Err() != nil {
		return
	}
	ended := 0
	for _, l := range c.Registry.List() {
		if c.Registry.TerminateWithCause(l.SessionID, gateway.ErrGatewayRestart) {
			ended++
		}
	}
	if c.Log != nil {
		c.Log.Warn("restarting on an administrator's request", "requested_by", d.RequestedBy, "sessions_ended", ended, "supervisor", Supervisor())
	}
	// Give the bridges a moment to record how their sessions ended before
	// the listener goes away.
	if ended > 0 {
		time.Sleep(2 * poll)
	}
	c.Exit()
}

// Supervisor names what will start the process again after it exits, when
// that can be told from the environment.
func Supervisor() string {
	if os.Getenv("INVOCATION_ID") != "" {
		return "systemd"
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return "kubernetes"
	}
	return "unknown"
}
