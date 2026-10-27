// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/protocol"
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
	// Action names what the drain ends in: restart (the default), reboot or
	// poweroff (ADR 0032), so the console can say which is coming.
	Action string `json:"action"`
	// then runs instead of Exit when set: a host action after the drain.
	then func()
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
	// Grace is how long, after the sessions are ended, the drain waits for
	// their bridges to finish: the end frame to the browser, the recording's
	// upload, the session row, the audit event, a database session's
	// containers. Zero means DefaultGrace. What is still running after
	// that is logged and abandoned (review finding SEC-10).
	Grace time.Duration

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
	return c.RestartThen(by, wait, "restart", nil)
}

// RestartThen is Restart with a different ending: after the drain, then runs
// in place of Exit — a reboot or power-off of the host (ADR 0032). action
// is the word the status shows for it.
func (c *Controller) RestartThen(by string, wait time.Duration, action string, then func()) Drain {
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
	d := Drain{RequestedAt: now, RequestedBy: by, Deadline: now.Add(wait), WaitMinutes: int(wait / time.Minute), Action: action, then: then}
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
	// Application sessions (ADR 0033) are not waited on: they hold nothing in
	// flight, so Waiting() leaves them out and the cutover below ends them
	// with the same gateway_restart reason as any bridge. A drain with only
	// application sessions open proceeds at once.
	for c.Registry.Waiting() > 0 && time.Now().Before(d.Deadline) {
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
	// the listener goes away, then sweep once more for a bridge that
	// redeemed its ticket before the drain began and registered after the
	// first pass, so it too ends with a recorded reason.
	if ended > 0 {
		time.Sleep(2 * poll)
	}
	for _, l := range c.Registry.List() {
		if c.Registry.TerminateWithCause(l.SessionID, gateway.ErrGatewayRestart) {
			ended++
		}
	}
	// Ending a session is not the end of its bridge: the recording still
	// uploads, the row closes, the audit event is written, a database
	// session's containers go. Wait for the bridges to leave the registry,
	// within Grace, before the process goes away under them (SEC-10).
	// Application sessions are left out here as above: a cutover ends them
	// and nothing of theirs is in flight.
	grace := c.Grace
	if grace <= 0 {
		grace = DefaultGrace
	}
	deadline := time.Now().Add(grace)
	for c.Registry.Waiting() > 0 && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
	if c.Log != nil {
		var ids []string
		for _, l := range c.Registry.List() {
			if l.Protocol != protocol.HTTP {
				ids = append(ids, l.SessionID)
			}
		}
		if len(ids) > 0 {
			c.Log.Warn("restarting with sessions still finishing; their recordings or rows may be incomplete", "sessions", ids, "waited", grace.String())
		}
	}
	if d.then != nil {
		d.then()
		return
	}
	c.Exit()
}

// DefaultGrace is how long a drain waits for ended sessions' bridges to
// finish before the process exits regardless.
const DefaultGrace = 30 * time.Second

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
