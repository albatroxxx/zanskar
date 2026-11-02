// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
)

// maxPerPass is how many messages a channel gets from one pass; past it, one
// more says how many were left out (ADR 0039).
const maxPerPass = 20

// batch is how many events one read of the log takes.
const batch = 200

// Status is how a channel's deliveries are going, for the console.
type Status struct {
	LastSentAt  *time.Time `json:"last_sent_at,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	LastErrorAt *time.Time `json:"last_error_at,omitempty"`
}

// Notifier follows the audit log and tells each enabled channel the events
// it asked for, from its own checkpoint (ADR 0039).
type Notifier struct {
	Channels *Repo
	Audit    *audit.Log
	// Resolve names ids by kind for the messages (session.Repo.ResolveNames).
	Resolve func(ctx context.Context, kind string, ids []string) (map[string]string, error)
	// Base is the console's public address, for links; empty leaves them out.
	Base   string
	Sender *Sender
	Log    *slog.Logger
	// Interval between passes; default 10 s.
	Interval time.Duration

	mu      sync.Mutex
	status  map[string]Status
	retryAt map[string]time.Time
	backoff map[string]time.Duration
}

// Status reports a channel's deliveries.
func (n *Notifier) Status(id string) Status {
	if n == nil {
		return Status{}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.status[id]
}

// Run passes over the channels until ctx ends.
func (n *Notifier) Run(ctx context.Context) {
	every := n.Interval
	if every <= 0 {
		every = 10 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		n.Pass(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Pass delivers what each enabled channel has not been told yet. A failing
// channel backs off, doubling to five minutes, without holding the others.
func (n *Notifier) Pass(ctx context.Context) {
	channels, err := n.Channels.List(ctx)
	if err != nil {
		n.Log.Warn("notify: list channels", "err", err)
		return
	}
	now := time.Now()
	for _, c := range channels {
		if !c.Enabled || len(c.Events) == 0 {
			continue
		}
		n.mu.Lock()
		wait := now.Before(n.retryAt[c.ID])
		n.mu.Unlock()
		if wait {
			continue
		}
		sent, err := n.flush(ctx, c)
		n.mu.Lock()
		if n.status == nil {
			n.status, n.retryAt, n.backoff = map[string]Status{}, map[string]time.Time{}, map[string]time.Duration{}
		}
		st := n.status[c.ID]
		at := time.Now().UTC()
		if err != nil {
			b := min(n.backoff[c.ID]*2+10*time.Second, 5*time.Minute)
			n.backoff[c.ID], n.retryAt[c.ID] = b, now.Add(b)
			st.LastError, st.LastErrorAt = err.Error(), &at
			n.Log.Warn("notify: delivery failed", "channel", c.Name, "err", err, "retry_in", b)
		} else {
			delete(n.backoff, c.ID)
			delete(n.retryAt, c.ID)
			if sent > 0 {
				st.LastSentAt, st.LastError, st.LastErrorAt = &at, "", nil
			}
		}
		n.status[c.ID] = st
		n.mu.Unlock()
	}
}

// flush reads the log after c's checkpoint and sends what c asked for. The
// checkpoint moves only past what was delivered, so a failure resends from
// the event that failed: at least once, in order.
func (n *Notifier) flush(ctx context.Context, c *Channel) (int, error) {
	last, err := n.Audit.ExportCheckpoint(ctx, Sink(c.ID))
	if err != nil {
		return 0, err
	}
	sent := 0
	for {
		events, err := n.Audit.ListAfter(ctx, last, batch)
		if err != nil {
			return sent, err
		}
		if len(events) == 0 {
			return sent, nil
		}
		var due []audit.Event
		var kinds []string
		for _, e := range events {
			if k := kindOf(e); k != "" && c.Wants(k) {
				due = append(due, e)
				kinds = append(kinds, k)
			}
		}
		names, err := n.names(ctx, due)
		if err != nil {
			return sent, err
		}
		for i, e := range due {
			if sent == maxPerPass {
				more := len(due) - i
				if err := n.Sender.Send(ctx, c, Message{Kind: "summary", EventID: e.ID, At: e.Timestamp.UTC().Format("2006-01-02 15:04 UTC"),
					Subject: fmt.Sprintf("%d more events", more), Text: fmt.Sprintf("%d more events this channel asked for; see the console's Events page.", more), Link: n.base() + "/admin/events"}); err != nil {
					return sent, err
				}
				break
			}
			if err := n.Sender.Send(ctx, c, message(e, kinds[i], names, n.base())); err != nil {
				return sent, err
			}
			sent++
			if err := n.Audit.SaveExportCheckpoint(ctx, Sink(c.ID), e.ID); err != nil {
				return sent, err
			}
		}
		last = events[len(events)-1].ID
		if err := n.Audit.SaveExportCheckpoint(ctx, Sink(c.ID), last); err != nil {
			return sent, err
		}
		if len(events) < batch || sent >= maxPerPass {
			return sent, nil
		}
	}
}

func (n *Notifier) base() string { return strings.TrimRight(n.Base, "/") }

// names resolves every id the messages of due will name, one lookup per kind.
func (n *Notifier) names(ctx context.Context, due []audit.Event) (Names, error) {
	want := map[string][]string{}
	for _, e := range due {
		want["user"] = append(want["user"], e.ActorUserID)
		if id := detail(e, "target_id"); id != "" {
			want["target"] = append(want["target"], id)
		}
		if id := detail(e, "asg_id"); id != "" {
			want["autoscaling_group"] = append(want["autoscaling_group"], id)
		}
		if e.ObjectType == "identity_provider" {
			want["identity_provider"] = append(want["identity_provider"], e.ObjectID)
		}
	}
	got := map[string]map[string]string{}
	for kind, ids := range want {
		if n.Resolve == nil {
			break
		}
		m, err := n.Resolve(ctx, kind, ids)
		if err != nil {
			return nil, err
		}
		got[kind] = m
	}
	return func(kind, id string) string {
		if id == "" {
			return ""
		}
		if name := got[kind][id]; name != "" {
			return name
		}
		if len(id) > 8 {
			return id[:8]
		}
		return id
	}, nil
}

// Start puts a new channel at the newest event, so it is told what happens
// from now on, never the log's history (ADR 0039).
func (n *Notifier) Start(ctx context.Context, id string) error {
	newest, err := n.Audit.Newest(ctx)
	if err != nil {
		return err
	}
	return n.Audit.SaveExportCheckpoint(ctx, Sink(id), newest)
}
