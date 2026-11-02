// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/user"
)

// Handler serves the notification channels' admin API (ADR 0039).
type Handler struct {
	Channels *Repo
	Notifier *Notifier
	Audit    *audit.Log
	Log      *slog.Logger
}

// Register mounts the routes.
func (h *Handler) Register(mux *http.ServeMux) {
	admin := auth.RequireRole(user.RoleAdmin)
	mux.Handle("GET /api/v1/admin/notifications", admin(http.HandlerFunc(h.list)))
	mux.Handle("POST /api/v1/admin/notifications", admin(http.HandlerFunc(h.create)))
	mux.Handle("PUT /api/v1/admin/notifications/{id}", admin(http.HandlerFunc(h.update)))
	mux.Handle("DELETE /api/v1/admin/notifications/{id}", admin(http.HandlerFunc(h.remove)))
	mux.Handle("POST /api/v1/admin/notifications/{id}/test", admin(http.HandlerFunc(h.test)))
	mux.Handle("POST /api/v1/admin/notifications/{id}/signing-key", admin(http.HandlerFunc(h.newKey)))
}

// channelView is a channel as the API shows it: never its secret, with how
// its deliveries are going.
type channelView struct {
	*Channel
	Status Status `json:"status"`
}

// channelInput is what the console sends. A secret field left empty on an
// update keeps the stored one.
type channelInput struct {
	Name         string   `json:"name"`
	Kind         string   `json:"kind"`
	Events       []string `json:"events"`
	Enabled      *bool    `json:"enabled"`
	WebhookURL   string   `json:"webhook_url"`
	SMTPHost     string   `json:"smtp_host"`
	SMTPPort     int      `json:"smtp_port"`
	SMTPUsername string   `json:"smtp_username"`
	SMTPPassword string   `json:"smtp_password"`
	From         string   `json:"from"`
	To           []string `json:"to"`
}

var (
	nameRe  = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._-]{0,63}$`)
	emailRe = regexp.MustCompile(`^[^@\s<>",;]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$`)
	hostRe  = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)
)

// apply checks in and writes it onto c and s, the stored secret, which an
// empty secret field leaves as it was. It returns a sentence for a refusal.
func apply(in channelInput, c *Channel, s *Secret) string {
	in.Name = strings.TrimSpace(in.Name)
	if !nameRe.MatchString(in.Name) {
		return "name: up to 64 letters, digits, spaces, dots, dashes or underscores"
	}
	for _, e := range in.Events {
		if !slices.Contains(Events, e) {
			return "events: unknown kind " + e
		}
	}
	c.Name, c.Events = in.Name, slices.Compact(slices.Sorted(slices.Values(in.Events)))
	if in.Enabled != nil {
		c.Enabled = *in.Enabled
	}
	switch c.Kind {
	case KindWebhook:
		if in.WebhookURL != "" {
			if err := CheckWebhookURL(in.WebhookURL); err != nil {
				return err.Error()
			}
			s.WebhookURL = strings.TrimSpace(in.WebhookURL)
			u, _ := url.Parse(s.WebhookURL)
			c.Config = Config{WebhookHost: u.Hostname()}
		}
		if s.WebhookURL == "" {
			return "webhook_url: required"
		}
	case KindEmail:
		host := strings.TrimSpace(in.SMTPHost)
		if !hostRe.MatchString(host) {
			return "smtp_host: a host name or address"
		}
		if in.SMTPPort < 0 || in.SMTPPort > 65535 {
			return "smtp_port: 1-65535, or empty for 587"
		}
		from := strings.TrimSpace(in.From)
		if !emailRe.MatchString(from) {
			return "from: an email address"
		}
		var to []string
		for _, t := range in.To {
			if t = strings.TrimSpace(t); t == "" {
				continue
			}
			if !emailRe.MatchString(t) {
				return "to: " + t + " is not an email address"
			}
			to = append(to, t)
		}
		if len(to) == 0 || len(to) > 20 {
			return "to: 1 to 20 email addresses"
		}
		if strings.ContainsAny(in.SMTPUsername, "\r\n") {
			return "smtp_username: one line"
		}
		c.Config = Config{SMTPHost: host, SMTPPort: in.SMTPPort, SMTPUsername: strings.TrimSpace(in.SMTPUsername), From: from, To: to}
		if in.SMTPPassword != "" {
			s.SMTPPassword = in.SMTPPassword
		}
		if c.Config.SMTPUsername == "" {
			s.SMTPPassword = ""
		}
	default:
		return "kind: webhook or email"
	}
	return ""
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	channels, err := h.Channels.List(r.Context())
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	views := make([]channelView, len(channels))
	for i, c := range channels {
		views[i] = channelView{c, h.Notifier.Status(c.ID)}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": views, "events": Events})
}

func newSigningKey() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var in channelInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.BadRequest(w, r, err.Error())
		return
	}
	c := &Channel{Kind: in.Kind, Enabled: true}
	var s Secret
	if msg := apply(in, c, &s); msg != "" {
		httpx.BadRequest(w, r, msg)
		return
	}
	if c.Kind == KindWebhook {
		s.SigningKey = newSigningKey()
	}
	if err := h.Channels.Create(r.Context(), c, s); err != nil {
		h.fail(w, r, err)
		return
	}
	// From now on, never the log's history.
	if err := h.Notifier.Start(r.Context(), c.ID); err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	h.record(r, audit.NotifyChannelCreate, c, nil)
	out := map[string]any{"channel": channelView{c, Status{}}}
	// Shown once: the receiver needs it to check the signature.
	if s.SigningKey != "" {
		out["signing_key"] = s.SigningKey
	}
	httpx.WriteJSON(w, http.StatusCreated, out)
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	c, err := h.Channels.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	var in channelInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.BadRequest(w, r, err.Error())
		return
	}
	s := c.secret
	in.Kind = c.Kind
	if msg := apply(in, c, &s); msg != "" {
		httpx.BadRequest(w, r, msg)
		return
	}
	if err := h.Channels.Update(r.Context(), c, s); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, audit.NotifyChannelUpdate, c, map[string]any{"secret_changed": in.WebhookURL != "" || in.SMTPPassword != ""})
	httpx.WriteJSON(w, http.StatusOK, channelView{c, h.Notifier.Status(c.ID)})
}

func (h *Handler) remove(w http.ResponseWriter, r *http.Request) {
	c, err := h.Channels.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if err := h.Channels.Delete(r.Context(), c.ID); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, audit.NotifyChannelDelete, c, nil)
	w.WriteHeader(http.StatusNoContent)
}

// test sends one message now, so an administrator sees the channel work, or
// reads why not.
func (h *Handler) test(w http.ResponseWriter, r *http.Request) {
	c, err := h.Channels.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	p, _ := auth.FromContext(r.Context())
	m := Message{Kind: "test", At: time.Now().UTC().Format("2006-01-02 15:04 UTC"),
		Subject: "Test from " + p.User.Username, Text: "This channel works: " + p.User.Username + " sent a test from the console.", Link: h.Notifier.base() + "/admin/settings"}
	ctx, cancel := context.WithTimeout(r.Context(), sendTimeout)
	defer cancel()
	sendErr := h.Notifier.Sender.Send(ctx, c, m)
	outcome := audit.Success
	if sendErr != nil {
		outcome = audit.Failure
	}
	auth.Recorder{Audit: h.Audit, Log: h.Log}.Record(r, auth.ActorFor(r).Event(audit.NotifyChannelTest, "notification_channel", c.ID, outcome, map[string]any{"name": c.Name, "kind": c.Kind}))
	if sendErr != nil {
		httpx.WriteError(w, r, http.StatusBadGateway, "delivery_failed", sendErr.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// newKey replaces a webhook's signing key and shows the new one once.
func (h *Handler) newKey(w http.ResponseWriter, r *http.Request) {
	c, err := h.Channels.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if c.Kind != KindWebhook {
		httpx.BadRequest(w, r, "only a webhook has a signing key")
		return
	}
	s := c.secret
	s.SigningKey = newSigningKey()
	if err := h.Channels.Update(r.Context(), c, s); err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, audit.NotifyChannelKey, c, nil)
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"signing_key": s.SigningKey})
}

func (h *Handler) record(r *http.Request, action string, c *Channel, extra map[string]any) {
	d := map[string]any{"name": c.Name, "kind": c.Kind, "events": c.Events, "enabled": c.Enabled}
	for k, v := range extra {
		d[k] = v
	}
	auth.Recorder{Audit: h.Audit, Log: h.Log}.Record(r, auth.ActorFor(r).Event(action, "notification_channel", c.ID, audit.Success, d))
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "notification channel not found")
	case errors.Is(err, ErrDuplicate):
		httpx.WriteError(w, r, http.StatusConflict, "duplicate", "a notification channel has that name")
	default:
		httpx.Internal(w, r, h.Log, err)
	}
}
