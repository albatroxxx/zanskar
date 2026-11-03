// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
)

// serverInput is what the console sends for the mail server. A password
// left empty keeps the stored one.
type serverInput struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	From     string `json:"from"`
}

// getServer is the mail server as the console shows it: never its password,
// only whether one is held; null when none is set.
func (h *Handler) getServer(w http.ResponseWriter, r *http.Request) {
	s, err := h.Channels.Server(r.Context())
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, s)
}

// putServer sets the mail server: a host, a port (587 when empty), an
// account with its password (kept when the field is empty), and the sender.
func (h *Handler) putServer(w http.ResponseWriter, r *http.Request) {
	var in serverInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.BadRequest(w, r, err.Error())
		return
	}
	host := strings.TrimSpace(in.Host)
	if !hostRe.MatchString(host) {
		httpx.BadRequest(w, r, "host: a host name or address")
		return
	}
	if in.Port < 0 || in.Port > 65535 {
		httpx.BadRequest(w, r, "port: 1-65535, or empty for 587")
		return
	}
	from := strings.TrimSpace(in.From)
	if !emailRe.MatchString(from) {
		httpx.BadRequest(w, r, "from: an email address")
		return
	}
	username := strings.TrimSpace(in.Username)
	if strings.ContainsAny(username, "\r\n") {
		httpx.BadRequest(w, r, "username: one line")
		return
	}
	existing, err := h.Channels.Server(r.Context())
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	password := in.Password
	if password == "" && existing != nil && existing.HasPassword {
		password = existing.password
	}
	if username == "" {
		password = ""
	} else if password == "" {
		httpx.BadRequest(w, r, "password: required with a username")
		return
	}
	s := &Server{Host: host, Port: in.Port, Username: username, From: from}
	if err := h.Channels.SetServer(r.Context(), s, password); err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	h.recordServer(r, audit.NotifyEmailServerUpdate, audit.Success, map[string]any{"host": host, "port": in.Port, "username": username, "from": from, "secret_changed": in.Password != ""})
	httpx.WriteJSON(w, http.StatusOK, s)
}

// deleteServer forgets the mail server.
func (h *Handler) deleteServer(w http.ResponseWriter, r *http.Request) {
	if err := h.Channels.ClearServer(r.Context()); err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	h.recordServer(r, audit.NotifyEmailServerDelete, audit.Success, nil)
	w.WriteHeader(http.StatusNoContent)
}

// testServer sends one message to the address given through the mail
// server, so an administrator sees it work, or reads why not.
func (h *Handler) testServer(w http.ResponseWriter, r *http.Request) {
	var in struct {
		To string `json:"to"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.BadRequest(w, r, err.Error())
		return
	}
	to := strings.TrimSpace(in.To)
	if !emailRe.MatchString(to) {
		httpx.BadRequest(w, r, "to: an email address")
		return
	}
	s, err := h.Channels.Server(r.Context())
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	if s == nil {
		httpx.WriteError(w, r, http.StatusConflict, "no_mail_server", "no mail server is set")
		return
	}
	p, _ := auth.FromContext(r.Context())
	m := Message{Kind: "test", At: time.Now().UTC().Format("2006-01-02 15:04 UTC"),
		Subject: "Test from " + p.User.Username, Text: "The mail server works: " + p.User.Username + " sent a test from the console.", Link: h.Notifier.base() + "/admin/settings"}
	ctx, cancel := context.WithTimeout(r.Context(), sendTimeout)
	defer cancel()
	sendErr := h.Notifier.Sender.SendThrough(ctx, s, []string{to}, m)
	outcome := audit.Success
	if sendErr != nil {
		outcome = audit.Failure
	}
	h.recordServer(r, audit.NotifyEmailServerTest, outcome, map[string]any{"to": to})
	if sendErr != nil {
		httpx.WriteError(w, r, http.StatusBadGateway, "delivery_failed", sendErr.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) recordServer(r *http.Request, action string, outcome audit.Outcome, details map[string]any) {
	auth.Recorder{Audit: h.Audit, Log: h.Log}.Record(r, auth.ActorFor(r).Event(action, "email_server", "1", outcome, details))
}
