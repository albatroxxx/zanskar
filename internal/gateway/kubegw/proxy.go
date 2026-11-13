// SPDX-License-Identifier: Apache-2.0

package kubegw

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// TokenPrefix opens every session token, so it is told apart from an API
// token (auth.TokenPrefix) and from anything else a person might paste.
const TokenPrefix = "zk8s_"

// Identity is who a session acts as in the cluster (ADR 0045, 2): the
// person, with their Zanskar groups, or, when User is empty, the credential
// itself (shared identity).
type Identity struct {
	User string
	// Groups are Zanskar group names; each goes out as GroupPrefix+name,
	// beside system:authenticated.
	Groups []string
}

// Options builds a session's proxy.
type Options struct {
	SessionID  string
	Endpoint   Endpoint
	Credential Credential
	Identity   Identity
	Scope      Scope
	// Record takes one line per request that names a resource, as the
	// recording and the live watcher show it; nil records nothing.
	Record func(line string)
	Log    *slog.Logger
}

// Session is one kube session's endpoint at the gateway: it checks the
// session token, holds the line of the scope, and forwards each request to
// the cluster as the person, with the vaulted credential in place of
// whatever the person sent as authentication. It lives until Close.
type Session struct {
	ID       string
	scope    Scope
	identity Identity
	cred     Credential
	upstream *url.URL
	tr       *http.Transport
	rp       *httputil.ReverseProxy
	hash     [sha256.Size]byte
	record   func(string)
	log      *slog.Logger
	active   atomic.Int64 // unix nanoseconds of the last request or stream byte
	// ctx ends with the session: every request in flight runs under it too.
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	closed  bool
	tunnels map[*tunnel]struct{}
}

// NewSession returns the session's proxy and its token, the one text that
// opens it, which the caller hands the person once and never stores.
func NewSession(o Options) (*Session, string, error) {
	tr, err := Transport(o.Endpoint, o.Credential)
	if err != nil {
		return nil, "", err
	}
	u, err := url.Parse(o.Endpoint.APIServer)
	if err != nil {
		return nil, "", err
	}
	u.Path, u.RawPath, u.RawQuery = "", "", ""
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, "", err
	}
	token := TokenPrefix + base64.RawURLEncoding.EncodeToString(raw[:])
	if o.Log == nil {
		o.Log = slog.Default()
	}
	s := &Session{ID: o.SessionID, scope: o.Scope, identity: o.Identity, cred: o.Credential, upstream: u, tr: tr,
		hash: sha256.Sum256([]byte(token)), record: o.Record, log: o.Log, tunnels: map[*tunnel]struct{}{}}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.touch()
	s.rp = &httputil.ReverseProxy{
		Rewrite:   s.rewrite,
		Transport: roundTripper{s},
		// A watch or a log stream is written as it comes.
		FlushInterval:  -1,
		ModifyResponse: s.modifyResponse,
		ErrorHandler:   s.errorHandler,
		ErrorLog:       slog.NewLogLogger(o.Log.Handler(), slog.LevelDebug),
	}
	return s, token, nil
}

// Authenticate reports whether bearer is this session's token and the
// session is still open. The comparison takes the same time whatever the
// token.
func (s *Session) Authenticate(bearer string) bool {
	sum := sha256.Sum256([]byte(bearer))
	ok := subtle.ConstantTimeCompare(sum[:], s.hash[:]) == 1
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	return ok && !closed
}

// LastActive is when the session last carried a request or a stream byte.
func (s *Session) LastActive() time.Time { return time.Unix(0, s.active.Load()) }

func (s *Session) touch() { s.active.Store(time.Now().UnixNano()) }

// Close ends the session: the token is refused from here, every open stream
// is closed, and the cluster's connections are dropped.
func (s *Session) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	open := make([]*tunnel, 0, len(s.tunnels))
	for t := range s.tunnels {
		open = append(open, t)
	}
	s.mu.Unlock()
	// Requests in flight (a watch, a log) end with the context; upgraded
	// streams, which the context no longer reaches, are closed by hand.
	s.cancel()
	for _, t := range open {
		_ = t.Close()
	}
	s.tr.CloseIdleConnections()
}

// Streams is how many upgraded streams (exec, attach, port-forward) are open.
func (s *Session) Streams() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tunnels)
}

type ctxKey int

const labelKey ctxKey = 1

// ServeHTTP answers one request whose URL path is the API path, the gateway's
// prefix already removed. The caller has checked the token.
func (s *Session) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The server's read deadline is for the request; a watch or a log
	// stream answers for longer than it allows (server.go, ReadTimeout).
	_ = http.NewResponseController(w).SetReadDeadline(time.Time{})
	req, ok := Parse(r.Method, r.URL.Path, r.URL.Query())
	if !ok {
		writeStatus(w, http.StatusNotFound, "NotFound", "Zanskar: not an API path")
		return
	}
	s.touch()
	if ok, why := s.scope.Allow(req); !ok {
		s.line(req.Label() + " → 403 (gateway: outside the access)")
		writeStatus(w, http.StatusForbidden, "Forbidden", why)
		return
	}
	// The request runs under both the person's request and the session: an
	// end to either ends what is in flight.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	if !req.Discovery {
		ctx = context.WithValue(ctx, labelKey, req.Label())
	}
	s.rp.ServeHTTP(w, r.WithContext(ctx))
}

// Watch ties in-flight requests to the session's life: when ctx ends, every
// request still running is cut and the session closed.
func (s *Session) Watch(ctx context.Context) {
	go func() {
		<-ctx.Done()
		s.Close()
	}()
}

// rewrite points the request at the cluster and replaces everything the
// person sent as identity with Zanskar's credential and the impersonation
// headers (ADR 0045, 3). Nothing else the person sent is forwarded as
// authentication.
func (s *Session) rewrite(pr *httputil.ProxyRequest) {
	pr.SetURL(s.upstream)
	h := pr.Out.Header
	for k := range h {
		if strings.HasPrefix(k, "Impersonate-") || strings.HasPrefix(k, "X-Remote-") || strings.HasPrefix(k, "X-Forwarded-") {
			h.Del(k)
		}
	}
	h.Del("Authorization")
	h.Del("Cookie")
	h.Del("X-Real-Ip")
	if s.cred.Token != "" {
		h.Set("Authorization", "Bearer "+s.cred.Token)
	}
	if s.identity.User != "" {
		h.Set("Impersonate-User", s.identity.User)
		groups := make([]string, 0, len(s.identity.Groups)+1)
		groups = append(groups, "system:authenticated")
		for _, g := range s.identity.Groups {
			groups = append(groups, GroupPrefix+g)
		}
		h["Impersonate-Group"] = groups
	}
}

func (s *Session) modifyResponse(res *http.Response) error {
	label, _ := res.Request.Context().Value(labelKey).(string)
	if label == "" {
		return nil
	}
	if res.StatusCode == http.StatusSwitchingProtocols {
		s.line(label + " → stream opened")
		return nil
	}
	s.line(fmt.Sprintf("%s → %d", label, res.StatusCode))
	return nil
}

func (s *Session) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	if label, _ := r.Context().Value(labelKey).(string); label != "" {
		s.line(label + " → 502 (cluster unreachable)")
	}
	if r.Context().Err() == nil {
		s.log.Info("kube: request to the cluster failed", "session", s.ID, "err", err)
	}
	writeStatus(w, http.StatusBadGateway, "ServiceUnavailable", "Zanskar: the cluster could not be reached")
}

func (s *Session) line(text string) {
	if s.record != nil {
		s.record(text)
	}
}

// roundTripper wraps the cluster transport so a stream's bytes count as
// activity and an upgraded stream can be closed with the session.
type roundTripper struct{ s *Session }

func (t roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := t.s.tr.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	label, _ := req.Context().Value(labelKey).(string)
	if res.StatusCode == http.StatusSwitchingProtocols {
		// The reverse proxy needs the upgraded body to read and write; a
		// body that is not both is its 502.
		if rwc, ok := res.Body.(io.ReadWriteCloser); ok {
			res.Body = t.s.newTunnel(rwc, label)
		}
		return res, nil
	}
	res.Body = &activeBody{ReadCloser: res.Body, s: t.s}
	return res, nil
}

// activeBody counts a streamed answer (a watch, a log) as activity.
type activeBody struct {
	io.ReadCloser
	s *Session
}

func (b *activeBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.s.touch()
	}
	return n, err
}

// tunnel is one upgraded stream (exec, attach, port-forward): bytes are
// counted both ways and count as activity; Close records how it went and is
// what the session's Close reaches.
type tunnel struct {
	rwc     io.ReadWriteCloser
	s       *Session
	label   string
	started time.Time
	in, out atomic.Int64
	once    sync.Once
}

func (s *Session) newTunnel(rwc io.ReadWriteCloser, label string) *tunnel {
	t := &tunnel{rwc: rwc, s: s, label: label, started: time.Now()}
	s.mu.Lock()
	s.tunnels[t] = struct{}{}
	s.mu.Unlock()
	return t
}

// Read is the cluster's side: bytes to the person.
func (t *tunnel) Read(p []byte) (int, error) {
	n, err := t.rwc.Read(p)
	if n > 0 {
		t.out.Add(int64(n))
		t.s.touch()
	}
	return n, err
}

// Write is the person's side: bytes to the cluster.
func (t *tunnel) Write(p []byte) (int, error) {
	n, err := t.rwc.Write(p)
	if n > 0 {
		t.in.Add(int64(n))
		t.s.touch()
	}
	return n, err
}

func (t *tunnel) Close() error {
	t.once.Do(func() {
		t.s.mu.Lock()
		delete(t.s.tunnels, t)
		t.s.mu.Unlock()
		if t.label != "" {
			t.s.line(fmt.Sprintf("%s → stream ended after %s, %s sent, %s received", t.label,
				time.Since(t.started).Round(time.Second), sizeOf(t.in.Load()), sizeOf(t.out.Load())))
		}
	})
	return t.rwc.Close()
}

// sizeOf reads a byte count the way a person does.
func sizeOf(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// writeStatus answers as the API does, a Status object, so kubectl prints the
// sentence: "Error from server (Forbidden): Zanskar: ...".
func writeStatus(w http.ResponseWriter, code int, reason, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"kind": "Status", "apiVersion": "v1", "metadata": map[string]any{},
		"status": "Failure", "message": msg, "reason": reason, "code": code,
	})
}

// WriteUnauthorized answers a request whose token names no open session.
func WriteUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="zanskar"`)
	writeStatus(w, http.StatusUnauthorized, "Unauthorized", "Zanskar: this session has ended or the token is not its own")
}

// Sessions holds the open kube sessions by id, for the one route that serves
// them all.
type Sessions struct {
	mu   sync.Mutex
	open map[string]*Session
}

// NewSessions returns an empty store.
func NewSessions() *Sessions { return &Sessions{open: map[string]*Session{}} }

// Add holds the session until Remove.
func (ss *Sessions) Add(s *Session) {
	ss.mu.Lock()
	ss.open[s.ID] = s
	ss.mu.Unlock()
}

// Remove forgets the session and closes it.
func (ss *Sessions) Remove(id string) {
	ss.mu.Lock()
	s := ss.open[id]
	delete(ss.open, id)
	ss.mu.Unlock()
	if s != nil {
		s.Close()
	}
}

// Get returns the open session with the id, when bearer is its token.
func (ss *Sessions) Get(id, bearer string) (*Session, bool) {
	ss.mu.Lock()
	s := ss.open[id]
	ss.mu.Unlock()
	if s == nil || !s.Authenticate(bearer) {
		return nil, false
	}
	return s, true
}

// Len is how many sessions are open.
func (ss *Sessions) Len() int {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return len(ss.open)
}

// Bearer reads the session token of a request; "" when it carries none. The
// token travels in the Authorization header only, never in the URL.
func Bearer(r *http.Request) string {
	v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !strings.HasPrefix(v, TokenPrefix) {
		return ""
	}
	return strings.TrimSpace(v)
}
