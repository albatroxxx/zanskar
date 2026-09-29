// SPDX-License-Identifier: Apache-2.0

package tlscert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

func newRepo(t *testing.T) (*Repo, *store.DB) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	kek, _ := crypto.NewLocalKEK(bytes.Repeat([]byte{5}, 32))
	ring, err := keyring.Open(ctx, db, kek)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ring.Close)
	return NewRepo(db, ring), db
}

// certFor makes a certificate signed by its own key, with the given
// validity, for tests of the upload rules.
func certFor(t *testing.T, cn string, notBefore, notAfter time.Time, eku []x509.ExtKeyUsage) (certPEM, keyPEM string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: cn}, NotBefore: notBefore, NotAfter: notAfter, DNSNames: []string{cn}, ExtKeyUsage: eku}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}))
}

// TestPrecedenceAndSwap: a fresh manager generates a self-signed
// certificate for the hosts it was given and seals its key; an upload takes
// over on the next handshake with no restart; reset falls back to the
// generated one; a reloaded manager sees the stored state; a file
// certificate sits between the two.
func TestPrecedenceAndSwap(t *testing.T) {
	ctx := context.Background()
	repo, db := newRepo(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := &Manager{Repo: repo, Log: log, Hosts: []string{"gw.example.test", "10.0.0.5"}}
	if err := m.Load(ctx); err != nil {
		t.Fatal(err)
	}
	a := m.Active()
	if a.Source != SourceGenerated || !a.SelfSigned || strings.Join(a.Hosts, ",") != "10.0.0.5,gw.example.test" || a.Fingerprint == "" {
		t.Fatalf("generated: %+v", a)
	}
	var stored []byte
	if err := db.QueryRowContext(ctx, `SELECT key_enc FROM tls_certificates WHERE kind = 'generated'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte("PRIVATE KEY")) {
		t.Fatal("the stored key must be sealed, not PEM")
	}
	first, err := m.GetCertificate(nil)
	if err != nil || first.Leaf == nil || first.Leaf.Subject.CommonName != "Zanskar gateway" {
		t.Fatalf("GetCertificate: %v", err)
	}

	certPEM, keyPEM := certFor(t, "real.example.test", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if info, err := m.Upload(ctx, certPEM, keyPEM, ""); err != nil || info.Source != SourceUploaded || info.Subject != "CN=real.example.test" {
		t.Fatalf("upload: %+v %v", info, err)
	}
	if c, _ := m.GetCertificate(nil); c.Leaf.Subject.CommonName != "real.example.test" {
		t.Fatal("the upload must serve on the next handshake")
	}
	again := &Manager{Repo: repo, Log: log, Hosts: []string{"x"}}
	if err := again.Load(ctx); err != nil || again.Active().Source != SourceUploaded {
		t.Fatalf("reload: %+v %v", again.Active(), err)
	}
	if info, err := m.Reset(ctx); err != nil || info.Source != SourceGenerated || info.Fingerprint != a.Fingerprint {
		t.Fatalf("reset must fall back to the same generated certificate: %+v %v", info, err)
	}

	fileCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	withFile := &Manager{Repo: repo, Log: log, File: &fileCert}
	if err := withFile.Load(ctx); err != nil || withFile.Active().Source != SourceFile {
		t.Fatalf("file precedence: %+v %v", withFile.Active(), err)
	}
	if _, err := withFile.Upload(ctx, certPEM, keyPEM, ""); err != nil || withFile.Active().Source != SourceUploaded {
		t.Fatal("upload beats file")
	}
	if err := withFile.Regenerate(ctx, []string{"new.example.test"}, ""); err != nil || withFile.Active().Source != SourceUploaded {
		t.Fatal("regenerating must not displace the uploaded certificate")
	}
	if g, err := withFile.Generated(ctx); err != nil || g.Hosts[0] != "new.example.test" {
		t.Fatalf("generated stored: %+v %v", g, err)
	}
}

// TestParseRefusals: mismatched key, expired leaf, not-yet-valid leaf,
// encrypted key, a leaf without server authentication, and garbage.
func TestParseRefusals(t *testing.T) {
	good, goodKey := certFor(t, "a", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), nil)
	_, otherKey := certFor(t, "b", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), nil)
	expired, expiredKey := certFor(t, "c", time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour), nil)
	future, futureKey := certFor(t, "d", time.Now().Add(time.Hour), time.Now().Add(48*time.Hour), nil)
	client, clientKey := certFor(t, "e", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	encrypted := "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB\n-----END ENCRYPTED PRIVATE KEY-----\n"
	cases := []struct{ name, cert, key, want string }{
		{"mismatch", good, otherKey, "private key does not match"},
		{"expired", expired, expiredKey, "expired"},
		{"future", future, futureKey, "not valid before"},
		{"encrypted", good, encrypted, "encrypted"},
		{"client-only", client, clientKey, "server authentication"},
		{"garbage", "hello", "world", "invalid"},
	}
	for _, c := range cases {
		_, _, err := Parse(c.cert, c.key)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (want %q)", c.name, err, c.want)
		}
	}
	if _, _, err := Parse(good, goodKey); err != nil {
		t.Fatal(err)
	}
}

// TestRoutes: the status shows the sources; upload applies and is audited
// with the fingerprint and never the key; a user is refused; proxy mode
// refuses management with a 409.
func TestRoutes(t *testing.T) {
	ctx := context.Background()
	repo, db := newRepo(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := user.NewRepo(db)
	sessions := auth.NewSessions(db, bytes.Repeat([]byte{6}, 32), false)
	auditLog := audit.NewLog(db)
	m := &Manager{Repo: repo, Log: log, Hosts: []string{"gw"}}
	if err := m.Load(ctx); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	(&Handler{Manager: m, Mode: "managed", Audit: auditLog, Log: log}).Register(mux)
	proxyMux := http.NewServeMux()
	(&Handler{Mode: "proxy", Audit: auditLog, Log: log}).Register(proxyMux)
	mw := &auth.Middleware{Sessions: sessions, Users: users, Log: log}
	srv, proxySrv := mw.Authenticate(mw.CSRF(mux)), mw.Authenticate(mw.CSRF(proxyMux))
	login := func(name string, role user.Role) (*http.Cookie, string) {
		u := &user.User{Username: name, DisplayName: name, Roles: []user.Role{role}}
		if err := users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		tok, sess, err := sessions.Create(ctx, u.ID, "203.0.113.9", "test", true)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: auth.CookieName, Value: tok}, sessions.CSRFToken(sess.ID)
	}
	admin, aCSRF := login("root", user.RoleAdmin)
	plain, pCSRF := login("alice", user.RoleUser)
	do := func(h http.Handler, method, path string, body any, cookie *http.Cookie, csrf string) (int, map[string]any, string) {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, path, &buf)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		req.RemoteAddr = "203.0.113.9:4321"
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out, rr.Body.String()
	}
	code, out, raw := do(srv, "GET", "/api/v1/admin/tls", nil, admin, aCSRF)
	if code != 200 || out["mode"] != "managed" || out["active"].(map[string]any)["source"] != SourceGenerated || strings.Contains(raw, "PRIVATE KEY") {
		t.Fatalf("status: %d %s", code, raw)
	}
	if code, _, _ := do(srv, "GET", "/api/v1/admin/tls", nil, plain, pCSRF); code != 403 {
		t.Fatalf("user: %d", code)
	}
	certPEM, keyPEM := certFor(t, "real.example.test", time.Now().Add(-time.Hour), time.Now().Add(400*24*time.Hour), nil)
	if code, out, _ := do(srv, "PUT", "/api/v1/admin/tls", map[string]string{"cert_pem": certPEM, "key_pem": "nope"}, admin, aCSRF); code != 400 {
		t.Fatalf("bad key: %d %v", code, out)
	}
	code, out, raw = do(srv, "PUT", "/api/v1/admin/tls", map[string]string{"cert_pem": certPEM, "key_pem": keyPEM}, admin, aCSRF)
	if code != 200 || out["active"].(map[string]any)["source"] != SourceUploaded || strings.Contains(raw, "PRIVATE KEY") {
		t.Fatalf("upload: %d %s", code, raw)
	}
	if code, out, _ := do(srv, "POST", "/api/v1/admin/tls/self-signed", map[string]any{"hosts": []string{"gw.example.test"}}, admin, aCSRF); code != 200 || out["active"].(map[string]any)["source"] != SourceUploaded {
		t.Fatalf("regenerate keeps the upload active: %d %v", code, out)
	}
	if code, out, _ := do(srv, "DELETE", "/api/v1/admin/tls", nil, admin, aCSRF); code != 200 || out["active"].(map[string]any)["source"] != SourceGenerated {
		t.Fatalf("reset: %d %v", code, out)
	}
	if code, out, _ := do(proxySrv, "PUT", "/api/v1/admin/tls", map[string]string{"cert_pem": certPEM, "key_pem": keyPEM}, admin, aCSRF); code != 409 || out["code"] != "tls_proxy" {
		t.Fatalf("proxy mode: %d %v", code, out)
	}
	events, _, err := auditLog.List(ctx, audit.Filter{ObjectType: "tls_certificate"})
	if err != nil || len(events) != 3 {
		t.Fatalf("audit: %d %v", len(events), err)
	}
	for _, ev := range events {
		if strings.Contains(string(ev.Details), "PRIVATE") {
			t.Fatal("audit must not carry key material")
		}
	}
}

// TestLocalHosts: a bound address is included; wildcard binds add the
// machine's addresses; localhost is always present.
func TestLocalHosts(t *testing.T) {
	hosts := LocalHosts("10.1.2.3:443")
	if hosts[0] != "localhost" || hosts[len(hosts)-1] != "10.1.2.3" {
		t.Fatalf("bound: %v", hosts)
	}
	if h := LocalHosts(":443"); len(h) < 2 {
		t.Fatalf("wildcard: %v", h)
	}
}

// TestListenerSwapsWithoutRestart: a TLS listener that asks the manager per
// handshake serves the self-signed certificate, then the uploaded one on
// the very next connection, then the self-signed one again after a reset,
// while the server never stops.
func TestListenerSwapsWithoutRestart(t *testing.T) {
	ctx := context.Background()
	repo, _ := newRepo(t)
	m := &Manager{Repo: repo, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Hosts: []string{"127.0.0.1"}}
	if err := m.Load(ctx); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }), TLSConfig: &tls.Config{GetCertificate: m.GetCertificate, MinVersion: tls.VersionTLS12}, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	leafCN := func() string {
		conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		return conn.ConnectionState().PeerCertificates[0].Subject.CommonName
	}
	if cn := leafCN(); cn != "Zanskar gateway" {
		t.Fatalf("first: %q", cn)
	}
	certPEM, keyPEM := certFor(t, "uploaded.example.test", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), nil)
	if _, err := m.Upload(ctx, certPEM, keyPEM, ""); err != nil {
		t.Fatal(err)
	}
	if cn := leafCN(); cn != "uploaded.example.test" {
		t.Fatalf("after upload: %q", cn)
	}
	if _, err := m.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	if cn := leafCN(); cn != "Zanskar gateway" {
		t.Fatalf("after reset: %q", cn)
	}
}
