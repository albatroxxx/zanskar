// SPDX-License-Identifier: Apache-2.0

package tlscert

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

// TestNamesFor (ADR 0021, amended 2026-10-30): only DNS names are ordered,
// the public URL's host and the configured TLS hosts, never an IP address, a
// bare word or localhost, once each.
func TestNamesFor(t *testing.T) {
	got := NamesFor("Zanskar.Example.com", []string{"10.0.0.5", "gw", "localhost", "a.localhost", "zanskar.example.com", "alt.example.com", " ", "bad_name.example.com"})
	if want := []string{"zanskar.example.com", "alt.example.com"}; !slices.Equal(got, want) {
		t.Fatalf("names %q, want %q", got, want)
	}
	if got := NamesFor("", nil); len(got) != 0 {
		t.Fatalf("no public URL, no names: %q", got)
	}
}

// acmeManager is a Manager serving a self-signed certificate, with ACME on
// for gw.example.com against directory.
func acmeManager(t *testing.T, directory string, on *atomic.Bool) *Manager {
	t.Helper()
	repo, _ := newRepo(t)
	m := &Manager{Repo: repo, Hosts: []string{"gw.example.com"}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := m.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.ACME = &ACME{
		Names:    []string{"gw.example.com"},
		Settings: func() (bool, string, string) { return on.Load(), "ops@example.com", directory },
		Cache:    DBCache{Repo: repo},
		Log:      m.Log,
	}
	return m
}

// TestACMEFallsBackAndBacksOff: off, or for a name it does not cover, the
// active certificate serves; on, a CA that fails leaves the self-signed one
// serving instead of failing the handshake, and the name is not tried again
// on every handshake (the CA's rate limits).
func TestACMEFallsBackAndBacksOff(t *testing.T) {
	var asked atomic.Int32
	ca := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer ca.Close()
	var on atomic.Bool
	m := acmeManager(t, ca.URL+"/dir", &on)
	self := m.Active().Fingerprint
	serve := func(name string) string {
		c, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: name})
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		return describe("", leaf, "").Fingerprint
	}
	if serve("gw.example.com") != self || asked.Load() != 0 {
		t.Fatalf("off: asked the CA %d times", asked.Load())
	}
	on.Store(true)
	if serve("other.example.com") != self || asked.Load() != 0 {
		t.Fatalf("an uncovered name asked the CA %d times", asked.Load())
	}
	// The CA answers 503, which the ACME client retries for minutes: the
	// handshake must not wait for that (2026-10-30, found by this test).
	m.ACME.Wait = 200 * time.Millisecond
	start := time.Now()
	if serve("gw.example.com") != self {
		t.Fatal("a covered name must fall back while the CA fails")
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("a handshake waited %s for a failing CA", took)
	}
	// The order runs on in the background; on a loaded runner it can reach
	// the CA after the handshake has fallen back (CI, 2026-10-31).
	for end := time.Now().Add(10 * time.Second); asked.Load() == 0 && time.Now().Before(end); {
		time.Sleep(20 * time.Millisecond)
	}
	if asked.Load() == 0 {
		t.Fatal("a covered name must try the CA")
	}
	// While that order runs, another handshake falls back at once rather
	// than starting a second order.
	start = time.Now()
	if serve("gw.example.com") != self || time.Since(start) > time.Second {
		t.Fatal("a second handshake during an order must fall back at once")
	}
	if st := m.ACME.Status(); !st.On {
		t.Fatalf("status: %+v", st)
	}
}

// TestUploadWinsOverACME: an uploaded certificate serves every name, the
// ACME one included, and its order is never placed.
func TestUploadWinsOverACME(t *testing.T) {
	var asked atomic.Int32
	ca := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { asked.Add(1) }))
	defer ca.Close()
	var on atomic.Bool
	on.Store(true)
	m := acmeManager(t, ca.URL+"/dir", &on)
	certPEM, keyPEM := certFor(t, "gw.example.com", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if _, err := m.Upload(context.Background(), certPEM, keyPEM, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "gw.example.com"}); err != nil {
		t.Fatal(err)
	}
	if asked.Load() != 0 || m.Active().Source != SourceUploaded {
		t.Fatalf("asked the CA %d times; serving %s", asked.Load(), m.Active().Source)
	}
}

// TestACMECacheOnEachBackend: the account and certificates autocert keeps
// are sealed in tls_certificates and come back; a miss is autocert's miss.
func TestACMECacheOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		kek, err := crypto.NewLocalKEK(bytes.Repeat([]byte{5}, 32))
		if err != nil {
			t.Fatal(err)
		}
		ring, err := keyring.Open(ctx, db, kek)
		if err != nil {
			t.Fatal(err)
		}
		defer ring.Close()
		c := DBCache{Repo: NewRepo(db, ring)}
		if _, err := c.Get(ctx, "acme_account+key"); !errors.Is(err, autocert.ErrCacheMiss) {
			t.Fatalf("miss: %v", err)
		}
		for _, v := range []string{"-----BEGIN EC PRIVATE KEY-----\nAAA\n", "second"} {
			if err := c.Put(ctx, "acme_account+key", []byte(v)); err != nil {
				t.Fatal(err)
			}
			got, err := c.Get(ctx, "acme_account+key")
			if err != nil || string(got) != v {
				t.Fatalf("round trip: %q %v", got, err)
			}
		}
		var stored []byte
		if err := db.QueryRowContext(ctx, db.Rebind(`SELECT data_enc FROM acme_cache WHERE cache_key = ?`), "acme_account+key").Scan(&stored); err != nil || bytes.Contains(stored, []byte("second")) {
			t.Fatalf("the cache must be sealed: %q %v", stored, err)
		}
		if err := c.Delete(ctx, "acme_account+key"); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Get(ctx, "acme_account+key"); !errors.Is(err, autocert.ErrCacheMiss) {
			t.Fatalf("after delete: %v", err)
		}
	})
}

// TestACMEOrdersFromPebble orders a real certificate from Pebble, Let's
// Encrypt's test CA, in a container with validation stubbed: the gateway
// serves it for its name, says so in its status, and a second gateway on the
// same database serves it from the cache without ordering again. Needs
// Docker (ZANSKAR_TEST_DOCKER=1); never the real Let's Encrypt.
func TestACMEOrdersFromPebble(t *testing.T) {
	if os.Getenv("ZANSKAR_TEST_DOCKER") != "1" {
		t.Skip("needs Docker: set ZANSKAR_TEST_DOCKER=1")
	}
	name := fmt.Sprintf("zanskar-pebble-%d", time.Now().UnixNano())
	// A random host port, or a fixed one where Docker runs in a VM whose
	// ports are forwarded by hand (Colima): ZANSKAR_TEST_PEBBLE_PORT.
	publish := "14000"
	if p := os.Getenv("ZANSKAR_TEST_PEBBLE_PORT"); p != "" {
		publish = p + ":14000"
	}
	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name, "-e", "PEBBLE_VA_ALWAYS_VALID=1", "-e", "PEBBLE_VA_NOSLEEP=1",
		"-p", publish, "ghcr.io/letsencrypt/pebble:2.7.0@sha256:c156cabea562e43ed0060bddc03539c07de40e311b52c6b0e5ea710a496e56b8").CombinedOutput()
	if err != nil {
		t.Fatalf("pebble: %v %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	portOut, err := exec.Command("docker", "port", name, "14000/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(strings.TrimSpace(strings.Split(string(portOut), "\n")[0]))
	directory := "https://127.0.0.1:" + port + "/dir"
	// Pebble's own CA signs its API; only this test trusts it.
	insecure := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // #nosec G402 -- Pebble's test CA, in a test
	deadline := time.Now().Add(30 * time.Second)
	for {
		if resp, err := insecure.Get(directory); err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pebble did not start")
		}
		time.Sleep(200 * time.Millisecond)
	}

	repo, _ := newRepo(t)
	var on atomic.Bool
	on.Store(true)
	gateway := func() *Manager {
		m := &Manager{Repo: repo, Hosts: []string{"gw.example.com"}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
		if err := m.Load(context.Background()); err != nil {
			t.Fatal(err)
		}
		m.ACME = &ACME{Names: []string{"gw.example.com"}, Settings: func() (bool, string, string) { return on.Load(), "ops@example.com", directory },
			Cache: DBCache{Repo: repo}, HTTPClient: insecure, Log: m.Log}
		return m
	}
	first := gateway()
	c, err := first.GetCertificate(&tls.ClientHelloInfo{ServerName: "gw.example.com", SupportedProtos: []string{"h2", "http/1.1"}, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(leaf.DNSNames, "gw.example.com") || !strings.Contains(leaf.Issuer.CommonName, "Pebble") {
		t.Fatalf("ordered %v from %q", leaf.DNSNames, leaf.Issuer.CommonName)
	}
	if st := first.ACME.Status(); st.NotAfter.IsZero() || st.LastError != "" {
		t.Fatalf("status: %+v", st)
	}
	// A second gateway on the same database reads it from the cache.
	second := gateway()
	second.ACME.Settings = func() (bool, string, string) { return true, "ops@example.com", "https://127.0.0.1:1/unreachable" }
	c2, err := second.GetCertificate(&tls.ClientHelloInfo{ServerName: "gw.example.com", SupportedProtos: []string{"http/1.1"}, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}})
	if err != nil || !bytes.Equal(c2.Certificate[0], c.Certificate[0]) {
		t.Fatalf("the second gateway ordered again or failed: %v", err)
	}
	if !challenge(&tls.ClientHelloInfo{SupportedProtos: []string{acme.ALPNProto}}) {
		t.Fatal("a TLS-ALPN-01 hello is a challenge")
	}
}
