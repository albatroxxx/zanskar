// SPDX-License-Identifier: Apache-2.0

package winrmgw

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/masterzen/winrm"
	"github.com/masterzen/winrm/soap"
)

func TestPinnedTransportAcceptsOnlyThePinnedCert(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "svc" || p != "pw" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
		_, _ = w.Write([]byte("<s:Envelope/>"))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	leaf := srv.Certificate()
	sum := sha256.Sum256(leaf.Raw)
	good := hex.EncodeToString(sum[:])

	ep := &winrm.Endpoint{Host: u.Hostname(), Port: port, HTTPS: true, Timeout: 5 * time.Second}

	pt, err := newPinnedTransport(u.Hostname(), port, "svc", "pw", good, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := pt.Transport(ep); err != nil {
		t.Fatal(err)
	}
	body, err := pt.Post(nil, soap.NewMessage())
	if err != nil || body != "<s:Envelope/>" {
		t.Fatalf("pinned post: %q %v", body, err)
	}

	// Wrong pin: the TLS handshake must fail before any request is sent.
	bad := hex.EncodeToString(make([]byte, sha256.Size))
	pt2, _ := newPinnedTransport(u.Hostname(), port, "svc", "pw", bad, false)
	_ = pt2.Transport(ep)
	if _, err := pt2.Post(nil, soap.NewMessage()); err == nil || !errors.Is(err, ErrCertMismatch) {
		t.Fatalf("expected ErrCertMismatch, got %v", err)
	}

	// Malformed pin is rejected up front.
	if _, err := newPinnedTransport("h", 1, "u", "p", "nothex", false); err == nil {
		t.Fatal("expected bad fingerprint error")
	}
	// Colon-separated upper-case fingerprints are normalised.
	colon := ""
	for i := 0; i < len(good); i += 2 {
		if i > 0 {
			colon += ":"
		}
		colon += good[i : i+2]
	}
	if _, err := newPinnedTransport("h", 1, "u", "p", colon, false); err != nil {
		t.Fatalf("colon form rejected: %v", err)
	}
}
