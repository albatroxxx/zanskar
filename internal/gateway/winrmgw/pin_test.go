// SPDX-License-Identifier: Apache-2.0

package winrmgw

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
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

// TestFaultSummaryFindsAccessDenied uses the shape Windows Server 2022 returns
// when a credential authenticates and is then refused a WinRS shell: an HTTP 500
// carrying a WSManFault, whose code and message sit well past the namespace
// declarations. Truncating the envelope hid it, so the gateway reported a
// generic connection failure (manual QA on a domain-joined instance).
func TestFaultSummaryFindsAccessDenied(t *testing.T) {
	body := []byte(`<s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" ` +
		`xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" ` +
		`xmlns:e="http://schemas.xmlsoap.org/ws/2004/08/eventing" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" ` +
		`xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" ` +
		`xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault"><s:Body><s:Fault><s:Code>` +
		`<s:Value>s:Sender</s:Value></s:Code><s:Reason><s:Text xml:lang="">Access is denied.</s:Text></s:Reason>` +
		`<s:Detail><f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="5" Machine="host">` +
		`<f:Message>Access is denied. </f:Message></f:WSManFault></s:Detail></s:Fault></s:Body></s:Envelope>`)
	got := faultSummary(body)
	if !strings.Contains(got, "wsman fault 5") || !strings.Contains(got, "Access is denied") {
		t.Fatalf("summary lost the fault: %q", got)
	}
	if len(body) < 300 {
		t.Fatal("test body must be long enough that a prefix would hide the fault")
	}
	if !notAuthorized(fmt.Errorf("winrmgw: http 500: %s", got)) {
		t.Fatalf("an access-denied fault must be recognised: %q", got)
	}
	// A plain authentication failure must not be mistaken for it.
	if notAuthorized(errors.New("winrmgw: http 401: ")) {
		t.Fatal("401 is an authentication failure, not an authorization one")
	}
	// A body with no fault at all still produces something readable.
	if s := faultSummary([]byte("<html>Service Unavailable</html>")); !strings.Contains(s, "Service Unavailable") {
		t.Fatalf("fallback summary: %q", s)
	}
}
