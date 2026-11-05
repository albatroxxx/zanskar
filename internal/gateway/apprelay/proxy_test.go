// SPDX-License-Identifier: Apache-2.0

package apprelay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type resolverFunc func(ctx context.Context, host string) ([]net.IPAddr, error)

func (f resolverFunc) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f(ctx, host)
}

// echoOrigin answers with what it saw: the method, the path, the Host
// header and whether the request came over TLS.
func echoOrigin(t *testing.T, secure bool) *httptest.Server {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
			if err != nil {
				return
			}
			defer c.CloseNow()
			typ, msg, err := c.Read(r.Context())
			if err != nil {
				return
			}
			_ = c.Write(r.Context(), typ, append([]byte("echo: "), msg...))
			return
		}
		_, _ = fmt.Fprintf(w, "%s %s host=%s tls=%v fwd=%q", r.Method, r.URL.Path, r.Host, r.TLS != nil, r.Header.Get("X-Forwarded-For"))
	})
	if secure {
		s := httptest.NewTLSServer(h)
		t.Cleanup(s.Close)
		return s
	}
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s
}

// logBuf collects the relay's JSON log lines.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) lines(msg string) []map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []map[string]any
	for line := range strings.SplitSeq(l.b.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

// proxyRig serves a relay whose proxy routes example.com:443 to origin,
// trusts httptest's certificate for everything (every test server presents
// it), resolves every name to 127.0.0.1 and classifies 127.0.0.1 as
// classify says. The returned client goes through the proxy trusting the
// session's CA, as the browser does.
type proxyRig struct {
	proxyURL *url.URL
	client   *http.Client
	caPool   *x509.CertPool
	log      *logBuf
	dialled  func() []string
}

func newProxyRig(t *testing.T, origin *httptest.Server, classify func(net.IP) string, tweak func(*Proxy)) *proxyRig {
	t.Helper()
	caCert, caKey, err := NewSessionCA("test session")
	if err != nil {
		t.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM([]byte(caCert))
	testCert := origin.Certificate()
	bundle := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testCert.Raw}))
	roots := x509.NewCertPool()
	roots.AddCert(testCert)
	port := freePort(t)
	_, oport, _ := net.SplitHostPort(origin.Listener.Addr().String())
	cfg := &Proxy{Listen: "internal:" + strconv.Itoa(port), CACert: caCert, CAKey: caKey, TLSCA: bundle, Name: "Wiki",
		Allow: []Route{{Host: "example.com", Port: 443, To: "127.0.0.1:" + oport}}}
	if tweak != nil {
		tweak(cfg)
	}
	lb := &logBuf{}
	var mu sync.Mutex
	var dials []string
	r := &Relay{
		Config: Config{Proxy: cfg}, Log: slog.New(slog.NewJSONHandler(lb, &slog.HandlerOptions{Level: slog.LevelDebug})), InternalIP: "127.0.0.1",
		Resolver: resolverFunc(func(_ context.Context, host string) ([]net.IPAddr, error) {
			if strings.HasSuffix(host, ".gone") {
				return nil, fmt.Errorf("no such host")
			}
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		}),
		Classify: classify, Roots: roots,
		Dial: func(ctx context.Context, to string) (net.Conn, error) {
			mu.Lock()
			dials = append(dials, to)
			mu.Unlock()
			return (&net.Dialer{}).DialContext(ctx, "tcp", to)
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = r.Serve(ctx) }()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	waitListening(t, addr)
	pu, _ := url.Parse("http://" + addr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &proxyRig{proxyURL: pu, client: client, caPool: caPool, log: lb, dialled: func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), dials...)
	}}
}

func public(net.IP) string { return "" }

// get sends a request through the proxy with the headers given, as the
// browser would, and returns the status and body.
func (pr *proxyRig) get(t *testing.T, rawURL string, hdr map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, rawURL, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := pr.client.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

var (
	document = map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
	iframe   = map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "iframe", "Referer": "https://example.com/page"}
	script   = map[string]string{"Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "script", "Referer": "https://example.com/page"}
)

// TestProxyPagesAtOriginsDependenciesAnywhere (ADR 0037, amended
// 2026-11-03, later): a page opens at the application's origin, reached at
// its pinned address over TLS the relay verifies, with the browser's Host
// header and nothing added; a script, a fetch or a frame from a public host
// on any port goes through; a page anywhere else gets the relay's own
// blocked page, which names the application.
func TestProxyPagesAtOriginsDependenciesAnywhere(t *testing.T) {
	origin := echoOrigin(t, true)
	pub := echoOrigin(t, true)
	pr := newProxyRig(t, origin, public, nil)
	code, body := pr.get(t, "https://example.com/page?x=1", document)
	if code != 200 || !strings.Contains(body, "GET /page host=example.com tls=true fwd=\"\"") {
		t.Fatalf("origin page: %d %q", code, body)
	}
	pubURL := "https://" + pub.Listener.Addr().String()
	for _, hdr := range []map[string]string{script, iframe, {"Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Origin": "https://example.com"}} {
		if code, body := pr.get(t, pubURL+"/dep.js", hdr); code != 200 || !strings.Contains(body, "GET /dep.js") {
			t.Fatalf("%v: %d %q", hdr, code, body)
		}
	}
	code, body = pr.get(t, pubURL+"/", document)
	if code != 403 || !strings.Contains(body, "This page is blocked") || !strings.Contains(body, "<strong>Wiki</strong>") {
		t.Fatalf("a page elsewhere: %d %q", code, body)
	}
	// The pinned address was dialled for the origin, the checked one for the public host.
	_, oport, _ := net.SplitHostPort(origin.Listener.Addr().String())
	if d := pr.dialled(); len(d) == 0 || d[0] != "127.0.0.1:"+oport {
		t.Fatalf("dialled %v", d)
	}
	refused := pr.log.lines("apprelay refused")
	if len(refused) != 1 || refused[0]["why"] != "not an origin of the application" || refused[0]["what"] != "document" {
		t.Fatalf("refusal lines: %v", refused)
	}
}

// TestProxyLeafCertificates: the relay presents, for each host, a leaf
// signed by the session's CA that names that host, and the same one again.
func TestProxyLeafCertificates(t *testing.T) {
	pr := newProxyRig(t, echoOrigin(t, true), public, nil)
	see := func(host string) *x509.Certificate {
		c, err := net.Dial("tcp", pr.proxyURL.Host)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, _ = fmt.Fprintf(c, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", host, host)
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("connect %s: %v %v", host, err, resp)
		}
		_ = resp.Body.Close()
		tc := tls.Client(c, &tls.Config{ServerName: host, RootCAs: pr.caPool, MinVersion: tls.VersionTLS12})
		if err := tc.Handshake(); err != nil {
			t.Fatalf("handshake %s: %v", host, err)
		}
		return tc.ConnectionState().PeerCertificates[0]
	}
	a, b := see("example.com"), see("example.com")
	if a.DNSNames[0] != "example.com" || !bytes.Equal(a.Raw, b.Raw) || a.Issuer.CommonName != "test session" {
		t.Fatalf("leaf: %v issuer %v same=%v", a.DNSNames, a.Issuer.CommonName, bytes.Equal(a.Raw, b.Raw))
	}
	if c := see("cdn.example"); c.DNSNames[0] != "cdn.example" {
		t.Fatalf("another host's leaf: %v", c.DNSNames)
	}
}

// TestProxyTunnelKeepsAlive: a tunnel carries request after request, as a
// browser sends them, and is not cut at the first one's end.
func TestProxyTunnelKeepsAlive(t *testing.T) {
	pr := newProxyRig(t, echoOrigin(t, true), public, nil)
	c, err := net.Dial("tcp", pr.proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = fmt.Fprintf(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("connect: %v %v", err, resp)
	}
	_ = resp.Body.Close()
	tc := tls.Client(c, &tls.Config{ServerName: "example.com", RootCAs: pr.caPool, MinVersion: tls.VersionTLS12})
	br := bufio.NewReader(tc)
	for i := range 3 {
		_, _ = fmt.Fprintf(tc, "GET /n%d HTTP/1.1\r\nHost: example.com\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: document\r\n\r\n", i)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("request %d on the tunnel: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(body), fmt.Sprintf("GET /n%d ", i)) {
			t.Fatalf("request %d: %d %q", i, resp.StatusCode, body)
		}
	}
}

// TestProxyPlainHTTP: a plain destination gets no fetch metadata from the
// browser, so a GET that asks for HTML is a page and anything else a
// dependency; the request reaches the origin whole, by its pinned address.
func TestProxyPlainHTTP(t *testing.T) {
	origin := echoOrigin(t, false)
	pub := echoOrigin(t, false)
	_, oport, _ := net.SplitHostPort(origin.Listener.Addr().String())
	pr := newProxyRig(t, echoOrigin(t, true), public, func(p *Proxy) {
		p.Allow = append(p.Allow, Route{Host: "plain.corp", Port: 80, To: "127.0.0.1:" + oport})
	})
	html := map[string]string{"Accept": "text/html,application/xhtml+xml", "Upgrade-Insecure-Requests": "1"}
	if code, body := pr.get(t, "http://plain.corp/home", html); code != 200 || !strings.Contains(body, "GET /home host=plain.corp tls=false") {
		t.Fatalf("plain origin page: %d %q", code, body)
	}
	pubURL := "http://" + pub.Listener.Addr().String()
	if code, body := pr.get(t, pubURL+"/pic.png", map[string]string{"Accept": "image/avif,image/webp,*/*"}); code != 200 || !strings.Contains(body, "GET /pic.png") {
		t.Fatalf("plain public image: %d %q", code, body)
	}
	if code, body := pr.get(t, pubURL+"/", html); code != 403 || !strings.Contains(body, "This page is blocked") {
		t.Fatalf("plain page elsewhere: %d %q", code, body)
	}
}

// TestProxyPrivateDependencies: a dependency on a private address is
// refused and said in the log with what asked and from where; allowed by
// host:port or by network it goes through; an address that is never
// allowable stays refused however it is listed.
func TestProxyPrivateDependencies(t *testing.T) {
	pub := echoOrigin(t, true)
	pubURL := "https://" + pub.Listener.Addr().String()
	private := func(net.IP) string { return "private" }
	pr := newProxyRig(t, echoOrigin(t, true), private, nil)
	if code, body := pr.get(t, pubURL+"/x.js", script); code != 403 || !strings.Contains(body, "private") {
		t.Fatalf("private, unlisted: %d %q", code, body)
	}
	lines := pr.log.lines("apprelay refused")
	if len(lines) != 1 || lines[0]["why"] != "private" || lines[0]["what"] != "script" || lines[0]["from"] != "https://example.com" || lines[0]["port"] == "" {
		t.Fatalf("refusal line: %v", lines)
	}
	// Said once, then counted: a second ask within the minute adds no line.
	pr.get(t, pubURL+"/x.js", script)
	if n := len(pr.log.lines("apprelay refused")); n != 1 {
		t.Fatalf("a repeat was said again: %d lines", n)
	}
	byHost := newProxyRig(t, echoOrigin(t, true), private, func(p *Proxy) { p.PrivateHosts = []string{pub.Listener.Addr().String()} })
	if code, body := byHost.get(t, pubURL+"/x.js", script); code != 200 || !strings.Contains(body, "GET /x.js") {
		t.Fatalf("private, allowed by host: %d %q", code, body)
	}
	byNet := newProxyRig(t, echoOrigin(t, true), private, func(p *Proxy) { p.PrivateNetworks = []string{"127.0.0.0/8"} })
	if code, _ := byNet.get(t, pubURL+"/x.js", script); code != 200 {
		t.Fatalf("private, allowed by network: %d", code)
	}
	// A private frame, a private page: the frame goes through, the page does not.
	if code, _ := byNet.get(t, pubURL+"/frame", iframe); code != 200 {
		t.Fatalf("private frame: %d", code)
	}
	if code, _ := byNet.get(t, pubURL+"/", document); code != 403 {
		t.Fatalf("private page: %d", code)
	}
	never := newProxyRig(t, echoOrigin(t, true), func(net.IP) string { return "link-local" }, func(p *Proxy) {
		p.PrivateHosts = []string{pub.Listener.Addr().String()}
		p.PrivateNetworks = []string{"127.0.0.0/8"}
	})
	if code, body := never.get(t, pubURL+"/x.js", script); code != 403 || !strings.Contains(body, "link-local") {
		t.Fatalf("link-local, listed: %d %q", code, body)
	}
}

// TestProxyRefusedPageIsTheBlockPage (live, 2026-11-05): a page typed at a
// private address was answered with the bare text "Zanskar: private", where
// a public address that is not an endpoint got the block page. Both get the
// block page now, the private one saying why; a script still gets the bare
// 403. The browser's own request for /favicon.ico after the refused page is
// not a refusal of its own: the live list showed one visit as two rows.
func TestProxyRefusedPageIsTheBlockPage(t *testing.T) {
	pub := echoOrigin(t, true)
	pubURL := "https://" + pub.Listener.Addr().String()
	pr := newProxyRig(t, echoOrigin(t, true), func(net.IP) string { return "private" }, nil)
	code, body := pr.get(t, pubURL+"/", document)
	if code != 403 || !strings.Contains(body, "This page is blocked") || !strings.Contains(body, "private address") || strings.Contains(body, "may still load") {
		t.Fatalf("private page: %d %q", code, body)
	}
	icon := map[string]string{"Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image"}
	if code, _ := pr.get(t, pubURL+"/favicon.ico", icon); code != 403 {
		t.Fatalf("favicon: %d", code)
	}
	if code, body := pr.get(t, pubURL+"/x.js", script); code != 403 || strings.Contains(body, "<html") {
		t.Fatalf("a script is still bare: %d %q", code, body)
	}
	lines := pr.log.lines("apprelay refused")
	for _, l := range lines {
		if l["what"] == "image" {
			t.Fatalf("the favicon was said as a refusal: %v", lines)
		}
	}
	if len(lines) != 2 {
		t.Fatalf("want the page and the script, got %v", lines)
	}
}

// TestProxyRefusesWhatItCannotVerifyOrResolve: a site whose certificate no
// root vouches for is answered 502 and never served; a name that does not
// resolve, and the browser's own service hosts, are refused at CONNECT.
func TestProxyRefusesWhatItCannotVerifyOrResolve(t *testing.T) {
	pub := echoOrigin(t, true)
	pr := newProxyRig(t, echoOrigin(t, true), public, nil)
	// Without the test roots the public site is unverifiable.
	unverifiable := newProxyRigRoots(t, pub, nil)
	if code, body := unverifiable.get(t, "https://"+pub.Listener.Addr().String()+"/x.js", script); code != 502 || !strings.Contains(body, "certificate") {
		t.Fatalf("unverifiable site: %d %q", code, body)
	}
	// The tunnel opens, so the refusal can say what asked; nothing is dialled.
	before := len(pr.dialled())
	for host, why := range map[string]string{"nowhere.gone": "lookup failed", "accounts.google.com": "the browser's own service"} {
		if code, body := pr.get(t, "https://"+host+"/x.js", script); code != 403 || !strings.Contains(body, why) {
			t.Fatalf("%s: %d %q, want 403 %q", host, code, body, why)
		}
	}
	if n := len(pr.dialled()); n != before {
		t.Fatalf("a refused destination was dialled: %v", pr.dialled()[before:])
	}
}

// newProxyRigRoots is newProxyRig with the roots given for sites that are
// not the application's (nil: the system's).
func newProxyRigRoots(t *testing.T, origin *httptest.Server, roots *x509.CertPool) *proxyRig {
	t.Helper()
	pr := newProxyRig(t, origin, public, nil)
	// A second relay with the roots given, on its own port.
	caCert, caKey, _ := NewSessionCA("test session")
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM([]byte(caCert))
	port := freePort(t)
	_, oport, _ := net.SplitHostPort(origin.Listener.Addr().String())
	r := &Relay{
		Config: Config{Proxy: &Proxy{Listen: "internal:" + strconv.Itoa(port), CACert: caCert, CAKey: caKey,
			Allow: []Route{{Host: "example.com", Port: 443, To: "127.0.0.1:" + oport}}}},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), InternalIP: "127.0.0.1", Classify: public, Roots: roots,
		Resolver: resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = r.Serve(ctx) }()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	waitListening(t, addr)
	pu, _ := url.Parse("http://" + addr)
	pr.proxyURL = pu
	pr.client = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS12}}}
	return pr
}

// TestProxyWebSockets: a secure WebSocket to a public host goes through
// the inspected tunnel and echoes; a plain one, which the browser sends as
// CONNECT with HTTP inside, is read as such and goes through too.
func TestProxyWebSockets(t *testing.T) {
	pub := echoOrigin(t, true)
	pr := newProxyRig(t, echoOrigin(t, true), public, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, hs, err := websocket.Dial(ctx, "wss://"+pub.Listener.Addr().String()+"/ws", &websocket.DialOptions{HTTPClient: pr.client,
		HTTPHeader: http.Header{"Origin": []string{"https://example.com"}}})
	if hs != nil && hs.Body != nil {
		_ = hs.Body.Close()
	}
	if err != nil {
		t.Fatalf("wss through the proxy: %v (relay said: %v %v)", err, pr.log.lines("apprelay origin unreachable"), pr.log.lines("apprelay origin certificate refused"))
	}
	defer c.CloseNow()
	if err := c.Write(ctx, websocket.MessageText, []byte("hi")); err != nil {
		t.Fatal(err)
	}
	if _, msg, err := c.Read(ctx); err != nil || string(msg) != "echo: hi" {
		t.Fatalf("echo: %q %v", msg, err)
	}
	// Plain HTTP inside a CONNECT tunnel, as Chromium sends ws://.
	plain := echoOrigin(t, false)
	raw, err := net.Dial("tcp", pr.proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	dest := plain.Listener.Addr().String()
	_, _ = fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", dest, dest)
	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("connect: %v %v", err, resp)
	}
	_ = resp.Body.Close()
	_, _ = fmt.Fprintf(raw, "GET /inside HTTP/1.1\r\nHost: %s\r\nAccept: */*\r\nOrigin: https://example.com\r\n\r\n", dest)
	resp, err = http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("plain inside the tunnel: %v %v", err, resp)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), "GET /inside host="+dest+" tls=false") {
		t.Fatalf("plain inside the tunnel: %q", body)
	}
}

// TestProxyConfigValidation: the proxy's table is checked as the socks
// table is, and a session has one or the other.
func TestProxyConfigValidation(t *testing.T) {
	caCert, caKey, _ := NewSessionCA("s")
	ok := Route{Host: "app.corp", Port: 443, To: "10.0.0.5:443"}
	good := func() *Proxy {
		return &Proxy{Listen: "internal:3128", CACert: caCert, CAKey: caKey, Allow: []Route{ok}}
	}
	if err := (&Config{Proxy: good()}).Validate(); err != nil {
		t.Fatalf("a good table: %v", err)
	}
	for _, c := range []struct {
		name, want string
		cfg        Config
	}{
		{"every address", `must be "internal:<port>"`, Config{Proxy: func() *Proxy { p := good(); p.Listen = ":3128"; return p }()}},
		{"both", "proxy or socks", Config{Proxy: good(), SOCKS: &SOCKS{Listen: "internal:1080", Allow: []Route{ok}}}},
		{"no ca", "proxy ca", Config{Proxy: func() *Proxy { p := good(); p.CAKey = "nope"; return p }()}},
		{"no routes", "allows nothing", Config{Proxy: func() *Proxy { p := good(); p.Allow = nil; return p }()}},
		{"bad network", "private network", Config{Proxy: func() *Proxy { p := good(); p.PrivateNetworks = []string{"10.0.0.0"}; return p }()}},
		{"bad host", "must be host:port", Config{Proxy: func() *Proxy { p := good(); p.PrivateHosts = []string{"cdn.corp"}; return p }()}},
		{"bad bundle", "no certificate", Config{Proxy: func() *Proxy { p := good(); p.TLSCA = "junk"; return p }()}},
	} {
		err := c.cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}
