// SPDX-License-Identifier: Apache-2.0

package apprelay

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/albatroxxx/zanskar/internal/ipspace"
)

// Proxy is the browser's HTTP proxy that inspects (ADR 0037, amended
// 2026-11-03, later), the relay's way out under an application whose
// dependencies may come from any public address. A plain http request
// arrives whole; for https the browser sends CONNECT, and the relay answers,
// presents a leaf certificate for the host signed by the session's CA, and
// reads each request in clear. A top-level document opens at the origins
// alone and gets the relay's own page anywhere else; a frame, a script, a
// style, a font, an image, a fetch or a WebSocket is a dependency, let
// through to any public address on any port, to a private one the
// application allows, and refused otherwise, each refusal said in the log
// for the gateway to collect.
type Proxy struct {
	// Listen is "internal:<port>": the session network only.
	Listen string `json:"listen"`
	// CACert and CAKey are the session's certificate authority, PEM. The
	// browser trusts the certificate; the key signs a leaf per host and
	// lives nowhere but here.
	CACert string `json:"ca_cert"`
	CAKey  string `json:"ca_key"`
	// Allow are the origins: a page opens there and nowhere else; each is
	// dialled at the address the gateway pinned.
	Allow []Route `json:"allow"`
	// TLSCA is a PEM bundle an https origin among Allow is verified against
	// beside the system roots; empty, the system roots alone.
	TLSCA string `json:"tls_ca,omitempty"`
	// PrivateNetworks (CIDRs) and PrivateHosts (host:port) are the private
	// addresses the application's dependencies may reach.
	PrivateNetworks []string `json:"private_networks,omitempty"`
	PrivateHosts    []string `json:"private_hosts,omitempty"`
	// Name is the application's, on the page that says a page was refused.
	Name string `json:"name,omitempty"`
}

// validProxy checks the proxy's table: a listen on the session network, a
// CA that parses, origins as validSOCKS wants them, networks that parse and
// hosts that are host:port.
func (c *Config) validProxy() error {
	p := c.Proxy
	if p == nil {
		return nil
	}
	if !strings.HasPrefix(p.Listen, "internal:") {
		return errors.New(`apprelay config: proxy listen must be "internal:<port>"`)
	}
	port, err := listenPort(p.Listen)
	if err != nil {
		return fmt.Errorf("apprelay config: proxy: %w", err)
	}
	for _, f := range c.Forwards {
		if fp, _ := listenPort(f.Listen); fp == port {
			return fmt.Errorf("apprelay config: proxy listens on %d, as a forward does", port)
		}
	}
	if c.SOCKS != nil {
		return errors.New("apprelay config: a session has a proxy or socks, not both")
	}
	if _, _, err := parseCA(p.CACert, p.CAKey); err != nil {
		return fmt.Errorf("apprelay config: proxy ca: %w", err)
	}
	if err := validRoutes(p.Allow); err != nil {
		return fmt.Errorf("apprelay config: proxy: %w", err)
	}
	if p.TLSCA != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(p.TLSCA)) {
		return errors.New("apprelay config: proxy tls_ca holds no certificate")
	}
	for _, n := range p.PrivateNetworks {
		if _, _, err := net.ParseCIDR(n); err != nil {
			return fmt.Errorf("apprelay config: proxy private network %q: %w", n, err)
		}
	}
	for _, h := range p.PrivateHosts {
		host, port, err := net.SplitHostPort(h)
		if err != nil || normHost(host) == "" {
			return fmt.Errorf("apprelay config: proxy private host %q must be host:port", h)
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("apprelay config: proxy private host %q has no valid port", h)
		}
	}
	return nil
}

// parseCA reads the session's CA certificate and EC key from PEM.
func parseCA(certPEM, keyPEM string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cb, _ := pem.Decode([]byte(certPEM))
	if cb == nil {
		return nil, nil, errors.New("certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("certificate: %w", err)
	}
	kb, _ := pem.Decode([]byte(keyPEM))
	if kb == nil {
		return nil, nil, errors.New("key is not PEM")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("key: %w", err)
	}
	if !cert.IsCA {
		return nil, nil, errors.New("certificate is not a CA")
	}
	return cert, key, nil
}

// NewSessionCA makes a certificate authority for one session: an ECDSA key
// and a certificate valid for two days, longer than any session. Returns
// both as PEM.
func NewSessionCA(name string) (certPEM, keyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name, Organization: []string{"Zanskar session"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})), nil
}

// decision is where a destination (host:port) may be reached, or why not.
type decision struct {
	// kind is origin, public, private or refused.
	kind string
	// to is ip:port, the address dialled.
	to  string
	why string
	at  time.Time
}

const (
	kindOrigin  = "origin"
	kindPublic  = "public"
	kindPrivate = "private"
	kindRefused = "refused"
)

// decisionTTL is how long a destination's lookup is reused.
const decisionTTL = time.Minute

// browserServices are hosts Chromium calls for itself whatever its policy
// says (seen at the relay, 2026-11-03: sign-in checks, component updates).
// No application's page depends on them, so they stay refused as they were;
// an application that does name one lists it as an endpoint.
var browserServices = map[string]bool{
	"accounts.google.com": true, "update.googleapis.com": true,
	"clients1.google.com": true, "clients2.google.com": true, "clients3.google.com": true,
	"clients4.google.com": true, "clients5.google.com": true, "clients6.google.com": true,
}

// proxy runs one Proxy.
type proxy struct {
	r   *Relay
	cfg *Proxy
	// ctx is the relay's: a tunnel lives until the relay ends, not until
	// the CONNECT request's own context, which the outer server cancels
	// whenever a read through its reader errs, as the inner server's
	// deadline trick makes it do at each hijack and each request's end.
	ctx     context.Context
	ca      *x509.Certificate
	caKey   *ecdsa.PrivateKey
	leafKey *ecdsa.PrivateKey
	leaves  sync.Map // host -> *tls.Certificate
	routes  map[string]string
	hosts   map[string]bool // a route's host: verified against pool
	pool    *x509.CertPool
	nets    []*net.IPNet
	private map[string]bool // host:port
	// decided caches decision by host:port; pins is host:port -> ip:port
	// for every destination allowed, read by the dialers.
	decided   sync.Map
	pins      sync.Map
	rp        *httputil.ReverseProxy
	rpUpgrade *httputil.ReverseProxy
	block     *template.Template
	refused   *refusals
}

func newProxy(r *Relay, cfg *Proxy) (*proxy, error) {
	ca, key, err := parseCA(cfg.CACert, cfg.CAKey)
	if err != nil {
		return nil, err
	}
	leaf, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	px := &proxy{r: r, cfg: cfg, ca: ca, caKey: key, leafKey: leaf, routes: map[string]string{}, hosts: map[string]bool{}, private: map[string]bool{}}
	for _, rt := range cfg.Allow {
		host := normHost(rt.Host)
		px.routes[net.JoinHostPort(host, strconv.Itoa(rt.Port))] = rt.To
		px.hosts[host] = true
	}
	if cfg.TLSCA != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		pool.AppendCertsFromPEM([]byte(cfg.TLSCA))
		px.pool = pool
	}
	for _, n := range cfg.PrivateNetworks {
		_, ipn, _ := net.ParseCIDR(n)
		px.nets = append(px.nets, ipn)
	}
	for _, h := range cfg.PrivateHosts {
		host, port, _ := net.SplitHostPort(h)
		px.private[net.JoinHostPort(normHost(host), port)] = true
	}
	px.block = template.Must(template.New("block").Parse(blockPage))
	px.refused = &refusals{log: r.Log, seen: map[string]*refusal{}}
	// Two ways to the origin: HTTP/2 where the origin offers it, and
	// HTTP/1.1 alone for an upgrade (a WebSocket), which HTTP/2 cannot carry.
	px.rp = px.reverseProxy([]string{"h2", "http/1.1"}, true)
	px.rpUpgrade = px.reverseProxy([]string{"http/1.1"}, false)
	return px, nil
}

// reverseProxy forwards to the origin decided for a request, over the
// protocols given.
func (px *proxy) reverseProxy(protos []string, h2 bool) *httputil.ReverseProxy {
	r := px.r
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			t, _ := pr.In.Context().Value(targetKey{}).(*url.URL)
			pr.SetURL(t)
			// The browser's own Host header, not the target's; and no
			// X-Forwarded-*: the origin learns nothing of the session.
			pr.Out.Host = pr.In.Host
		},
		Transport: &http.Transport{
			DialContext:           px.dial,
			DialTLSContext:        px.tlsDialer(protos),
			ForceAttemptHTTP2:     h2,
			MaxIdleConnsPerHost:   8,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 90 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
		FlushInterval: 100 * time.Millisecond,
		ModifyResponse: func(resp *http.Response) error {
			// QUIC cannot go through the proxy; pins would outlive the session's CA.
			resp.Header.Del("Alt-Svc")
			resp.Header.Del("Public-Key-Pins")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				return
			}
			var cerr *tls.CertificateVerificationError
			if errors.As(err, &cerr) || strings.Contains(err.Error(), "x509") {
				r.Log.Warn("apprelay origin certificate refused", "host", req.URL.Host, "err", err)
				http.Error(w, "Zanskar could not verify this site's certificate.", http.StatusBadGateway)
				return
			}
			r.Log.Debug("apprelay origin unreachable", "host", req.URL.Host, "err", err)
			http.Error(w, "Zanskar could not reach this site.", http.StatusBadGateway)
		},
	}
}

type targetKey struct{}

// serveProxy accepts on ln for p until ctx ends.
func (r *Relay) serveProxy(ctx context.Context, p *Proxy, ln net.Listener) error {
	px, err := newProxy(r, p)
	if err != nil {
		_ = ln.Close()
		return err
	}
	px.ctx = ctx
	srv := &http.Server{Handler: px, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10,
		BaseContext: func(net.Listener) context.Context { return ctx }}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	err = srv.Serve(ln)
	if ctx.Err() != nil || errors.Is(err, http.ErrServerClosed) {
		return ctx.Err()
	}
	return err
}

// ServeHTTP takes what the browser sends the proxy: CONNECT for a secure
// destination (or a plain WebSocket), or an absolute-URI request for a
// plain one.
func (px *proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		px.connect(w, req)
		return
	}
	if req.URL.Host == "" {
		// Not a proxy request: something on the session network talking
		// to the relay itself.
		http.Error(w, "Zanskar relay", http.StatusBadRequest)
		return
	}
	dest := canonicalDest(req.URL.Host, req.URL.Scheme)
	px.handle(w, req, dest, "http")
}

// canonicalDest is host:port with the host as routes compare it and the
// scheme's port when none was given.
func canonicalDest(hostport, scheme string) string {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = hostport, "80"
		if scheme == "https" {
			port = "443"
		}
	}
	return net.JoinHostPort(normHost(host), port)
}

// connect answers CONNECT with the tunnel, inside which the relay reads
// HTTP, under TLS when the first byte is a TLS record, plain otherwise (a
// ws:// upgrade). Whether the destination may be reached is decided on the
// request inside, where what asked for it and from which page are known,
// so a refusal can say so; the tunnel to a refused destination carries
// nothing but the relay's 403.
func (px *proxy) connect(w http.ResponseWriter, req *http.Request) {
	dest := canonicalDest(req.Host, "https")
	if _, _, err := net.SplitHostPort(dest); err != nil {
		http.Error(w, "Zanskar: not host:port", http.StatusBadRequest)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		_ = conn.Close()
		return
	}
	ctx := px.ctx
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	first, err := brw.Peek(1)
	if err != nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	var c net.Conn = &bufConn{Conn: conn, r: brw.Reader}
	scheme := "http"
	if first[0] == 0x16 {
		scheme = "https"
		host, _, _ := net.SplitHostPort(dest)
		c = tls.Server(c, &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				name := hello.ServerName
				if name == "" {
					name = host
				}
				return px.leaf(name)
			},
		})
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { px.handle(w, r, dest, scheme) }),
		ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	_ = srv.Serve(&oneListener{c: c, done: make(chan struct{})})
}

// bufConn reads through the bytes the hijacked reader already buffered.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// oneListener hands out one connection, then waits until it is closed.
type oneListener struct {
	c    net.Conn
	once sync.Once
	done chan struct{}
}

func (l *oneListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = &closeNotify{Conn: l.c, done: l.done} })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return l.c.Close()
}

func (l *oneListener) Addr() net.Addr { return l.c.LocalAddr() }

// closeNotify ends the listener with its one connection.
type closeNotify struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *closeNotify) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

// leaf is the certificate presented for name, minted once and kept.
func (px *proxy) leaf(name string) (*tls.Certificate, error) {
	name = normHost(name)
	if c, ok := px.leaves.Load(name); ok {
		return c.(*tls.Certificate), nil
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(48 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(name); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, px.ca, &px.leafKey.PublicKey, px.caKey)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der, px.ca.Raw}, PrivateKey: px.leafKey}
	px.leaves.Store(name, c)
	return c, nil
}

// destination decides where dest (host:port) may be reached: an origin at
// its pinned address; otherwise, every address the host resolves to must be
// public, or private and allowed, and the one checked is dialled. The
// browser's own service hosts are refused as before.
func (px *proxy) destination(ctx context.Context, dest string) *decision {
	if to, ok := px.routes[dest]; ok {
		px.pins.Store(dest, to)
		return &decision{kind: kindOrigin, to: to}
	}
	if d, ok := px.decided.Load(dest); ok && time.Since(d.(*decision).at) < decisionTTL {
		return d.(*decision)
	}
	d := px.decide(ctx, dest)
	d.at = time.Now()
	px.decided.Store(dest, d)
	if d.kind != kindRefused {
		px.pins.Store(dest, d.to)
	}
	return d
}

func (px *proxy) decide(ctx context.Context, dest string) *decision {
	host, port, err := net.SplitHostPort(dest)
	if err != nil {
		return &decision{kind: kindRefused, why: "not host:port"}
	}
	if browserServices[host] {
		return &decision{kind: kindRefused, why: "the browser's own service"}
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		res := px.r.Resolver
		if res == nil {
			res = net.DefaultResolver
		}
		lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		addrs, err := res.LookupIPAddr(lctx, host)
		if err != nil {
			return &decision{kind: kindRefused, why: "lookup failed: " + err.Error()}
		}
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	}
	if len(ips) == 0 {
		return &decision{kind: kindRefused, why: "resolves to nothing"}
	}
	classify := px.r.Classify
	if classify == nil {
		classify = ipspace.Reserved
	}
	kind := kindPublic
	var pick net.IP
	for _, ip := range ips {
		why := classify(ip)
		switch {
		case why == "":
		case why == "private" && (px.private[dest] || px.inNets(ip)):
			kind = kindPrivate
		case why == "private":
			return &decision{kind: kindRefused, why: "private"}
		case net.ParseIP(host) != nil:
			return &decision{kind: kindRefused, why: why}
		default:
			return &decision{kind: kindRefused, why: "resolves to " + ip.String() + ", which is " + why}
		}
		if pick == nil || (ip.To4() != nil && pick.To4() == nil) {
			pick = ip
		}
	}
	return &decision{kind: kind, to: net.JoinHostPort(pick.String(), port)}
}

func (px *proxy) inNets(ip net.IP) bool {
	for _, n := range px.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// dial reaches addr (host:port, as the transport names it) at the address
// decided for it, never by the name.
func (px *proxy) dial(ctx context.Context, _, addr string) (net.Conn, error) {
	to, ok := px.pins.Load(addr)
	if !ok {
		return nil, fmt.Errorf("apprelay: %s was not decided", addr)
	}
	return px.r.Dial(ctx, to.(string))
}

// tlsDialer is dial, then TLS to the origin by its name over the protocols
// given: verified against the application's bundle beside the system roots
// for its own origins, the system roots for anything else; an IP literal
// against its address.
func (px *proxy) tlsDialer(protos []string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		host = normHost(host)
		conn, err := px.dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		pool := px.r.Roots
		if px.hosts[host] && px.pool != nil {
			pool = px.pool
		}
		// ServerName verifies the certificate against the name, an IP
		// literal included (its address among the SANs); Go sends no SNI
		// for an IP, as a browser would not.
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: protos, RootCAs: pool, ServerName: host}
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return tc, nil
	}
}

// isDocument says whether req opens a page at the top: Chromium's fetch
// metadata when the destination is secure; without it (a plain http
// destination gets none), a GET that asks for HTML.
func isDocument(req *http.Request) bool {
	mode, dest := req.Header.Get("Sec-Fetch-Mode"), req.Header.Get("Sec-Fetch-Dest")
	if mode != "" || dest != "" {
		return mode == "navigate" && dest == "document"
	}
	return (req.Method == http.MethodGet || req.Method == http.MethodHead) && strings.HasPrefix(req.Header.Get("Accept"), "text/html")
}

// what says what a request fetched, for the refusal log: the fetch
// metadata's destination, or document or resource without it.
func what(req *http.Request) string {
	if d := req.Header.Get("Sec-Fetch-Dest"); d != "" {
		return d
	}
	if isDocument(req) {
		return "document"
	}
	return "resource"
}

// from is the origin of the page that asked, from Origin or Referer; empty
// when neither says.
func from(req *http.Request) string {
	raw := req.Header.Get("Origin")
	if raw == "" || raw == "null" {
		raw = req.Header.Get("Referer")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// handle serves one request bound for dest under scheme: the block page
// for a document anywhere but an origin, 403 for a destination the rules
// refuse, the origin's answer otherwise.
func (px *proxy) handle(w http.ResponseWriter, req *http.Request, dest, scheme string) {
	d := px.destination(req.Context(), dest)
	if d.kind == kindRefused {
		px.refused.add(dest, d.why, what(req), from(req))
		http.Error(w, "Zanskar: "+d.why, http.StatusForbidden)
		return
	}
	if d.kind != kindOrigin && isDocument(req) {
		px.refused.add(dest, "not an origin of the application", "document", from(req))
		px.blocked(w, req, dest, scheme)
		return
	}
	px.r.Log.Debug("apprelay request", "host", dest, "what", what(req), "kind", d.kind)
	target := &url.URL{Scheme: scheme, Host: dest}
	rp := px.rp
	if req.Header.Get("Upgrade") != "" {
		rp = px.rpUpgrade
	}
	rp.ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), targetKey{}, target)))
}

// blocked is the relay's own page: a page opens at the application's
// addresses only.
func (px *proxy) blocked(w http.ResponseWriter, req *http.Request, dest, scheme string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	host, port, _ := net.SplitHostPort(dest)
	shown := host
	if (scheme == "https" && port != "443") || (scheme == "http" && port != "80") {
		shown = dest
	}
	_ = px.block.Execute(w, map[string]string{"App": px.cfg.Name, "Host": shown})
	_ = req
}

const blockPage = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Blocked</title>
<style>body{font-family:system-ui,sans-serif;background:#f4f1ec;color:#2b2a28;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
main{max-width:34rem;padding:2rem}h1{font-size:1.4rem;margin:0 0 .5rem}p{margin:.4rem 0;color:#5c5955}code{background:#e9e4dc;padding:0 .3em;border-radius:3px}</style></head>
<body><main><h1>This page is blocked</h1>
<p>Zanskar opens pages at {{if .App}}<strong>{{.App}}</strong>{{else}}this application{{end}} only; <code>{{.Host}}</code> is not one of its addresses.</p>
<p>Its pages may still load what they need from there.</p></main></body></html>
`

// refusals keeps what the proxy refused and says it in the log, one line
// per destination, reason, kind and asking page when first seen and then at
// most once a minute with the count since, for the gateway to collect. The
// browser's own service hosts are not said: they are not the page's.
type refusals struct {
	log  interface{ Info(string, ...any) }
	mu   sync.Mutex
	seen map[string]*refusal
}

type refusal struct {
	n    int
	said time.Time
}

func (rs *refusals) add(dest, why, what, from string) {
	if why == "the browser's own service" {
		return
	}
	host, port, _ := net.SplitHostPort(dest)
	key := strings.Join([]string{dest, why, what, from}, "|")
	rs.mu.Lock()
	defer rs.mu.Unlock()
	r, ok := rs.seen[key]
	if !ok {
		r = &refusal{}
		rs.seen[key] = r
	}
	r.n++
	if ok && time.Since(r.said) < time.Minute {
		return
	}
	rs.log.Info("apprelay refused", "host", host, "port", port, "why", why, "what", what, "from", from, "count", r.n)
	r.n, r.said = 0, time.Now()
}
