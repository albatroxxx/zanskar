// SPDX-License-Identifier: Apache-2.0

// Package kubegw reaches a Kubernetes cluster's API server as Zanskar (ADR
// 0045): with the cluster's credential, over TLS to the enrolled CA, by
// plain HTTPS. It speaks no client library; the API is HTTP and the gateway
// needs its shape at the request level anyway, to proxy it (proxy.go).
package kubegw

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Credential is Zanskar's own identity in the cluster: a bearer token, a
// client certificate and its key (one PEM text), or a source of bearers for
// a credential whose token is minted and expires (an EKS role, ADR 0045 8),
// asked for the token of each request. Exactly one is set.
type Credential struct {
	Token   string
	CertPEM []byte
	Bearer  func(context.Context) (string, error)
}

// bearer is the token a request carries now, or "" for a certificate.
func (c Credential) bearer(ctx context.Context) (string, error) {
	if c.Bearer != nil {
		return c.Bearer(ctx)
	}
	return c.Token, nil
}

// Endpoint is a cluster as the gateway reaches it.
type Endpoint struct {
	// APIServer is https://host[:port], no path.
	APIServer string
	// CA is the PEM bundle the server's certificate is verified against;
	// empty, the system roots.
	CA string
	// DialIP, when set, is dialled in place of the URL's host, which stays
	// the TLS server name: the address rules resolved the name once and the
	// client must not look it up again (connect.checkAddress).
	DialIP net.IP
}

// MaxBody bounds what a test reads from the cluster.
const MaxBody = 1 << 20

var (
	// ErrUnauthorized is the cluster refusing the credential.
	ErrUnauthorized = errors.New("kubegw: the cluster refused the credential")
	// ErrForbidden is the cluster refusing the request with the credential.
	ErrForbidden = errors.New("kubegw: the cluster forbids this to the credential")
)

// Transport returns an HTTP transport to the endpoint: TLS to its CA (or the
// system roots), HTTP/1.1 only, since the API's upgraded streams (exec,
// attach, port-forward) and the reverse proxy's handling of a 101 need it,
// and the dial pinned to DialIP when set.
func Transport(ep Endpoint, cred Credential) (*http.Transport, error) {
	u, err := url.Parse(ep.APIServer)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, fmt.Errorf("kubegw: api server must be https://host[:port]")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
	if ep.CA != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(ep.CA)) {
			return nil, fmt.Errorf("kubegw: the CA bundle holds no certificate")
		}
		cfg.RootCAs = pool
	}
	if len(cred.CertPEM) > 0 {
		pair, err := tls.X509KeyPair(cred.CertPEM, cred.CertPEM)
		if err != nil {
			return nil, fmt.Errorf("kubegw: client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	tr := &http.Transport{
		TLSClientConfig:     cfg,
		ForceAttemptHTTP2:   false,
		TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{},
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        8,
		IdleConnTimeout:     90 * time.Second,
	}
	if ep.DialIP != nil {
		port := u.Port()
		if port == "" {
			port = "443"
		}
		pinned := net.JoinHostPort(ep.DialIP.String(), port)
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, pinned)
		}
	} else {
		tr.DialContext = d.DialContext
	}
	return tr, nil
}

// Client reaches one cluster as Zanskar.
type Client struct {
	base string
	cred Credential
	http *http.Client
}

// New returns a client for the endpoint with the credential.
func New(ep Endpoint, cred Credential) (*Client, error) {
	tr, err := Transport(ep, cred)
	if err != nil {
		return nil, err
	}
	return &Client{base: strings.TrimSuffix(ep.APIServer, "/"), cred: cred, http: &http.Client{Transport: tr, Timeout: 20 * time.Second}}, nil
}

// Close releases the client's connections.
func (c *Client) Close() { c.http.CloseIdleConnections() }

// do sends one request as Zanskar and reads a bounded answer.
func (c *Client) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	tok, err := c.cred.bearer(ctx)
	if err != nil {
		return 0, nil, err
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(res.Body, MaxBody))
	if err != nil {
		return res.StatusCode, nil, err
	}
	switch res.StatusCode {
	case http.StatusUnauthorized:
		return res.StatusCode, b, ErrUnauthorized
	case http.StatusForbidden:
		return res.StatusCode, b, ErrForbidden
	}
	return res.StatusCode, b, nil
}

// Version is what the cluster says of itself.
type Version struct {
	GitVersion string `json:"gitVersion"`
	Platform   string `json:"platform"`
}

// Version asks the cluster its version, the one call every credential may
// make, so it is the reachability check.
func (c *Client) Version(ctx context.Context) (*Version, error) {
	code, b, err := c.do(ctx, http.MethodGet, "/version", nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("kubegw: /version answered %d", code)
	}
	var v Version
	if err := json.Unmarshal(b, &v); err != nil || v.GitVersion == "" {
		return nil, fmt.Errorf("kubegw: /version did not answer as a Kubernetes API server")
	}
	return &v, nil
}

// MayImpersonate asks the cluster, through a SelfSubjectAccessReview, whether
// the credential may impersonate users and groups: what every session as the
// person needs (ADR 0045, 2).
func (c *Client) MayImpersonate(ctx context.Context) (users, groups bool, err error) {
	users, err = c.selfAccess(ctx, "impersonate", "users")
	if err != nil {
		return false, false, err
	}
	groups, err = c.selfAccess(ctx, "impersonate", "groups")
	return users, groups, err
}

func (c *Client) selfAccess(ctx context.Context, verb, resource string) (bool, error) {
	review := map[string]any{
		"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview",
		"spec": map[string]any{"resourceAttributes": map[string]string{"verb": verb, "resource": resource}},
	}
	code, b, err := c.do(ctx, http.MethodPost, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", review)
	if err != nil {
		return false, err
	}
	if code != http.StatusCreated && code != http.StatusOK {
		return false, fmt.Errorf("kubegw: access review answered %d", code)
	}
	var out struct {
		Status struct {
			Allowed bool `json:"allowed"`
		} `json:"status"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return false, fmt.Errorf("kubegw: access review: %w", err)
	}
	return out.Status.Allowed, nil
}

// Namespaces lists the cluster's namespaces, in the cluster's order. A
// credential that may not list them (which impersonation alone does not
// grant) gets an empty list and no error: the test says so beside it.
func (c *Client) Namespaces(ctx context.Context) ([]string, error) {
	code, b, err := c.do(ctx, http.MethodGet, "/api/v1/namespaces", nil)
	if errors.Is(err, ErrForbidden) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("kubegw: namespaces answered %d", code)
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("kubegw: namespaces: %w", err)
	}
	names := make([]string, 0, len(list.Items))
	for _, it := range list.Items {
		names = append(names, it.Metadata.Name)
	}
	return names, nil
}
