// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client calls a Zanskar gateway's API with an API token (ADR 0044).
type Client struct {
	base  string // https://gw.example.com/api/v1
	token string
	http  *http.Client
	ua    string
}

// APIError is the gateway's answer to a request it refused: its status,
// and the code and message of its error body.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("zanskar: %s (%d %s)", e.Message, e.Status, e.Code)
	}
	return fmt.Sprintf("zanskar: HTTP %d", e.Status)
}

// IsNotFound reports whether err is the gateway saying the object is gone.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// NewClient returns a client for the gateway at rawURL (its origin; the
// API is under /api/v1), with token, trusting caPEM too when it is given.
func NewClient(rawURL, token, caPEM, version string) (*Client, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("url must be the gateway's address, such as https://zanskar.example.com")
	}
	if u.Scheme == "http" && !loopback(u.Hostname()) {
		return nil, fmt.Errorf("url must be https:// unless the gateway is on this machine: the token would cross the network in clear")
	}
	if !strings.HasPrefix(token, "zapi_") {
		return nil, fmt.Errorf("token must be a Zanskar API token (zapi_...), made under Settings › API tokens")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if caPEM != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, fmt.Errorf("ca_pem holds no certificate")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &Client{
		base:  strings.TrimSuffix(u.Scheme+"://"+u.Host+u.Path, "/") + "/api/v1",
		token: token,
		http:  &http.Client{Transport: tr, Timeout: 60 * time.Second},
		ua:    "terraform-provider-zanskar/" + version,
	}, nil
}

func loopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// do sends in as JSON (when not nil) and reads the answer into out (when
// not nil). A status of 400 and up is an *APIError.
func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return err
	}
	if res.StatusCode >= 400 {
		ae := &APIError{Status: res.StatusCode}
		_ = json.Unmarshal(data, ae)
		var named struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &named) == nil {
			ae.Code, ae.Message = named.Code, named.Message
		}
		return ae
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

// page is one page of a list.
type page[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor"`
}

// findByName walks a list at path, page by page, for the item named name.
func findByName[T any](ctx context.Context, c *Client, path, name string, nameOf func(T) string) (*T, error) {
	cursor := ""
	for range 1000 {
		q := url.Values{"limit": {"500"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var p page[T]
		if err := c.do(ctx, http.MethodGet, path+"?"+q.Encode(), nil, &p); err != nil {
			return nil, err
		}
		for i := range p.Items {
			if nameOf(p.Items[i]) == name {
				return &p.Items[i], nil
			}
		}
		if p.NextCursor == "" {
			return nil, nil
		}
		cursor = p.NextCursor
	}
	return nil, fmt.Errorf("zanskar: %s did not end", path)
}
