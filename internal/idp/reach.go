// SPDX-License-Identifier: Apache-2.0

package idp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"strings"
	"syscall"
)

// PlainError is err in words an administrator can act on. A failure to
// reach the provider at all, the usual reason a sync or a test fails, names
// the host and what happened (no answer in time, a name that does not
// resolve, a refused connection, no route, an untrusted certificate) rather
// than the chain of calls it came through; until 2026-11-02 the console showed
// `list the directory: discovery: Get "https://…/.well-known/openid-
// configuration": context deadline exceeded (Client.Timeout exceeded while
// awaiting headers)`. Any other error keeps its own words. The full error
// belongs in the server log.
func PlainError(err error) string {
	if err == nil {
		return ""
	}
	why, ok := unreachable(err)
	if !ok {
		return err.Error()
	}
	return "could not reach " + hostOf(err) + ": " + why
}

// unreachable says why err is a failure to reach the provider, or false
// when it is something else (an answer the provider gave, a refusal of the
// client's credentials, a configuration error).
func unreachable(err error) (string, bool) {
	var dns *net.DNSError
	var unknownCA x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	var verify *tls.CertificateVerificationError
	var ne net.Error
	switch {
	case errors.As(err, &dns) && (dns.IsNotFound || !dns.IsTimeout):
		return "the name does not resolve from the gateway", true
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "it did not answer in time", true
	case errors.Is(err, syscall.ECONNREFUSED):
		return "it refused the connection", true
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "no route from the gateway", true
	case errors.As(err, &unknownCA), errors.As(err, &invalid), errors.As(err, &hostname), errors.As(err, &verify):
		why := err.Error()
		if i := strings.LastIndex(why, "x509: "); i >= 0 {
			why = why[i+len("x509: "):]
		}
		return "its certificate is not trusted (" + why + ")", true
	}
	return "", false
}

// hostOf is the host of the request err came from, or "the provider" when
// it names none.
func hostOf(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		if u, perr := url.Parse(ue.URL); perr == nil && u.Host != "" {
			return u.Host
		}
	}
	return "the provider"
}
