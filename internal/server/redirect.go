// SPDX-License-Identifier: Apache-2.0

package server

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var hostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$`)

// redirectHandler answers every request on the plain-HTTP listener with a
// permanent redirect to the same path on the HTTPS listener. The target
// host is never the request's own text: the client's Host header (port
// stripped) is matched against the names the served certificate covers,
// and the certificate's copy of the name is what the redirect uses; a host
// that is not covered falls back to fallbackHost (the listen host when it
// is a concrete address) or is refused, since a redirect to a name the
// certificate cannot serve would only move the browser warning one hop.
// tlsPort is added unless it is 443. Nothing else is served here.
func redirectHandler(tlsPort, fallbackHost string, covered func() []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked := r.Host
		if h, _, err := net.SplitHostPort(asked); err == nil {
			asked = h
		}
		asked = strings.ToLower(strings.Trim(asked, "[]"))
		// wellFormed gates both the certificate lookup and whether the name is
		// safe to repeat back: anything else is an arbitrary request header and
		// is never echoed.
		wellFormed := net.ParseIP(asked) != nil || (len(asked) <= 253 && hostRe.MatchString(asked))
		host := ""
		if covered != nil && wellFormed {
			for _, name := range covered() {
				if strings.EqualFold(name, asked) {
					host = name
					break
				}
			}
		}
		if host == "" {
			host = fallbackHost
		}
		if host == "" {
			// Refusing rather than guessing: a redirect to a name the served
			// certificate cannot serve would only move the browser warning one
			// hop. Say which name was asked for and how to make it work, since
			// a cloud instance reached by its public address lands here every
			// time (the address is translated upstream, so it is on no
			// interface and cannot be guessed).
			which := "The address you used"
			if wellFormed {
				which = strconv.Quote(asked)
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusBadRequest)
			// #nosec G705 -- `which` is either a fixed string or a host that
			// passed hostRe (letters, digits, hyphens and dots) or net.ParseIP,
			// quoted; it cannot carry markup. The response is text/plain with
			// nosniff, so there is no document for a script to run in.
			_, _ = io.WriteString(w, "Zanskar serves HTTPS, and this listener only redirects to a name its certificate covers.\n\n"+
				which+" is not one of them, so there is nothing safe to redirect you to.\n\n"+
				"Reach it over https:// directly, or add this name to the certificate: set ZANSKAR_TLS_HOSTS\n"+
				"in the environment file (zanskar init -tls-hosts), or use Regenerate self-signed on the\n"+
				"Settings page and list it there.\n")
			return
		}
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		if tlsPort != "443" && tlsPort != "" {
			host += ":" + tlsPort
		}
		w.Header().Set("Cache-Control", "no-store")
		// Scheme-only redirect: the host is a name from the served certificate
		// or the listen host, never the request's text; the path is the
		// request's own.
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently) // #nosec G710 -- see above
	})
}

// newRedirectServer builds the plain-HTTP server for addr; covered lists
// the names the HTTPS listener's certificate carries.
func newRedirectServer(addr, tlsListenAddr string, covered func() []string) *http.Server {
	host, port, _ := net.SplitHostPort(tlsListenAddr)
	if host == "0.0.0.0" || host == "::" {
		host = ""
	}
	return &http.Server{
		Addr:              addr,
		Handler:           redirectHandler(port, host, covered),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

// bindHint turns a refused bind on a privileged port into advice: the
// packaged unit grants CAP_NET_BIND_SERVICE, a hand-written one must.
func bindHint(err error, addr string) error {
	if err == nil {
		return nil
	}
	var sysErr syscall.Errno
	if errors.As(err, &sysErr) && sysErr == syscall.EACCES {
		if _, port, perr := net.SplitHostPort(addr); perr == nil {
			if n, cerr := strconv.Atoi(port); cerr == nil && n < 1024 {
				return fmt.Errorf("%w: binding port %d needs CAP_NET_BIND_SERVICE; the packaged unit grants it (AmbientCapabilities=CAP_NET_BIND_SERVICE), add it to yours or choose a port above 1023", err, n)
			}
		}
	}
	return err
}
