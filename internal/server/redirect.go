// SPDX-License-Identifier: Apache-2.0

package server

import (
	"errors"
	"fmt"
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
// permanent redirect to the same path on the HTTPS listener. The Host
// header is the client's to set, so it is validated as a host name or IP
// and used without its port; anything else falls back to fallbackHost
// (the listen host when it is a concrete address) or is refused. tlsPort
// is added unless it is 443. Nothing else is served here.
func redirectHandler(tlsPort, fallbackHost string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		if net.ParseIP(host) == nil && (len(host) > 253 || !hostRe.MatchString(host)) {
			host = fallbackHost
		}
		if host == "" {
			http.Error(w, "use https", http.StatusBadRequest)
			return
		}
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		if tlsPort != "443" && tlsPort != "" {
			host += ":" + tlsPort
		}
		w.Header().Set("Cache-Control", "no-store")
		// Same-host, scheme-only redirect: the host is the client's own Host
		// header after validation (a name or IP, no port) or the listen host,
		// and the scheme is fixed to https, so no third-party destination can
		// be produced.
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently) // #nosec G710 -- see above
	})
}

// newRedirectServer builds the plain-HTTP server for addr.
func newRedirectServer(addr, tlsListenAddr string) *http.Server {
	host, port, _ := net.SplitHostPort(tlsListenAddr)
	if host == "0.0.0.0" || host == "::" {
		host = ""
	}
	return &http.Server{
		Addr:              addr,
		Handler:           redirectHandler(port, host),
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
