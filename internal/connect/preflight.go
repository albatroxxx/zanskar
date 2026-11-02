// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/albatroxxx/zanskar/internal/target"
)

// preflightTimeout bounds the pre-flight dial: long enough for a host across
// a slow VPN, short enough that a person waits seconds, not the bridge's
// full dial timeout, to hear a host is down.
const preflightTimeout = 4 * time.Second

// preflight dials a host's port before its session's ticket is handed out
// (2026-11-03 live audit, idea 2). A host that does not answer used to open a
// desktop that drew nothing, end as "target lost" in a second, and leave a
// recording of nothing, six times in three minutes as the person retried;
// now the Connect button says the host is not answering and no session
// starts. Hosts only: SSH, RDP, VNC and WinRM. A database or application
// session starts containers of its own and reports their failures itself.
//
// It dials only the address the gateway's address rules approve, the same
// lookup a session makes, so it reaches nothing a session could not; and it
// runs after the policy check, so it tells nobody whether a target they may
// not reach is up. It returns a refusal's code and message, or "".
func (h *Handler) preflight(ctx context.Context, ep *endpoint, proto target.Protocol) (string, string) {
	switch proto {
	case target.SSH, target.RDP, target.VNC, target.WinRM:
	default:
		return "", ""
	}
	ip, err := h.Prober.Resolve(ctx, ep.Address)
	switch {
	case errors.Is(err, target.ErrAddressForbidden):
		return "address_forbidden", addressRefusedMsg
	case err != nil:
		return "target_unreachable", fmt.Sprintf("%s could not be found: its address %s does not resolve", ep.Name, ep.Address)
	}
	port := ep.port(proto)
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	dctx, cancel := context.WithTimeout(ctx, preflightTimeout)
	defer cancel()
	dial := h.PreflightDial
	if dial == nil {
		dial = defaultPreflightDial
	}
	if err := dial(dctx, addr); err != nil {
		h.Log.Info("pre-flight dial failed", "target", ep.LiveKey, "addr", addr, "err", err)
		return "target_unreachable", unreachableMsg(ep.Name, port, err)
	}
	return "", ""
}

// defaultPreflightDial is the pre-flight dial of a Handler without its own.
// This package's tests, whose targets mostly have no listener, set it to
// succeed; the pre-flight's own tests dial for real.
var defaultPreflightDial = dialTCP

// dialTCP opens and closes one TCP connection.
func dialTCP(ctx context.Context, addr string) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return c.Close()
}

// unreachableMsg says in words why a host's port did not take a connection.
func unreachableMsg(name string, port int, err error) string {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Sprintf("%s refused the connection on port %d: the service is not running there, or a firewall turns it away", name, port)
	case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		return fmt.Sprintf("%s did not answer on port %d within %d seconds: it may be stopped, or a firewall drops the gateway's connection", name, port, int(preflightTimeout/time.Second))
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return fmt.Sprintf("%s cannot be reached from the gateway: no route to it", name)
	}
	return fmt.Sprintf("%s did not take a connection on port %d", name, port)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
