// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/gateway/guac"
	"github.com/albatroxxx/zanskar/internal/user"
)

// joinRecorder is a guacd that accepts a join of an existing connection and
// reports what the gateway asked for: which connection, and the values it
// sent for the "read-only" parameter.
func joinRecorder(t *testing.T) (string, <-chan [2]string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan [2]string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		rd := guac.NewReader(c)
		sel, err := rd.Read()
		if err != nil || sel.Opcode != "select" || len(sel.Args) != 1 {
			return
		}
		_, _ = c.Write([]byte(guac.Encode("args", "VERSION_1_5_0", "read-only")))
		for {
			in, err := rd.Read()
			if err != nil {
				return
			}
			if in.Opcode == "connect" {
				ro := ""
				if len(in.Args) > 1 {
					ro = in.Args[1]
				}
				got <- [2]string{sel.Args[0], ro}
				break
			}
		}
		_, _ = c.Write([]byte(guac.Encode("ready", "$join-1")))
		for {
			if in, err := rd.Read(); err != nil || in.Opcode == "disconnect" {
				return
			}
		}
	}()
	return ln.Addr().String(), got
}

// TestShadowDesktopJoinsReadOnly: a reviewer watching a live desktop session
// joins its guacd connection read-only, so they can see but never type or
// click into someone else's desktop; watching starts and ends as audit
// events. A desktop session cannot be joined while guacd is unset or before
// it has a guacd connection.
func TestShadowDesktopJoinsReadOnly(t *testing.T) {
	e := newShadowEnv(t)
	auditor := e.cookieFor(t, "auditor", user.RoleAuditor)
	addr, got := joinRecorder(t)
	e.reg.Add(context.Background(), gateway.Live{SessionID: "d1", UserID: "owner", TargetID: "t1", Protocol: "rdp", GuacID: "$conn-9"})
	e.reg.Add(context.Background(), gateway.Live{SessionID: "d2", UserID: "owner", TargetID: "t1", Protocol: "vnc"})

	if _, code := dialShadow(t, e, "d1", auditor); code != 404 {
		t.Fatalf("guacd unset: %d, want 404", code)
	}
	e.h.GuacdAddr = func() string { return addr }
	if _, code := dialShadow(t, e, "d2", auditor); code != 404 {
		t.Fatalf("no guacd connection yet: %d, want 404", code)
	}

	ws, code := dialShadow(t, e, "d1", auditor)
	if ws == nil {
		t.Fatalf("join: %d", code)
	}
	select {
	case req := <-got:
		if req[0] != "$conn-9" || req[1] != "true" {
			t.Fatalf("join asked for connection %q read-only=%q, want $conn-9 read-only=true", req[0], req[1])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("guacd was never asked to join")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, data, err := ws.Read(ctx); err != nil || !strings.Contains(string(data), "d1") {
		t.Fatalf("first message %q %v, want the session id", data, err)
	}
	_ = ws.Close(websocket.StatusNormalClosure, "")

	for _, action := range []string{"session.shadow.start", "session.shadow.end"} {
		deadline := time.Now().Add(5 * time.Second)
		for {
			evs, _, err := e.auditLog.List(context.Background(), audit.Filter{Action: action, Limit: 1})
			if err == nil && len(evs) == 1 && evs[0].ObjectID == "d1" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s for d1 never recorded", action)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}
