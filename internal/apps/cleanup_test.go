// SPDX-License-Identifier: Apache-2.0

package apps

import (
	"net/http"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/gateway"
	"github.com/albatroxxx/zanskar/internal/store"
)

// TestTouchAndEndedElsewhere: a request older than a minute after the last
// moves the application row and the sign-in behind it, so neither goes idle
// under use; and a row whose access session ended somewhere else (an
// administrator, another gateway on the same database) is forgotten by
// whichever path meets it first: the next request, the sweep, or a resume.
func TestTouchAndEndedElsewhere(t *testing.T) {
	f := newFixture(t)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := f.db.ExecContext(f.ctx, f.db.Rebind(q), args...); err != nil {
			t.Fatal(err)
		}
	}
	count := func() int {
		t.Helper()
		var n int
		if err := f.db.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM app_sessions`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	appCookie, sid := f.open("/")
	old := time.Now().Add(-2 * time.Minute).UTC()
	exec(`UPDATE app_sessions SET last_seen_at = ? WHERE session_id = ?`, store.TimeArg(old), sid)
	exec(`UPDATE auth_sessions SET last_seen_at = ? WHERE id = ?`, store.TimeArg(old), f.authSID)
	if rr := f.app(http.MethodGet, "http://wiki.apps.test/", nil, appCookie); rr.Code != http.StatusOK {
		t.Fatalf("request: %d", rr.Code)
	}
	row, err := f.h.Repo.Lookup(f.ctx, hashToken(appCookie.Value))
	if err != nil {
		t.Fatal(err)
	}
	if !row.LastSeenAt.After(old.Add(time.Minute)) || !row.AuthLastSeenAt.After(old.Add(time.Minute)) {
		t.Errorf("touch: app row %v, sign-in %v, both set two minutes back", row.LastSeenAt, row.AuthLastSeenAt)
	}

	// Ended elsewhere, met by a request: the cookie is cleared and the row goes.
	exec(`UPDATE access_sessions SET ended_at = ?, end_reason = 'admin_terminated' WHERE id = ?`, store.TimeArg(time.Now()), sid)
	rr := f.app(http.MethodGet, "http://wiki.apps.test/", nil, appCookie)
	if rr.Code != http.StatusFound {
		t.Errorf("ended session served: %d", rr.Code)
	}
	if c := cookieNamed(rr.Result(), cookieName); c == nil || c.MaxAge >= 0 {
		t.Errorf("cookie of an ended session not cleared: %v", c)
	}
	if n := count(); n != 0 {
		t.Errorf("app_sessions rows after the request: %d", n)
	}

	if f.h.Registry.Count() != 0 {
		t.Errorf("registry still lists the session that ended elsewhere: %d", f.h.Registry.Count())
	}

	// Met by the sweep.
	_, sid = f.open("/")
	exec(`UPDATE access_sessions SET ended_at = ?, end_reason = 'admin_terminated' WHERE id = ?`, store.TimeArg(time.Now()), sid)
	if n, err := f.h.Sweep(f.ctx); err != nil || n != 0 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	if n := count(); n != 0 || f.h.Registry.Count() != 0 {
		t.Errorf("after the sweep: %d rows, %d in the registry", n, f.h.Registry.Count())
	}

	// Met by a resume on a fresh process.
	_, sid = f.open("/")
	exec(`UPDATE access_sessions SET ended_at = ?, end_reason = 'admin_terminated' WHERE id = ?`, store.TimeArg(time.Now()), sid)
	h2 := &Handler{Repo: f.h.Repo, Sessions: f.access, Auth: f.sessions, Registry: gateway.NewRegistry(), Audit: f.auditLog, Log: f.h.Log,
		Targets: f.h.Targets, Gate: f.h.Gate, Prober: f.h.Prober, Domain: f.h.Domain, PublicURL: f.h.PublicURL}
	if err := h2.Resume(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 0 || h2.Registry.Count() != 0 {
		t.Errorf("after resume: %d rows, %d in the registry", n, h2.Registry.Count())
	}
}
