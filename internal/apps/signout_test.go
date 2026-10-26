// SPDX-License-Identifier: Apache-2.0

package apps

import (
	"net/http"
	"testing"

	"github.com/albatroxxx/zanskar/internal/session"
)

// TestSignoutIsNotCrossSite: the application cookie is SameSite=Lax, so a
// link on any site could navigate the browser to /_zanskar/signout and end
// the session, audited as the person's own exit. A cross-site navigation is
// refused and changes nothing; the application's own pages and a typed
// address still sign out.
func TestSignoutIsNotCrossSite(t *testing.T) {
	f := newFixture(t)
	appCookie, sid := f.open("/")
	for _, site := range []string{"cross-site", "same-site"} {
		rr := f.app(http.MethodGet, "http://wiki.apps.test"+signoutPath, http.Header{"Sec-Fetch-Site": {site}}, appCookie)
		if rr.Code != http.StatusForbidden {
			t.Errorf("%s signout: %d", site, rr.Code)
		}
		if c := cookieNamed(rr.Result(), cookieName); c != nil {
			t.Errorf("%s signout touched the cookie: %v", site, c)
		}
		if s, err := f.access.Get(f.ctx, sid); err != nil || s.EndedAt != nil {
			t.Errorf("%s signout ended the session: %v %+v", site, err, s)
		}
	}
	rr := f.app(http.MethodGet, "http://wiki.apps.test"+signoutPath, http.Header{"Sec-Fetch-Site": {"same-origin"}}, appCookie)
	if rr.Code != http.StatusOK {
		t.Fatalf("same-origin signout: %d", rr.Code)
	}
	if s := f.waitEnded(sid); s.EndReason != session.EndUserExit {
		t.Errorf("end reason: %q", s.EndReason)
	}
}
