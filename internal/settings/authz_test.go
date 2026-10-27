// SPDX-License-Identifier: Apache-2.0

package settings

import "testing"

// TestRoutesRequireAdmin: every settings route is wired to the admin guard
// (review Q1, finding 4). The user-role fixture of newEnv stands in for any
// signed-in non-administrator.
func TestRoutesRequireAdmin(t *testing.T) {
	e := newEnv(t)
	routes := []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/v1/admin/settings", nil},
		{"PUT", "/api/v1/admin/settings/" + KeyLogLevel, map[string]any{"value": "debug"}},
		{"DELETE", "/api/v1/admin/settings/" + KeyLogLevel, nil},
		{"GET", "/api/v1/admin/settings/login-banner", nil},
	}
	for _, rt := range routes {
		if code, _ := e.do(rt.method, rt.path, rt.body, nil, ""); code != 401 {
			t.Errorf("%s %s anonymous: %d, want 401", rt.method, rt.path, code)
		}
		if code, _ := e.do(rt.method, rt.path, rt.body, e.plain, e.pCSRF); code != 403 {
			t.Errorf("%s %s as a user: %d, want 403", rt.method, rt.path, code)
		}
		if code, _ := e.do(rt.method, rt.path, rt.body, e.admin, e.aCSRF); code == 401 || code == 403 {
			t.Errorf("%s %s as an administrator: %d, must pass the guard", rt.method, rt.path, code)
		}
	}
}
