// SPDX-License-Identifier: Apache-2.0

package credential

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestAuditNeverHoldsSecrets runs every credential operation the API offers
// (create, generate, update, rotate, a certificate authority's rotation from
// prepare to retire, cancel, delete) and then reads the whole audit table:
// no password, private key or passphrase that passed through may appear in it,
// nor any PEM block at all. CLAUDE.md: audit details never contain secrets.
func TestAuditNeverHoldsSecrets(t *testing.T) {
	e := newHandlerEnv(t)
	secrets := []string{"first-password-1", "second-password-2", "third-password-3", "key-passphrase-4"}
	id := func(body string) string {
		var c struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal([]byte(body), &c)
		return c.ID
	}
	must := func(want int, method, path string, body any) string {
		t.Helper()
		code, out := e.do(method, path, body)
		if code != want {
			t.Fatalf("%s %s: %d %s", method, path, code, out)
		}
		return out
	}

	pw := id(must(201, "POST", "/api/v1/credentials", map[string]any{"name": "pw", "type": "password", "mode": "vaulted", "username": "root", "password": secrets[0]}))
	must(200, "PATCH", "/api/v1/credentials/"+pw, map[string]any{"password": secrets[1]})
	must(200, "PUT", "/api/v1/credentials/"+pw, map[string]any{"name": "pw-renamed", "password": secrets[2]})
	must(200, "POST", "/api/v1/credentials/"+pw+"/rotate", map[string]any{"password": "fourth-password-5"})
	secrets = append(secrets, "fourth-password-5")

	keyPEM, err := GenerateSSHKey()
	if err != nil {
		t.Fatal(err)
	}
	key := id(must(201, "POST", "/api/v1/credentials", map[string]any{"name": "key", "type": "ssh_key", "mode": "vaulted", "username": "deploy", "private_key": keyPEM}))
	gen := id(must(201, "POST", "/api/v1/credentials/generate-ssh-key", map[string]any{"name": "gen", "username": "deploy"}))
	ca := id(must(201, "POST", "/api/v1/credentials", map[string]any{"name": "ca", "type": "ssh_ca", "mode": "vaulted"}))
	must(200, "POST", "/api/v1/credentials/"+ca+"/rotate", map[string]any{})
	must(200, "DELETE", "/api/v1/credentials/"+ca+"/rotate", nil)
	must(200, "POST", "/api/v1/credentials/"+ca+"/rotate", map[string]any{})
	must(200, "POST", "/api/v1/credentials/"+ca+"/rotate/cut-over", nil)
	must(200, "POST", "/api/v1/credentials/"+ca+"/rotate/retire", nil)

	// The private keys that exist now, generated or supplied, are secrets too.
	ctx := context.Background()
	for _, cid := range []string{key, gen, ca} {
		opened, err := e.vault.Open(ctx, cid)
		if err != nil {
			t.Fatalf("open %s: %v", cid, err)
		}
		secrets = append(secrets, strings.TrimSpace(string(opened.PrivateKey)))
		opened.Close()
	}
	secrets = append(secrets, strings.TrimSpace(keyPEM))
	must(204, "DELETE", "/api/v1/credentials/"+key, nil)

	rows, err := e.db.QueryContext(ctx, `SELECT action, actor_ip, object_type, object_id, details FROM audit_events`)
	if err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	n := 0
	for rows.Next() {
		var a, ip, ot, oid, d string
		if err := rows.Scan(&a, &ip, &ot, &oid, &d); err != nil {
			t.Fatal(err)
		}
		log.WriteString(a + " " + ip + " " + ot + " " + oid + " " + d + "\n")
		n++
	}
	_ = rows.Close()
	if n < 10 {
		t.Fatalf("only %d audit events; the operations above should each record one", n)
	}
	all := log.String()
	for _, s := range secrets {
		if s != "" && strings.Contains(all, s) {
			t.Fatalf("a secret reached the audit log: %.20q…", s)
		}
	}
	if strings.Contains(all, "PRIVATE KEY") {
		t.Fatal("a PEM block reached the audit log")
	}
}

// TestEnsureUserSupplied: every "prompt at connect" slot shares one row,
// made the first time it is needed; a vaulted credential that took its name
// is reported rather than silently reused.
func TestEnsureUserSupplied(t *testing.T) {
	v, _ := testVault(t)
	ctx := context.Background()
	first, err := v.EnsureUserSupplied(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	again, err := v.EnsureUserSupplied(ctx, "")
	if err != nil || again != first {
		t.Fatalf("second call: %s %v, want the same row %s", again, err, first)
	}
	c, err := v.Get(ctx, first)
	if err != nil || c.Mode != ModeUserSupplied {
		t.Fatalf("shared row: %+v %v", c, err)
	}
	if _, err := v.Open(ctx, first); err == nil {
		t.Fatal("a user-supplied credential holds no secret to open")
	}

	other, _ := testVault(t)
	taken := &Credential{Name: "User supplied (prompt at connect)", Type: TypePassword, Mode: ModeVaulted, Username: "x"}
	if err := other.Create(ctx, taken, &Secret{Password: "pw-123456"}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := other.EnsureUserSupplied(ctx, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("name taken by a vaulted credential: %v, want ErrInvalid", err)
	}
}
