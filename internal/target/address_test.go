// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/albatroxxx/zanskar/internal/audit"
)

// TestAddressChangeResetsTrust: a trusted key is kept across an update that
// keeps the address, and cleared by one that changes it, with the certificate
// pins, because a new address may be a different machine. The update is
// audited as a trust reset, and the next probe sees the new machine's key as
// new ("pending"), not as a changed key that looks like an attack.
func TestAddressChangeResetsTrust(t *testing.T) {
	e := newEnv(t)
	port, fp := startSSHServer(t)
	write := func(address, name string) map[string]any {
		return map[string]any{"name": name, "address": address, "os_family": "linux", "ports": map[string]int{"ssh": port}}
	}
	code, body := e.do("POST", "/api/v1/targets", write("127.0.0.1", "box"), e.admin)
	if code != 201 {
		t.Fatalf("create: %d %v", code, body)
	}
	id := body["id"].(string)
	if code, body := e.do("POST", "/api/v1/targets/"+id+"/probe", nil, e.admin); code != 200 || body["host_key_fingerprint"] != fp {
		t.Fatalf("probe: %d %v", code, body)
	}
	if code, body := e.do("POST", "/api/v1/targets/"+id+"/host-key/trust", map[string]string{"host_key_fingerprint": fp}, e.admin); code != 200 {
		t.Fatalf("trust: %d %v", code, body)
	}
	pin := func(column string) {
		t.Helper()
		if _, err := e.db.ExecContext(context.Background(), e.db.Rebind(`UPDATE targets SET `+column+` = 'ab12' WHERE id = ?`), id); err != nil { // #nosec G202 -- fixed column names below
			t.Fatal(err)
		}
	}
	pin("tls_fingerprint")
	pin("winrm_tls_fingerprint")

	// Same address, new name: trust and pins stay.
	code, body = e.do("PUT", "/api/v1/targets/"+id, write("127.0.0.1", "box-renamed"), e.admin)
	if code != 200 || body["host_key_status"] != "trusted" || body["host_key_fingerprint"] != fp || body["tls_fingerprint"] != "ab12" {
		t.Fatalf("rename kept trust? %d %v", code, body)
	}

	// New address: trust and every pin are gone, in the response and stored.
	code, body = e.do("PUT", "/api/v1/targets/"+id, write("localhost", "box-renamed"), e.admin)
	if code != 200 || body["host_key_status"] != "unknown" || body["host_key_fingerprint"] != nil || body["tls_fingerprint"] != nil || body["winrm_tls_fingerprint"] != nil {
		t.Fatalf("address change response: %d %v", code, body)
	}
	if _, stored := e.do("GET", "/api/v1/targets/"+id, nil, e.admin); stored["host_key_status"] != "unknown" || stored["tls_fingerprint"] != nil {
		t.Fatalf("address change stored: %v", stored)
	}
	evs, _, err := e.audit.List(context.Background(), audit.Filter{Action: "target.update", Limit: 1})
	if err != nil || len(evs) == 0 {
		t.Fatalf("target.update not audited: %v", err)
	}
	var d map[string]any
	_ = json.Unmarshal(evs[0].Details, &d)
	if d["trust_reset"] != true {
		t.Fatalf("target.update details %v, want trust_reset", d)
	}

	// The next probe sees the key as new, not changed.
	if code, body := e.do("POST", "/api/v1/targets/"+id+"/probe", nil, e.admin); code != 200 || body["host_key_status"] != "pending" {
		t.Fatalf("probe after the move: %d %v", code, body)
	}
}
