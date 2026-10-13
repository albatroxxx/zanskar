// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// TestOfflineCommandsRefuseUnmigratedDatabase: every command that opens the
// database on its own (not serve) refuses one with migrations pending and
// says what to run, as `admin create` and `serve` already did, rather than
// working on a schema the code no longer matches.
func TestOfflineCommandsRefuseUnmigratedDatabase(t *testing.T) {
	newCLIGateway(t, false)
	for name, run := range map[string]func() error{
		"admin create":    func() error { return runAdmin([]string{"create", "--username", "root", "--name", "Root"}) },
		"admin reset-mfa": func() error { return runAdmin([]string{"reset-mfa", "--username", "root"}) },
		"audit verify":    func() error { return runAudit([]string{"verify"}) },
		"key status":      func() error { return runKey([]string{"status"}) },
	} {
		t.Setenv("ZANSKAR_ADMIN_PASSWORD", "a long enough passphrase for root")
		_, _, err := output(t, run)
		if err == nil || !strings.Contains(err.Error(), "pending; run `zanskar migrate` first") {
			t.Errorf("%s on an unmigrated database: %v", name, err)
		}
	}
}
