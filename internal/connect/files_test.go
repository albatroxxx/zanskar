// SPDX-License-Identifier: Apache-2.0

package connect

import "testing"

// TestFileRegistryOwnerScoping covers the security-relevant behaviour: a
// session's file client is visible only to the user who owns it, unknown
// sessions are not found, and removal takes effect.
func TestFileRegistryOwnerScoping(t *testing.T) {
	r := newFileRegistry()
	r.add("sess-1", &fileSession{userID: "alice", targetKey: "t1"})

	if _, ok := r.lookup("sess-1", "alice"); !ok {
		t.Fatal("owner should find the session")
	}
	if _, ok := r.lookup("sess-1", "bob"); ok {
		t.Fatal("a non-owner must not find another user's session")
	}
	if _, ok := r.lookup("sess-unknown", "alice"); ok {
		t.Fatal("an unknown session must not be found")
	}

	r.remove("sess-1")
	if _, ok := r.lookup("sess-1", "alice"); ok {
		t.Fatal("a removed session must be gone")
	}
}
