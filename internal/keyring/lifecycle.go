// SPDX-License-Identifier: Apache-2.0

package keyring

import "github.com/albatroxxx/zanskar/internal/states"

// VersionLifecycle is a data-key version's declared lifecycle (ADR 0007, ADR
// 0047), as `zanskar key status` prints it.
var VersionLifecycle = states.New("data key version",
	[]string{"active", "superseded", "retired"},
	states.Move{From: "active", To: "superseded", By: "zanskar key rotate makes a newer version (key.rotate): this one only decrypts"},
	states.Move{From: "superseded", To: "retired", By: "not built: nothing sets retired_at; ADR 0007 calls it future work"},
).Describe(states.Doc{
	Derivation: "`active` is the highest id with `retired_at` null; any other such row is `superseded`; `retired_at` set is `retired` and the version is not loaded. " +
		"`rotated_at` is a different fact: the version was rewrapped by `key rotate-master`.",
	Notes: []string{
		"`retired_at` has readers and no writer; a version retired by hand while rows still reference it makes those rows unreadable.",
	},
})
