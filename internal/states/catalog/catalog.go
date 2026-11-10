// SPDX-License-Identifier: Apache-2.0

// Package catalog lists every declared lifecycle (ADR 0047), so the guard
// tests in cmd/zanskar and the generator in hack/gen-lifecycles read one
// list. A lifecycle that is not here is not guarded and not documented.
package catalog

import (
	"strings"

	"github.com/albatroxxx/zanskar/internal/access"
	"github.com/albatroxxx/zanskar/internal/apitoken"
	"github.com/albatroxxx/zanskar/internal/asg"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/connect"
	"github.com/albatroxxx/zanskar/internal/credential"
	"github.com/albatroxxx/zanskar/internal/idp"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/lifecycle"
	"github.com/albatroxxx/zanskar/internal/notify"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/states"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/tlscert"
	"github.com/albatroxxx/zanskar/internal/user"
)

// All returns every declared lifecycle, exposed ones first, in the order the
// document shows them.
func All() []states.Lifecycle {
	return []states.Lifecycle{
		session.Lifecycle,
		session.RecordingLifecycle,
		target.Lifecycle,
		target.HostKeyLifecycle,
		target.CertificateLifecycle,
		asg.InstanceLifecycle,
		user.Lifecycle,
		access.Lifecycle,
		apitoken.Lifecycle,
		credential.RotationLifecycle,
		policy.ReviewLifecycle,
		lifecycle.EnvFileLifecycle,
		tlscert.SourceLifecycle,
		// Declared and documented, carried by no field of their own: the
		// phases live in memory or in words the schema already has.
		connect.FlowLifecycle,
		auth.SignInLifecycle,
		auth.SessionLifecycle,
		auth.AuthenticatorLifecycle,
		lifecycle.DrainLifecycle,
		lifecycle.BootChangeLifecycle,
		lifecycle.InstallLifecycle,
		idp.SyncLifecycle,
		notify.ChannelLifecycle,
		keyring.VersionLifecycle,
	}
}

// Exposed returns the lifecycles an API field carries.
func Exposed() []states.Lifecycle {
	var out []states.Lifecycle
	for _, l := range All() {
		if l.Exposed() {
			out = append(out, l)
		}
	}
	return out
}

// Document renders docs/lifecycles.md from the declarations. The file is
// checked in so a reader (or an agent) finds it without running anything;
// TestLifecyclesDocIsCurrent fails when it is stale.
func Document() string {
	var b strings.Builder
	b.WriteString(`# Lifecycles

Generated from the declarations in the code (` + "`go run ./hack/gen-lifecycles > docs/lifecycles.md`" + `);
do not edit by hand. [ADR 0047](adr/0047-lifecycles-declared-once.md) is the decision.

Every record below has a stored ` + "`status`" + ` (what was set) and a computed ` + "`state`" + ` (what holds now,
from the row and the clock), or only the latter. The field named under each heading carries the state
on the wire; its OpenAPI enum, the console's labels in ` + "`web/src/api/states.ts`" + ` and this document are
held to the declaration by the tests in ` + "`cmd/zanskar/lifecycles_test.go`" + `. A move is drawn with what
makes it: an audit action where one is recorded, otherwise the code path in words.

`)
	for i, l := range All() {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(l.Markdown())
	}
	return b.String()
}
