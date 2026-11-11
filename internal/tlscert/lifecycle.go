// SPDX-License-Identifier: Apache-2.0

package tlscert

import (
	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/states"
)

// SourceLifecycle is which certificate the gateway serves (ADR 0021, ADR
// 0047): uploaded in the console, from the environment's files, or made by
// the gateway, in that order of precedence.
var SourceLifecycle = states.New("TLS certificate source",
	[]string{SourceGenerated, SourceFile, SourceUploaded},
	states.Move{From: SourceGenerated, To: SourceUploaded, By: audit.TLSCertificateUpload},
	states.Move{From: SourceFile, To: SourceUploaded, By: audit.TLSCertificateUpload},
	states.Move{From: SourceUploaded, To: SourceFile, By: audit.TLSCertificateReset + " with ZANSKAR_TLS_CERT set"},
	states.Move{From: SourceUploaded, To: SourceGenerated, By: audit.TLSCertificateReset + " with no file; or at start, when the upload can no longer serve"},
	states.Move{From: SourceGenerated, To: SourceGenerated, By: audit.TLSCertificateRegenerate + "; the 6-hourly renewal within 30 days of its end (no event)"},
).Describe(states.Doc{
	Field:      "source",
	Schemas:    []string{"TLSCertInfo"},
	Derivation: "`TLSStatus.active.source`; the mode (`file`, `managed`, `proxy`) is fixed for the process and says who terminates TLS, not which certificate.",
	Notes: []string{
		"An uploaded certificate that expires while the process runs keeps serving until a restart; only the generated one is renewed.",
	},
})
