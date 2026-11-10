// SPDX-License-Identifier: Apache-2.0

package target

import (
	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/states"
)

// State is what holds of a target now (ADR 0047). Status is what an
// administrator set (active, disabled); a retired target (ADR 0019) has
// deleted_at set and is never returned, so `retired` is declared and never
// carried.
type State string

// Target states.
const (
	StateActive   State = "active"
	StateDisabled State = "disabled"
	StateRetired  State = "retired"
)

// StateOf derives the target's state from its status and whether it is retired.
func StateOf(status string, retired bool) State {
	if retired {
		return StateRetired
	}
	if status == StatusDisabled {
		return StateDisabled
	}
	return StateActive
}

// Lifecycle is the target's declared lifecycle; autoscaling groups share it.
var Lifecycle = states.New("target", []string{string(StateActive), string(StateDisabled), string(StateRetired)},
	states.Move{From: "active", To: "disabled", By: audit.TargetUpdate},
	states.Move{From: "disabled", To: "active", By: audit.TargetUpdate},
	states.Move{From: "active", To: "retired", By: audit.TargetDelete},
	states.Move{From: "disabled", To: "retired", By: audit.TargetDelete},
).Describe(states.Doc{
	Field:   "state",
	Schemas: []string{"Target", "AutoscalingGroup"},
	Derivation: "The stored `status`. A retired row (`deleted_at` set) is read by no list or lookup, so `retired` never reaches " +
		"the wire; it is declared so the document says where a deleted target goes.",
	Notes: []string{
		"Retiring sets `status` to `disabled` as well, so every reader must add `deleted_at IS NULL`; the repository does.",
		"An update that leaves `status` out writes `active`: the API default, not the current value (OpenAPI `TargetWrite`).",
		"Autoscaling groups (`AutoscalingGroup.state`) follow the same lifecycle with `asg.update` and `asg.delete`.",
	},
})

// HostKeyLifecycle is the SSH host key's declared lifecycle: trust on first
// use, then an administrator's word.
var HostKeyLifecycle = states.New("host key",
	[]string{string(HostKeyUnknown), string(HostKeyPending), string(HostKeyTrusted), string(HostKeyChanged)},
	states.Move{From: "unknown", To: "pending", By: audit.TargetProbe + " sees a key"},
	states.Move{From: "pending", To: "pending", By: audit.TargetProbe + " sees another key (fingerprint replaced)"},
	states.Move{From: "pending", To: "trusted", By: audit.TargetHostKeyTrust},
	states.Move{From: "trusted", To: "changed", By: audit.TargetHostKeyChanged + " (live sessions end trust_lost)"},
	states.Move{From: "changed", To: "trusted", By: audit.TargetHostKeyTrust},
	states.Move{From: "pending", To: "unknown", By: "the address changes (" + audit.TargetUpdate + ")"},
	states.Move{From: "trusted", To: "unknown", By: "the address changes (" + audit.TargetUpdate + ")"},
	states.Move{From: "changed", To: "unknown", By: "the address changes (" + audit.TargetUpdate + ")"},
).Describe(states.Doc{
	Field:      "host_key_status",
	Schemas:    []string{"Target", "ProbeResult"},
	Derivation: "The stored `host_key_status`; `host_key_fingerprint` is the key it speaks of.",
	Notes: []string{
		"A key seen at a dial that differs from the trusted one is refused and audited (`target.hostkey.mismatch`) but changes no state: only a probe does.",
		"`unknown` also reads for a database or application, which is never probed for a key; the console hides it there.",
	},
})

// CertificateStatus is what holds of a Windows listener's pinned certificate
// (RDP, WinRM; ADR 0012): none seen yet, pinned, or a different one seen after
// the pin, awaiting an administrator. The host key's words, so the console
// speaks one language for trust.
type CertificateStatus string

// Certificate pin states.
const (
	CertificateNone    CertificateStatus = "none"
	CertificatePinned  CertificateStatus = "pinned"
	CertificateChanged CertificateStatus = "changed"
)

// CertificateStateOf derives a pin's state from the pinned and the pending fingerprint.
func CertificateStateOf(pinned, pending *string) CertificateStatus {
	switch {
	case pinned == nil || *pinned == "":
		return CertificateNone
	case pending != nil && *pending != "":
		return CertificateChanged
	}
	return CertificatePinned
}

// CertificateLifecycle is the pin's declared lifecycle, one per protocol.
var CertificateLifecycle = states.New("certificate pin",
	[]string{string(CertificateNone), string(CertificatePinned), string(CertificateChanged)},
	states.Move{From: "none", To: "pinned", By: audit.TargetProbe + " sees the first certificate"},
	states.Move{From: "pinned", To: "changed", By: audit.TargetTLSChanged + " (live sessions end trust_lost)"},
	states.Move{From: "changed", To: "pinned", By: audit.TargetTLSTrust},
	states.Move{From: "changed", To: "pinned", By: audit.TargetProbe + " sees the pinned certificate again"},
	states.Move{From: "pinned", To: "none", By: "the address changes (" + audit.TargetUpdate + ")"},
	states.Move{From: "changed", To: "none", By: "the address changes (" + audit.TargetUpdate + ")"},
).Describe(states.Doc{
	Field:      "tls_status",
	Schemas:    []string{"Target"},
	Derivation: "`none` with no pin, `changed` while a pending fingerprint waits beside the pin, else `pinned`; `winrm_tls_status` is the same for the WinRM listener.",
	Notes: []string{
		"Unlike the host key, the first certificate is pinned by the probe with no administrator's word, and a pending certificate does not stop a ticket: the session fails at redeem with `certificate_mismatch`.",
	},
})

// derive fills the computed fields from the stored ones (ADR 0047).
func (t *Target) derive() {
	t.State = StateOf(t.Status, false)
	t.TLSStatus = CertificateStateOf(t.TLSFingerprint, t.TLSFingerprintPending)
	t.WinRMTLSStatus = CertificateStateOf(t.WinRMTLSFingerprint, t.WinRMTLSFingerprintPending)
}
