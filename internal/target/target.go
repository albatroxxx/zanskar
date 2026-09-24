// SPDX-License-Identifier: Apache-2.0

// Package target holds static targets: machines enrolled by address. Each
// target advertises which protocols answered on its last probe, pins its SSH
// host key and TLS certificate, and maps a credential to each protocol.
// Autoscaling targets are a separate domain.
package target

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// Protocol is a way of reaching a target.
type Protocol string

// Protocols.
const (
	SSH      Protocol = "ssh"
	RDP      Protocol = "rdp"
	VNC      Protocol = "vnc"
	WinRM    Protocol = "winrm"
	Database Protocol = "database" // managed/PaaS database access (ADR 0017)
)

// Protocols lists the host protocols probed in a stable order. Database is not
// probed (it is a managed endpoint, not a host), so it is not included here.
var Protocols = []Protocol{SSH, RDP, VNC, WinRM}

// CredentialProtocols are the protocols a target may bind a vaulted credential
// to, in a stable order: the probed host protocols plus database (ADR 0017),
// which is not probed but still authenticates through a stored credential.
var CredentialProtocols = []Protocol{SSH, RDP, VNC, WinRM, Database}

// DefaultPorts are used when a target does not override a port.
var DefaultPorts = map[Protocol]int{SSH: 22, RDP: 3389, VNC: 5900, WinRM: 5986}

// EngineDefaultPorts maps a database engine to its default port; a database
// target's port defaults from its engine (ADR 0017).
var EngineDefaultPorts = map[string]int{"postgres": 5432, "mysql": 3306, "mariadb": 3306}

// ValidProtocol reports whether p is known.
func ValidProtocol(p Protocol) bool {
	if p == Database {
		return true
	}
	_, ok := DefaultPorts[p]
	return ok
}

// ValidEngine reports whether e is a supported database engine.
func ValidEngine(e string) bool {
	_, ok := EngineDefaultPorts[e]
	return ok
}

// OSFamily of the target.
type OSFamily string

// OS families.
const (
	Linux   OSFamily = "linux"
	Windows OSFamily = "windows"
	OtherOS OSFamily = "other"
)

// HostKeyStatus tracks SSH host key trust (trust on first use, then admin approval).
type HostKeyStatus string

// Host key states.
const (
	HostKeyUnknown HostKeyStatus = "unknown" // never probed
	HostKeyPending HostKeyStatus = "pending" // seen, awaiting admin trust
	HostKeyTrusted HostKeyStatus = "trusted" // admin approved this fingerprint
	HostKeyChanged HostKeyStatus = "changed" // a different key appeared after trust; connections refused
)

// Status of a target.
const (
	StatusActive   = "active"
	StatusDisabled = "disabled"
)

// Limits.
const (
	MaxNameLen  = 64
	MaxNotesLen = 4000
	MaxTags     = 32
	MaxTagLen   = 64
)

// Target is an enrolled machine.
type Target struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	// Engine and EngineVersion are set for database targets (ADR 0017); the
	// engine sets the default port and, at connect time, the client image.
	Engine              string              `json:"engine,omitempty"`
	EngineVersion       string              `json:"engine_version,omitempty"`
	OSFamily            OSFamily            `json:"os_family"`
	Ports               map[Protocol]int    `json:"ports"`
	Capabilities        []Protocol          `json:"capabilities"`
	HostKeyFingerprint  *string             `json:"host_key_fingerprint"`
	HostKeyStatus       HostKeyStatus       `json:"host_key_status"`
	TLSFingerprint      *string             `json:"tls_fingerprint"`       // RDP listener certificate, SHA-256 hex
	WinRMTLSFingerprint *string             `json:"winrm_tls_fingerprint"` // WinRM HTTPS listener certificate, SHA-256 hex
	Tags                map[string]string   `json:"tags"`
	Status              string              `json:"status"`
	Notes               string              `json:"notes"`
	Credentials         map[Protocol]string `json:"credentials"`
	CreatedBy           *string             `json:"created_by"`
	CreatedAt           time.Time           `json:"created_at"`
	UpdatedAt           time.Time           `json:"updated_at"`
	LastProbedAt        *time.Time          `json:"last_probed_at"`
}

// Port returns the effective port for p.
func (t *Target) Port(p Protocol) int {
	if p == Database {
		if n, ok := t.Ports[p]; ok && n > 0 {
			return n
		}
		return EngineDefaultPorts[t.Engine]
	}
	if n, ok := t.Ports[p]; ok && n > 0 {
		return n
	}
	return DefaultPorts[p]
}

// EffectivePorts returns every protocol's port, defaults filled in.
func (t *Target) EffectivePorts() map[Protocol]int {
	out := make(map[Protocol]int, len(Protocols))
	for _, p := range Protocols {
		out[p] = t.Port(p)
	}
	return out
}

// HasCapability reports whether the last probe (or the admin) declared p.
func (t *Target) HasCapability(p Protocol) bool {
	for _, c := range t.Capabilities {
		if c == p {
			return true
		}
	}
	return false
}

// Errors.
var (
	ErrNotFound            = errors.New("target: not found")
	ErrDuplicate           = errors.New("target: name already exists")
	ErrInvalid             = errors.New("target: invalid")
	ErrInvalidCredential   = errors.New("target: credential does not exist")
	ErrFingerprintMismatch = errors.New("target: fingerprint does not match the pending host key")
	ErrNoPendingHostKey    = errors.New("target: no host key awaiting trust")
)

var hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,62}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,62}[a-zA-Z0-9])?)*\.?$`)

// ValidAddress accepts a bare hostname or an IP literal: no scheme, no port,
// no brackets, no path.
func ValidAddress(s string) bool {
	if s == "" || len(s) > 253 || strings.ContainsAny(s, " \t/\\@[]") {
		return false
	}
	if ip := net.ParseIP(s); ip != nil {
		return true
	}
	return hostnameRe.MatchString(s)
}

// Validate checks the editable fields and normalises them.
func (t *Target) Validate() error {
	t.Name = strings.TrimSpace(t.Name)
	t.Address = strings.TrimSpace(t.Address)
	if t.Name == "" || len(t.Name) > MaxNameLen {
		return fmt.Errorf("%w: name must be 1-%d characters", ErrInvalid, MaxNameLen)
	}
	if !ValidAddress(t.Address) {
		return fmt.Errorf("%w: address must be a hostname or IP without scheme or port", ErrInvalid)
	}
	// A database target (ADR 0017) is a managed endpoint, not a host: it is
	// identified by its engine, and its os_family defaults to "other" since the
	// host-oriented notions (SSH host key, RDP/WinRM certificate) do not apply.
	if t.Engine != "" {
		t.Engine = strings.ToLower(strings.TrimSpace(t.Engine))
		if !ValidEngine(t.Engine) {
			return fmt.Errorf("%w: engine must be one of postgres, mysql, mariadb", ErrInvalid)
		}
		t.EngineVersion = strings.TrimSpace(t.EngineVersion)
		if t.OSFamily == "" {
			t.OSFamily = OtherOS
		}
	}
	switch t.OSFamily {
	case Linux, Windows, OtherOS:
	default:
		return fmt.Errorf("%w: os_family must be linux, windows or other", ErrInvalid)
	}
	if t.Status == "" {
		t.Status = StatusActive
	}
	if t.Status != StatusActive && t.Status != StatusDisabled {
		return fmt.Errorf("%w: status must be active or disabled", ErrInvalid)
	}
	if t.Ports == nil {
		t.Ports = map[Protocol]int{}
	}
	for p, n := range t.Ports {
		if !ValidProtocol(p) {
			return fmt.Errorf("%w: unknown protocol %q in ports", ErrInvalid, p)
		}
		if n < 1 || n > 65535 {
			return fmt.Errorf("%w: port for %s must be 1-65535", ErrInvalid, p)
		}
	}
	if t.Capabilities == nil {
		t.Capabilities = []Protocol{}
	}
	seen := map[Protocol]bool{}
	caps := t.Capabilities[:0]
	for _, c := range t.Capabilities {
		if !ValidProtocol(c) {
			return fmt.Errorf("%w: unknown capability %q", ErrInvalid, c)
		}
		if !seen[c] {
			seen[c] = true
			caps = append(caps, c)
		}
	}
	t.Capabilities = caps
	if t.Tags == nil {
		t.Tags = map[string]string{}
	}
	if len(t.Tags) > MaxTags {
		return fmt.Errorf("%w: at most %d tags", ErrInvalid, MaxTags)
	}
	for k, v := range t.Tags {
		if k == "" || len(k) > MaxTagLen || len(v) > MaxTagLen {
			return fmt.Errorf("%w: tag keys and values must be 1-%d characters", ErrInvalid, MaxTagLen)
		}
	}
	if len(t.Notes) > MaxNotesLen {
		return fmt.Errorf("%w: notes must be at most %d characters", ErrInvalid, MaxNotesLen)
	}
	if t.Credentials == nil {
		t.Credentials = map[Protocol]string{}
	}
	for p, id := range t.Credentials {
		if !ValidProtocol(p) {
			return fmt.Errorf("%w: unknown protocol %q in credentials", ErrInvalid, p)
		}
		if id == "" {
			return fmt.Errorf("%w: empty credential id for %s", ErrInvalid, p)
		}
	}
	return nil
}

// IsDatabase reports whether the target is a managed database endpoint (ADR 0017).
func (t *Target) IsDatabase() bool { return t.Engine != "" }

// MatchesTags reports whether every key in want is present with the same value.
func (t *Target) MatchesTags(want map[string]string) bool {
	for k, v := range want {
		if t.Tags[k] != v {
			return false
		}
	}
	return true
}
