// SPDX-License-Identifier: Apache-2.0

// Package protocol spells, once, the ways of reaching a target and the
// database engines a database target runs. It imports nothing from Zanskar,
// so the packages target itself imports (policy, gateway) share the names
// rather than repeating them as bare strings, where a typo compiles.
package protocol

import (
	"slices"
	"strings"
)

// Protocols, as policies, grants and sessions store them. target.Protocol
// gives them a type for a target's own fields.
const (
	SSH      = "ssh"
	RDP      = "rdp"
	VNC      = "vnc"
	WinRM    = "winrm"
	Database = "database" // managed/PaaS database access (ADR 0017)
	HTTP     = "http"     // a web application opened in an isolated browser beside the gateway (ADR 0034)
)

// Terminal reports whether p is a text shell, whose output a tap can fan
// out to a shadowing admin.
func Terminal(p string) bool { return p == SSH || p == WinRM }

// Desktop reports whether p is a remote desktop drawn through guacd.
func Desktop(p string) bool { return p == RDP || p == VNC }

// Name is how p reads in a label: SSH, RDP and VNC are acronyms, WinRM keeps
// its spelling, and "database" is a word, not a code. The console spells
// them the same way.
func Name(p string) string {
	switch p {
	case WinRM:
		return "WinRM"
	case Database:
		return Database
	default:
		return strings.ToUpper(p)
	}
}

// Database engines (ADR 0017).
const (
	Postgres = "postgres"
	MySQL    = "mysql"
	MariaDB  = "mariadb"
)

// Kinds of thing an access policy grants (ADR 0036). A target's kind is
// derived, never stored: an engine makes it a database, an upstream an
// application, anything else a host. Autoscaling groups are a kind of their
// own.
const (
	KindHost        = "host"
	KindDatabase    = "database"
	KindApplication = "application"
	KindAutoscaling = "autoscaling"
)

// Kinds lists every kind, in the order the console offers them.
var Kinds = []string{KindHost, KindDatabase, KindApplication, KindAutoscaling}

// kindProtocols is what each kind can serve. A grant offers only these, so a
// policy can no longer say ssh to a database.
var kindProtocols = map[string][]string{
	KindHost:        {SSH, RDP, VNC, WinRM},
	KindAutoscaling: {SSH, RDP, VNC, WinRM},
	KindDatabase:    {Database},
	KindApplication: {HTTP},
}

// ValidKind reports whether k is a kind.
func ValidKind(k string) bool {
	_, ok := kindProtocols[k]
	return ok
}

// KindProtocols returns the protocols a thing of kind k can serve.
func KindProtocols(k string) []string { return slices.Clone(kindProtocols[k]) }

// KindServes reports whether a thing of kind k can serve protocol p.
func KindServes(k, p string) bool { return slices.Contains(kindProtocols[k], p) }
