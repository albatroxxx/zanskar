// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import "syscall"

// Everything zanskar writes is sensitive (the SQLite database and its WAL,
// session recordings, the env file, backups), so make files private by
// default regardless of the inherited umask. Deliberate modes set by the code
// (0o600 / 0o700) are unaffected; this only tightens what the runtime and
// libraries create with their defaults.
func init() {
	syscall.Umask(0o077)
}
