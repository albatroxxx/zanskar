// SPDX-License-Identifier: Apache-2.0

// Package migrations embeds the SQL migration sets, one directory per driver.
// The two sets must contain the same file names; CI enforces this.
package migrations

import "embed"

// FS holds postgres/*.sql and sqlite/*.sql.
//
//go:embed postgres/*.sql sqlite/*.sql
var FS embed.FS
