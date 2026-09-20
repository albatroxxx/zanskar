// SPDX-License-Identifier: Apache-2.0

// Package version exposes build metadata injected at link time.
package version

// Version is set via -ldflags "-X .../internal/version.Version=v1.2.3".
var Version = "dev"
