// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package recording

// checkSpoolDir has no ownership model to check off Unix; releases are
// Linux-only, and this keeps other builds compiling.
func checkSpoolDir(string) error { return nil }
