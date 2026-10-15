// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lifecycle

import "syscall"

// statDev is a stat result's device id, already a uint64 on Linux.
func statDev(st *syscall.Stat_t) uint64 { return st.Dev }
