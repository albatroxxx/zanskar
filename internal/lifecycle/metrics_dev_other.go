// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package lifecycle

import "syscall"

// statDev widens the platform's device id (an int32 on Darwin) for use as a
// map key.
func statDev(st *syscall.Stat_t) uint64 { return uint64(st.Dev) } // #nosec G115 -- a device id, used as a map key only
