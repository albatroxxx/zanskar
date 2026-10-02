// SPDX-License-Identifier: Apache-2.0

//go:build unix

package recording

import (
	"fmt"
	"os"
	"syscall"
)

// checkSpoolDir refuses a spool directory another local user could tamper
// with. The default lives under the system temp directory, where anyone can
// create "zanskar-spool" first; whoever owns it could swap a recording before
// it is uploaded. The directory must be a real directory (not a symlink),
// owned by this process's user, and writable by no one else.
func checkSpoolDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	switch {
	case !info.IsDir():
		return fmt.Errorf("recording: spool %s is not a directory (a symlink?); set ZANSKAR_RECORDINGS_SPOOL_DIR to a private directory", dir)
	case !ok || int(st.Uid) != os.Geteuid():
		return fmt.Errorf("recording: spool %s is owned by another user; set ZANSKAR_RECORDINGS_SPOOL_DIR to a private directory", dir)
	case info.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("recording: spool %s is writable by other users (mode %o); set ZANSKAR_RECORDINGS_SPOOL_DIR to a private directory", dir, info.Mode().Perm())
	}
	return nil
}
