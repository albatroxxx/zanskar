// SPDX-License-Identifier: Apache-2.0

package settings

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// HostZone is the IANA name of the time zone the gateway host runs in: the
// TZ variable, else what /etc/localtime links to, else /etc/timezone, else
// UTC. Go's own time.Local only says "Local", which names nothing a browser
// can render in.
func HostZone() string {
	return hostZone(os.Getenv("TZ"), os.Readlink, os.ReadFile)
}

func hostZone(tz string, readlink func(string) (string, error), readFile func(string) ([]byte, error)) string {
	if z := zoneName(strings.TrimPrefix(tz, ":")); z != "" {
		return z
	}
	if target, err := readlink("/etc/localtime"); err == nil {
		if z := zoneName(target); z != "" {
			return z
		}
	}
	if b, err := readFile("/etc/timezone"); err == nil {
		if z := zoneName(strings.TrimSpace(string(b))); z != "" {
			return z
		}
	}
	return "UTC"
}

// zoneName turns a TZ value or a zoneinfo path into a zone name Go and
// browsers both know, or "" when it is neither.
func zoneName(s string) string {
	if i := strings.Index(s, "zoneinfo/"); i >= 0 {
		s = s[i+len("zoneinfo/"):]
	}
	s = filepath.ToSlash(strings.TrimSpace(s))
	if validZone(s) {
		return s
	}
	return ""
}

// validZone accepts an IANA zone name the runtime can load: never "Local",
// a path, or anything long.
func validZone(s string) bool {
	if s == "" || s == "Local" || len(s) > 64 || strings.HasPrefix(s, "/") || strings.Contains(s, "..") {
		return false
	}
	for _, r := range s {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && !strings.ContainsRune("/_+-", r) {
			return false
		}
	}
	_, err := time.LoadLocation(s)
	return err == nil
}
