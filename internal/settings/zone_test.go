// SPDX-License-Identifier: Apache-2.0

package settings

import (
	"errors"
	"testing"
)

// TestHostZone: the zone comes from TZ, else /etc/localtime's link, else
// /etc/timezone, else UTC; anything that is not a loadable zone name is
// passed over.
func TestHostZone(t *testing.T) {
	none := func(string) (string, error) { return "", errors.New("no link") }
	noFile := func(string) ([]byte, error) { return nil, errors.New("no file") }
	link := func(target string) func(string) (string, error) {
		return func(string) (string, error) { return target, nil }
	}
	file := func(body string) func(string) ([]byte, error) {
		return func(string) ([]byte, error) { return []byte(body), nil }
	}
	for _, tc := range []struct {
		name     string
		tz       string
		readlink func(string) (string, error)
		readFile func(string) ([]byte, error)
		want     string
	}{
		{"TZ", "Asia/Kolkata", none, noFile, "Asia/Kolkata"},
		{"TZ with a colon", ":Europe/London", none, noFile, "Europe/London"},
		{"TZ as a path", "/usr/share/zoneinfo/America/New_York", none, noFile, "America/New_York"},
		{"link", "", link("/usr/share/zoneinfo/Asia/Kolkata"), noFile, "Asia/Kolkata"},
		{"relative link", "", link("../usr/share/zoneinfo/Etc/UTC"), noFile, "Etc/UTC"},
		{"timezone file", "", none, file("Europe/Berlin\n"), "Europe/Berlin"},
		{"junk TZ falls through", "not a zone", link("/usr/share/zoneinfo/Asia/Tokyo"), noFile, "Asia/Tokyo"},
		{"nothing", "", none, noFile, "UTC"},
		{"junk everywhere", "Local", link("/etc/whatever"), file("../../etc/passwd"), "UTC"},
	} {
		if got := hostZone(tc.tz, tc.readlink, tc.readFile); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestTimeZoneSetting: only a zone name the runtime can load is accepted.
func TestTimeZoneSetting(t *testing.T) {
	d, ok := Lookup(KeyTimeZone)
	if !ok || d.Type != TypeTimeZone || !validZone(d.Default) {
		t.Fatalf("definition: %+v", d)
	}
	for _, good := range []string{"Asia/Kolkata", " Europe/London ", "UTC", "America/Argentina/Buenos_Aires", "Etc/GMT+5"} {
		if _, err := Validate(d, good); err != nil {
			t.Errorf("%q refused: %v", good, err)
		}
	}
	for _, bad := range []string{"", "Local", "Mars/Olympus", "/etc/passwd", "../../etc/passwd", "Asia/\nKolkata", "Asia Kolkata", string(make([]byte, 80))} {
		if _, err := Validate(d, bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestACMESettings (ADR 0021, amended 2026-10-30): the account email is an
// address or nothing, and the directory an https URL.
func TestACMESettings(t *testing.T) {
	email, _ := Lookup(KeyACMEEmail)
	dir, _ := Lookup(KeyACMEDirectory)
	for _, ok := range []string{"", "ops@example.com"} {
		if _, err := Validate(email, ok); err != nil {
			t.Errorf("email %q: %v", ok, err)
		}
	}
	for _, bad := range []string{"ops", "ops@", "a b@example.com", "ops@example"} {
		if _, err := Validate(email, bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("email %q accepted", bad)
		}
	}
	if _, err := Validate(dir, LetsEncryptDirectory); err != nil || dir.Default != LetsEncryptDirectory {
		t.Fatalf("directory default: %v", err)
	}
	for _, bad := range []string{"http://acme.example/dir", "acme.example/dir", "https://"} {
		if _, err := Validate(dir, bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("directory %q accepted", bad)
		}
	}
}
