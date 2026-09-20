// SPDX-License-Identifier: Apache-2.0

package user

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. Memory 64 MiB, 3 passes, 1 lane: above the OWASP
// minimum and about 100 ms on a modern core, so a login is cheap for a person
// and expensive for an offline attacker.
const (
	argonMemoryKiB = 64 * 1024
	argonTime      = 3
	argonThreads   = 1
	argonKeyLen    = 32
	argonSaltLen   = 16

	// Password length limits. The lower bound follows NIST SP 800-63B; the
	// upper bound stops a client from forcing a huge hash computation.
	MinPasswordLen = 12
	MaxPasswordLen = 256
)

// ErrWeakPassword is returned by CheckPasswordPolicy.
var ErrWeakPassword = errors.New("password does not meet policy")

// CheckPasswordPolicy enforces length only. Composition rules (digits, symbols)
// are deliberately not required; length and breach checks do more.
func CheckPasswordPolicy(pw string) error {
	if len(pw) < MinPasswordLen {
		return fmt.Errorf("%w: at least %d characters", ErrWeakPassword, MinPasswordLen)
	}
	if len(pw) > MaxPasswordLen {
		return fmt.Errorf("%w: at most %d characters", ErrWeakPassword, MaxPasswordLen)
	}
	return nil
}

// HashPassword returns a PHC-format argon2id string.
func HashPassword(pw string) (string, error) {
	if len(pw) > MaxPasswordLen {
		return "", ErrWeakPassword
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemoryKiB, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword reports whether pw matches the PHC hash. It returns false,
// never an error, for malformed hashes so callers cannot distinguish them.
func VerifyPassword(hash, pw string) bool {
	if len(pw) > MaxPasswordLen {
		return false
	}
	p, salt, want, err := parsePHC(hash)
	if err != nil {
		return false
	}
	if len(want) > 64 {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, p.time, p.memory, p.threads, uint32(len(want))) // #nosec G115 -- bounded above
	return subtle.ConstantTimeCompare(got, want) == 1
}

// NeedsRehash reports whether the hash was made with weaker parameters than
// the current ones, so it can be upgraded on next successful login.
func NeedsRehash(hash string) bool {
	p, _, _, err := parsePHC(hash)
	if err != nil {
		return true
	}
	return p.memory < argonMemoryKiB || p.time < argonTime
}

// dummyHash is verified against when a username does not exist, so a login
// attempt takes the same time whether or not the account is real.
var dummyHash = func() string {
	h, err := HashPassword("zanskar-dummy-password-for-timing")
	if err != nil {
		panic(err)
	}
	return h
}()

// BurnPasswordCheck spends the same CPU as a real verification.
func BurnPasswordCheck(pw string) {
	VerifyPassword(dummyHash, pw)
}

type phcParams struct {
	memory  uint32
	time    uint32
	threads uint8
}

func parsePHC(hash string) (phcParams, []byte, []byte, error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return phcParams{}, nil, nil, errors.New("not argon2id")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return phcParams{}, nil, nil, errors.New("bad version")
	}
	var p phcParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil {
		return phcParams{}, nil, nil, errors.New("bad params")
	}
	if p.memory == 0 || p.time == 0 || p.threads == 0 || p.memory > 1<<22 {
		return phcParams{}, nil, nil, errors.New("params out of range")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return phcParams{}, nil, nil, err
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) == 0 {
		return phcParams{}, nil, nil, errors.New("bad key")
	}
	return p, salt, key, nil
}
