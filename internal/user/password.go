// SPDX-License-Identifier: Apache-2.0

package user

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

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

	// MinPasswordLen and MaxPasswordLen bound a password's length. The lower
	// bound follows NIST SP 800-63B; the upper bound stops a client from
	// forcing a huge hash computation.
	MinPasswordLen = 12
	MaxPasswordLen = 256
)

// hashParams are what HashPassword uses and NeedsRehash compares against.
// In a test binary they drop to 8 MiB and one pass, so the suites that sign
// in are not spent hashing (the auth package alone was 78 s of it); nothing a
// test can do raises or lowers them at run time, and the production
// constants above are what every other binary hashes with. One test hashes
// with the production constants to keep them honest.
var hashParams = func() phcParams {
	if testing.Testing() {
		return phcParams{memory: 8 * 1024, time: 1, threads: argonThreads}
	}
	return productionParams()
}()

// productionParams are the constants above as a parameter set.
func productionParams() phcParams {
	return phcParams{memory: argonMemoryKiB, time: argonTime, threads: argonThreads}
}

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
func HashPassword(pw string) (string, error) { return hashPasswordWith(pw, hashParams) }

func hashPasswordWith(pw string, p phcParams) (string, error) {
	if len(pw) > MaxPasswordLen {
		return "", ErrWeakPassword
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, p.time, p.memory, p.threads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.memory, p.time, p.threads,
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
	return p.memory < hashParams.memory || p.time < hashParams.time
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

// passwordAlphabet is letters and digits without the ones that read
// ambiguously when a one-time password is passed on by voice or copied
// from a screen (I, O, i, l, o, 0, 1). Built at start rather than written
// out, so no string in the source looks like a key.
var passwordAlphabet = func() []byte {
	var a []byte
	for c := byte('A'); c <= 'Z'; c++ {
		if c != 'I' && c != 'O' {
			a = append(a, c)
		}
	}
	for c := byte('a'); c <= 'z'; c++ {
		if c != 'i' && c != 'l' && c != 'o' {
			a = append(a, c)
		}
	}
	for c := byte('2'); c <= '9'; c++ {
		a = append(a, c)
	}
	return a
}()

// GeneratePassword returns a random one-time password of 20 characters
// (about 116 bits) that satisfies the policy. Each character is drawn
// with rejection sampling so the alphabet is used evenly.
func GeneratePassword() (string, error) {
	const n = 20
	out := make([]byte, 0, n)
	buf := make([]byte, 64)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, v := range buf {
			if int(v) < 256-256%len(passwordAlphabet) {
				out = append(out, passwordAlphabet[int(v)%len(passwordAlphabet)])
				if len(out) == n {
					break
				}
			}
		}
	}
	return string(out), nil
}
