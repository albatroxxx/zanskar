// SPDX-License-Identifier: Apache-2.0

// Package crypto implements envelope encryption (ADR 0007).
//
// Every secret is encrypted with its own data-encryption key (DEK) under
// AES-256-GCM. DEKs are wrapped by a key-encryption key (KEK) that comes from a
// KEKProvider: a local master key today, AWS KMS or Vault Transit later. Rotating
// the KEK re-wraps DEKs and never touches secret ciphertext.
package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

const (
	keySize   = 32
	nonceSize = 12
)

// ErrInvalidCiphertext is returned when decryption fails for any reason. The
// reason is deliberately not distinguished to avoid oracle behaviour.
var ErrInvalidCiphertext = errors.New("crypto: invalid ciphertext")

// KEKProvider wraps and unwraps data-encryption keys.
type KEKProvider interface {
	// Wrap returns the wrapped DEK. aad binds the wrapping to a context such as
	// the key_versions row id.
	Wrap(ctx context.Context, dek, aad []byte) ([]byte, error)
	Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error)
	// Source names the provider for the key_versions.kek_source column.
	Source() string
}

// LocalKEK wraps DEKs with a 32-byte master key held in memory.
type LocalKEK struct {
	aead cipher.AEAD
}

// NewLocalKEK builds a provider from a 32-byte master key.
func NewLocalKEK(masterKey []byte) (*LocalKEK, error) {
	aead, err := newAEAD(masterKey)
	if err != nil {
		return nil, err
	}
	return &LocalKEK{aead: aead}, nil
}

// Wrap implements KEKProvider.
func (l *LocalKEK) Wrap(_ context.Context, dek, aad []byte) ([]byte, error) {
	return seal(l.aead, dek, aad)
}

// Unwrap implements KEKProvider.
func (l *LocalKEK) Unwrap(_ context.Context, wrapped, aad []byte) ([]byte, error) {
	return open(l.aead, wrapped, aad)
}

// Source implements KEKProvider.
func (l *LocalKEK) Source() string { return "local" }

// NewDEK returns a fresh random 32-byte data-encryption key.
func NewDEK() ([]byte, error) {
	dek := make([]byte, keySize)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("crypto: generate dek: %w", err)
	}
	return dek, nil
}

// Encrypt seals plaintext with the DEK. aad should identify the owning record
// (for example "credentials:<id>") so ciphertext cannot be moved between rows.
func Encrypt(dek, plaintext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(dek)
	if err != nil {
		return nil, err
	}
	return seal(aead, plaintext, aad)
}

// Decrypt opens ciphertext produced by Encrypt with the same DEK and aad.
func Decrypt(dek, ciphertext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(dek)
	if err != nil {
		return nil, err
	}
	return open(aead, ciphertext, aad)
}

// Zero overwrites b. Call it on DEKs and plaintext secrets once done with them.
// Go gives no guarantee about copies made by the runtime, so this is best-effort.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("crypto: key must be %d bytes, got %d", keySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// seal output layout: nonce || ciphertext || tag.
func seal(aead cipher.AEAD, plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: nonce: %w", err)
	}
	out := make([]byte, 0, nonceSize+len(plaintext)+aead.Overhead())
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, aad), nil
}

func open(aead cipher.AEAD, blob, aad []byte) ([]byte, error) {
	if len(blob) < nonceSize+aead.Overhead() {
		return nil, ErrInvalidCiphertext
	}
	pt, err := aead.Open(nil, blob[:nonceSize], blob[nonceSize:], aad)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}
	return pt, nil
}

// DeriveKey derives a 32-byte subkey from the master key for a named purpose
// using HKDF-SHA256, so one master secret can safely back several uses
// (KEK wrapping, CSRF HMAC) without any key being reused across them.
func DeriveKey(master []byte, purpose string) ([]byte, error) {
	if len(master) != keySize {
		return nil, fmt.Errorf("crypto: master key must be %d bytes", keySize)
	}
	return hkdf.Key(sha256.New, master, nil, purpose, keySize)
}
