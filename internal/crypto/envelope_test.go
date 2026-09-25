// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	master := bytes.Repeat([]byte{7}, 32)
	kek, err := NewLocalKEK(master)
	if err != nil {
		t.Fatal(err)
	}
	dek, err := NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := kek.Wrap(context.Background(), dek, []byte("key_versions:1"))
	if err != nil {
		t.Fatal(err)
	}
	unwrapped, err := kek.Unwrap(context.Background(), wrapped, []byte("key_versions:1"))
	if err != nil || !bytes.Equal(dek, unwrapped) {
		t.Fatalf("unwrap mismatch: %v", err)
	}
	if _, err := kek.Unwrap(context.Background(), wrapped, []byte("key_versions:2")); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("expected aad mismatch to fail, got %v", err)
	}

	ct, err := Encrypt(dek, []byte("hunter2"), []byte("credentials:abc"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Decrypt(dek, ct, []byte("credentials:abc"))
	if err != nil || string(pt) != "hunter2" {
		t.Fatalf("decrypt: %v %q", err, pt)
	}
	ct[len(ct)-1] ^= 1
	if _, err := Decrypt(dek, ct, []byte("credentials:abc")); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("expected tamper detection, got %v", err)
	}
}

func TestRejectsShortKeys(t *testing.T) {
	if _, err := NewLocalKEK([]byte("short")); err == nil {
		t.Fatal("expected error for short master key")
	}
	if _, err := Encrypt([]byte("short"), []byte("x"), nil); err == nil {
		t.Fatal("expected error for short dek")
	}
}

func TestNoncesDiffer(t *testing.T) {
	dek, _ := NewDEK()
	a, _ := Encrypt(dek, []byte("same"), nil)
	b, _ := Encrypt(dek, []byte("same"), nil)
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions of the same plaintext must differ")
	}
}

func TestRejectsOversizedPlaintext(t *testing.T) {
	dek, err := NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Encrypt(dek, make([]byte, MaxPlaintext+1), nil); !errors.Is(err, ErrPlaintextTooLarge) {
		t.Fatalf("Encrypt over the ceiling: got %v, want ErrPlaintextTooLarge", err)
	}
	// Exactly at the ceiling is fine.
	if _, err := Encrypt(dek, make([]byte, MaxPlaintext), nil); err != nil {
		t.Fatalf("Encrypt at the ceiling: %v", err)
	}
}
