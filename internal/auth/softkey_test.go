// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// softKey is a security key in software for the tests (ADR 0028): an ES256
// key pair that answers the gateway's registration and assertion options as
// a browser and an authenticator would, with real signatures, so the
// verification under test is go-webauthn's own.
type softKey struct {
	priv   *ecdsa.PrivateKey
	id     []byte
	rpID   string
	origin string
	count  uint32
	// synced marks a passkey a platform keeps in sync (backup eligible and
	// backed up).
	synced bool
}

// newSoftKey is a key for the gateway at testOrigin.
func newSoftKey(t *testing.T) *softKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return &softKey{priv: priv, id: id, rpID: testRPID, origin: testOrigin}
}

var b64 = base64.RawURLEncoding

// challengeOf reads the challenge out of begin's answer.
func challengeOf(t *testing.T, options map[string]any) string {
	t.Helper()
	pk, ok := options["publicKey"].(map[string]any)
	if !ok {
		t.Fatalf("no publicKey in %v", options)
	}
	c, ok := pk["challenge"].(string)
	if !ok || c == "" {
		t.Fatalf("no challenge in %v", pk)
	}
	return c
}

// authData is the authenticator data: the relying party's hash, the flags,
// the counter, and attested is the credential data at registration.
func (k *softKey) authData(attested []byte) []byte {
	rp := sha256.Sum256([]byte(k.rpID))
	flags := byte(0x01 | 0x04) // user present, user verified
	if k.synced {
		flags |= 0x08 | 0x10 // backup eligible, backed up
	}
	if attested != nil {
		flags |= 0x40
	}
	out := append([]byte{}, rp[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, k.count)
	return append(out, attested...)
}

// create answers registration options as navigator.credentials.create would.
func (k *softKey) create(t *testing.T, options map[string]any) json.RawMessage {
	t.Helper()
	client, _ := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": challengeOf(t, options), "origin": k.origin})
	// The uncompressed point is 0x04, then X, then Y, 32 bytes each.
	point, err := k.priv.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	cose, err := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: point[1:33], -3: point[33:65]})
	if err != nil {
		t.Fatal(err)
	}
	attested := make([]byte, 16) // a zero AAGUID: no model named
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(k.id)))
	attested = append(attested, k.id...)
	attested = append(attested, cose...)
	att, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": k.authData(attested)})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(k.id), "rawId": b64.EncodeToString(k.id), "type": "public-key",
		"authenticatorAttachment": "cross-platform", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON": b64.EncodeToString(client), "attestationObject": b64.EncodeToString(att), "transports": []string{"usb"},
		},
	})
	return out
}

// get answers assertion options as navigator.credentials.get would, its
// counter one past the last.
func (k *softKey) get(t *testing.T, options map[string]any) json.RawMessage {
	t.Helper()
	k.count++
	return k.sign(t, challengeOf(t, options))
}

// sign answers challenge at the key's current counter.
func (k *softKey) sign(t *testing.T, challenge string) json.RawMessage {
	t.Helper()
	client, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": k.origin})
	data := k.authData(nil)
	clientHash := sha256.Sum256(client)
	signed := sha256.Sum256(append(append([]byte{}, data...), clientHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, signed[:])
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(k.id), "rawId": b64.EncodeToString(k.id), "type": "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON": b64.EncodeToString(client), "authenticatorData": b64.EncodeToString(data), "signature": b64.EncodeToString(sig),
		},
	})
	return out
}
