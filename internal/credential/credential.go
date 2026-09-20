// SPDX-License-Identifier: Apache-2.0

// Package credential is the vault for the secrets Zanskar uses to reach
// targets (ADR 0005). Secrets are sealed with the key ring (ADR 0007) under
// an AAD bound to the row, and are only ever opened by the gateway.
package credential

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Type of credential.
type Type string

// Types.
const (
	TypePassword           Type = "password"
	TypeSSHKey             Type = "ssh_key"
	TypeSSHCA              Type = "ssh_ca"
	TypeDomain             Type = "domain"
	TypeEC2InstanceConnect Type = "ec2_instance_connect"
)

// ValidType reports whether t is known.
func ValidType(t Type) bool {
	switch t {
	case TypePassword, TypeSSHKey, TypeSSHCA, TypeDomain, TypeEC2InstanceConnect:
		return true
	}
	return false
}

// Mode says where the secret comes from at connect time.
type Mode string

// Modes.
const (
	ModeVaulted      Mode = "vaulted"       // Zanskar holds the secret
	ModeUserSupplied Mode = "user_supplied" // the user types it at connect time
	ModePassthrough  Mode = "passthrough"   // the user's own directory credentials are forwarded
)

// ValidMode reports whether m is known.
func ValidMode(m Mode) bool {
	return m == ModeVaulted || m == ModeUserSupplied || m == ModePassthrough
}

// Credential is the metadata of a stored credential. It never carries the secret.
type Credential struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Type       Type       `json:"type"`
	Mode       Mode       `json:"mode"`
	Username   string     `json:"username,omitempty"`
	Domain     string     `json:"domain,omitempty"`
	PublicKey  string     `json:"public_key,omitempty"`
	HasSecret  bool       `json:"has_secret"`
	KeyVersion int        `json:"key_version,omitempty"`
	CreatedBy  string     `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	RotatedAt  *time.Time `json:"rotated_at,omitempty"`
	InUseBy    InUseBy    `json:"in_use_by"`
}

// InUseBy counts the references that block deletion.
type InUseBy struct {
	Targets           int `json:"targets"`
	AutoscalingGroups int `json:"autoscaling_groups"`
}

// Secret is the write-only input. Exactly one of Password or PrivateKey is
// used depending on the type. Passphrase unlocks an encrypted PEM; the key is
// stored decrypted so the gateway never needs the passphrase.
type Secret struct {
	Password   string
	PrivateKey string
	Passphrase string
}

// Errors.
var (
	ErrNotFound   = errors.New("credential: not found")
	ErrDuplicate  = errors.New("credential: name already exists")
	ErrInUse      = errors.New("credential: still referenced by a target or autoscaling group")
	ErrInvalid    = errors.New("credential: invalid input")
	ErrNoSecret   = errors.New("credential: no secret stored")
	ErrBadKey     = errors.New("credential: private key could not be parsed")
	ErrPassphrase = errors.New("credential: private key is encrypted; passphrase missing or wrong")
)

// prepared is the validated, normalised form ready for storage.
type prepared struct {
	plaintext []byte // password bytes or PEM private key; nil when nothing is stored
	publicKey string
}

// validateAndPrepare applies the per-type rules and returns what to seal.
func validateAndPrepare(c *Credential, s *Secret) (*prepared, error) {
	c.Name = strings.TrimSpace(c.Name)
	c.Username = strings.TrimSpace(c.Username)
	c.Domain = strings.TrimSpace(c.Domain)
	if c.Name == "" || len(c.Name) > 255 {
		return nil, fmt.Errorf("%w: name required (1-255 characters)", ErrInvalid)
	}
	if !ValidType(c.Type) {
		return nil, fmt.Errorf("%w: unknown type %q", ErrInvalid, c.Type)
	}
	if !ValidMode(c.Mode) {
		return nil, fmt.Errorf("%w: unknown mode %q", ErrInvalid, c.Mode)
	}
	if s == nil {
		s = &Secret{}
	}
	if c.Type == TypeEC2InstanceConnect && c.Mode != ModeVaulted {
		return nil, fmt.Errorf("%w: ec2_instance_connect is always vaulted (there is no secret to supply)", ErrInvalid)
	}
	if c.Mode != ModeVaulted {
		// Nothing is stored; the user supplies or forwards the secret later.
		if s.Password != "" || s.PrivateKey != "" {
			return nil, fmt.Errorf("%w: mode %s cannot carry a secret", ErrInvalid, c.Mode)
		}
		c.Username, c.PublicKey = "", ""
		return &prepared{}, nil
	}

	switch c.Type {
	case TypePassword, TypeDomain:
		if c.Username == "" {
			return nil, fmt.Errorf("%w: username required", ErrInvalid)
		}
		if c.Type == TypeDomain && c.Domain == "" {
			return nil, fmt.Errorf("%w: domain required", ErrInvalid)
		}
		if s.Password == "" {
			return nil, fmt.Errorf("%w: password required", ErrInvalid)
		}
		if s.PrivateKey != "" {
			return nil, fmt.Errorf("%w: private_key not allowed for type %s", ErrInvalid, c.Type)
		}
		c.PublicKey = ""
		return &prepared{plaintext: []byte(s.Password)}, nil
	case TypeSSHKey, TypeSSHCA:
		if c.Type == TypeSSHKey && c.Username == "" {
			return nil, fmt.Errorf("%w: username required", ErrInvalid)
		}
		if s.Password != "" {
			return nil, fmt.Errorf("%w: password not allowed for type %s", ErrInvalid, c.Type)
		}
		if s.PrivateKey == "" {
			return nil, fmt.Errorf("%w: private_key required", ErrInvalid)
		}
		pemBytes, pub, err := normalisePrivateKey(s.PrivateKey, s.Passphrase)
		if err != nil {
			return nil, err
		}
		c.PublicKey = pub
		return &prepared{plaintext: pemBytes, publicKey: pub}, nil
	case TypeEC2InstanceConnect:
		if c.Username == "" {
			return nil, fmt.Errorf("%w: username required", ErrInvalid)
		}
		if s.Password != "" || s.PrivateKey != "" {
			return nil, fmt.Errorf("%w: ec2_instance_connect stores no secret", ErrInvalid)
		}
		c.PublicKey = ""
		return &prepared{}, nil
	}
	return nil, ErrInvalid
}

// normalisePrivateKey parses a PEM (OpenSSH, PKCS#1, PKCS#8, EC) private key,
// decrypting with the passphrase when needed, and re-encodes it unencrypted in
// OpenSSH format. It returns the PEM bytes and the authorized_keys public line.
func normalisePrivateKey(pemText, passphrase string) ([]byte, string, error) {
	raw := []byte(strings.TrimSpace(pemText) + "\n")
	key, err := ssh.ParseRawPrivateKey(raw)
	var pe *ssh.PassphraseMissingError
	if errors.As(err, &pe) {
		if passphrase == "" {
			return nil, "", ErrPassphrase
		}
		key, err = ssh.ParseRawPrivateKeyWithPassphrase(raw, []byte(passphrase))
		if err != nil {
			if strings.Contains(err.Error(), "passphrase") || strings.Contains(err.Error(), "decrypt") {
				return nil, "", ErrPassphrase
			}
			return nil, "", fmt.Errorf("%w: %w", ErrBadKey, err)
		}
	} else if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrBadKey, err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrBadKey, err)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrBadKey, err)
	}
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return pem.EncodeToMemory(block), pub, nil
}

// GenerateSSHKey returns a fresh ed25519 private key in OpenSSH PEM format.
// The caller stores it through the vault and shows only the public half.
func GenerateSSHKey() (string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(block)), nil
}
