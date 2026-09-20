// SPDX-License-Identifier: Apache-2.0

// Package audit defines audit events and the hash chain that makes the log
// tamper-evident (ADR 0008). Persistence lives with the store; this package is
// pure so it can be verified offline from an export.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// GenesisHash seeds the chain. It is a fixed public value; the chain's
// integrity comes from the sequence, not from the seed being secret.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Outcome of an audited action.
type Outcome string

// Outcomes.
const (
	Success Outcome = "success"
	Failure Outcome = "failure"
)

// Event is one audit record. Details must be JSON-serialisable and must never
// contain secrets; callers are responsible for redaction before logging.
type Event struct {
	ID          int64           `json:"id"`
	Timestamp   time.Time       `json:"ts"`
	ActorUserID string          `json:"actor_user_id"`
	ActorIP     string          `json:"actor_ip"`
	Action      string          `json:"action"`
	ObjectType  string          `json:"object_type"`
	ObjectID    string          `json:"object_id"`
	Outcome     Outcome         `json:"outcome"`
	Details     json.RawMessage `json:"details"`
	PrevHash    string          `json:"prev_hash"`
	Hash        string          `json:"hash"`
}

// canonical is the subset of Event that is hashed, in a fixed field order.
// ID is excluded so the hash can be computed before the row is inserted.
type canonical struct {
	Timestamp   string          `json:"ts"`
	ActorUserID string          `json:"actor_user_id"`
	ActorIP     string          `json:"actor_ip"`
	Action      string          `json:"action"`
	ObjectType  string          `json:"object_type"`
	ObjectID    string          `json:"object_id"`
	Outcome     Outcome         `json:"outcome"`
	Details     json.RawMessage `json:"details"`
	PrevHash    string          `json:"prev_hash"`
}

// ComputeHash returns hex(SHA-256(prev_hash || canonical JSON)).
func ComputeHash(e Event) (string, error) {
	details := e.Details
	if len(details) == 0 {
		details = json.RawMessage("{}")
	}
	compact, err := compactJSON(details)
	if err != nil {
		return "", fmt.Errorf("audit: details is not valid JSON: %w", err)
	}
	body, err := json.Marshal(canonical{
		Timestamp:   e.Timestamp.UTC().Format(time.RFC3339Nano),
		ActorUserID: e.ActorUserID,
		ActorIP:     e.ActorIP,
		Action:      e.Action,
		ObjectType:  e.ObjectType,
		ObjectID:    e.ObjectID,
		Outcome:     e.Outcome,
		Details:     compact,
		PrevHash:    e.PrevHash,
	})
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(e.PrevHash))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Link fills PrevHash and Hash for a new event that follows prev. Pass an
// empty string for prev when the log is empty.
func Link(e *Event, prevHash string) error {
	if prevHash == "" {
		prevHash = GenesisHash
	}
	e.PrevHash = prevHash
	h, err := ComputeHash(*e)
	if err != nil {
		return err
	}
	e.Hash = h
	return nil
}

// VerifyError reports where a chain broke.
type VerifyError struct {
	Index  int
	ID     int64
	Reason string
}

func (v *VerifyError) Error() string {
	return fmt.Sprintf("audit: chain broken at index %d (id %d): %s", v.Index, v.ID, v.Reason)
}

// Verify walks events in order and confirms every hash and link. events must
// be the complete, ordered log or a contiguous slice whose first PrevHash is
// known to the caller.
func Verify(events []Event) error {
	prev := GenesisHash
	for i, e := range events {
		if i == 0 && e.PrevHash != GenesisHash {
			// Contiguous slice not starting at genesis: trust its stated prev.
			prev = e.PrevHash
		}
		if e.PrevHash != prev {
			return &VerifyError{Index: i, ID: e.ID, Reason: "prev_hash does not match previous event"}
		}
		want, err := ComputeHash(e)
		if err != nil {
			return &VerifyError{Index: i, ID: e.ID, Reason: err.Error()}
		}
		if want != e.Hash {
			return &VerifyError{Index: i, ID: e.ID, Reason: "hash does not match content"}
		}
		prev = e.Hash
	}
	return nil
}

// compactJSON re-encodes JSON in Go's canonical compact form (sorted map keys).
func compactJSON(raw json.RawMessage) (json.RawMessage, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	if _, ok := v.(map[string]any); !ok {
		return nil, errors.New("details must be a JSON object")
	}
	return json.Marshal(v)
}
