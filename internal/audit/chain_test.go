// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func sample(n int) []Event {
	var evs []Event
	prev := ""
	base := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		e := Event{
			ID:          int64(i + 1),
			Timestamp:   base.Add(time.Duration(i) * time.Second),
			ActorUserID: "u1",
			ActorIP:     "10.0.0.1",
			Action:      "user.login",
			Outcome:     Success,
			Details:     json.RawMessage(`{"b":1,"a":2}`),
		}
		if err := Link(&e, prev); err != nil {
			panic(err)
		}
		prev = e.Hash
		evs = append(evs, e)
	}
	return evs
}

func TestChainVerifies(t *testing.T) {
	if err := Verify(sample(5)); err != nil {
		t.Fatal(err)
	}
	if err := Verify(nil); err != nil {
		t.Fatal(err)
	}
}

func TestTamperDetected(t *testing.T) {
	evs := sample(5)
	evs[2].ActorUserID = "attacker"
	var ve *VerifyError
	if err := Verify(evs); !errors.As(err, &ve) || ve.Index != 2 {
		t.Fatalf("expected break at index 2, got %v", err)
	}

	evs = sample(5)
	evs = append(evs[:2], evs[3:]...) // delete one
	if err := Verify(evs); !errors.As(err, &ve) || ve.Index != 2 {
		t.Fatalf("expected deletion detected at index 2, got %v", err)
	}
}

func TestCanonicalDetailsOrdering(t *testing.T) {
	a := Event{Timestamp: time.Unix(0, 0), Outcome: Success, Details: json.RawMessage(`{"b":1,"a":2}`), PrevHash: GenesisHash}
	b := Event{Timestamp: time.Unix(0, 0), Outcome: Success, Details: json.RawMessage(`{ "a": 2, "b": 1 }`), PrevHash: GenesisHash}
	ha, _ := ComputeHash(a)
	hb, _ := ComputeHash(b)
	if ha != hb {
		t.Fatal("equivalent details must hash identically")
	}
}

func TestDetailsMustBeObject(t *testing.T) {
	e := Event{Timestamp: time.Unix(0, 0), Outcome: Success, Details: json.RawMessage(`[1]`), PrevHash: GenesisHash}
	if _, err := ComputeHash(e); err == nil {
		t.Fatal("expected error for non-object details")
	}
}
