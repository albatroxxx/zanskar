// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"
)

// FuzzChain: a chain linked from arbitrary field values must verify, and
// changing any hashed field of any event afterwards must be detected at
// that event's index.
func FuzzChain(f *testing.F) {
	f.Add("u1", "user.login", "session", "abc", "note", uint8(1))
	f.Add("", "", "", "", "", uint8(0))
	f.Add("u\x00", "a\"b", "{}", "]", " ", uint8(2))
	f.Fuzz(func(t *testing.T, actor, action, objType, objID, detail string, tamperAt uint8) {
		details, _ := json.Marshal(map[string]string{"k": detail})
		events := make([]Event, 3)
		prev := ""
		for i := range events {
			events[i] = Event{ID: int64(i + 1), Timestamp: time.Unix(1_700_000_000+int64(i), int64(i)), ActorUserID: actor, ActorIP: "10.0.0." + strconv.Itoa(i), Action: action, ObjectType: objType, ObjectID: objID, Outcome: Success, Details: details}
			if err := Link(&events[i], prev); err != nil {
				t.Fatalf("Link: %v", err)
			}
			prev = events[i].Hash
		}
		if err := Verify(events); err != nil {
			t.Fatalf("fresh chain failed to verify: %v", err)
		}
		i := int(tamperAt) % len(events)
		events[i].Action += "x"
		err := Verify(events)
		if err == nil {
			t.Fatalf("tampered event %d was not detected", i)
		}
		var ve *VerifyError
		if !errors.As(err, &ve) || ve.Index != i {
			t.Fatalf("tamper at %d reported as %v", i, err)
		}
	})
}

// FuzzVerifySignature: the genuine signature verifies; any other signature
// string, or any change to the body, does not.
func FuzzVerifySignature(f *testing.F) {
	f.Add([]byte("secret"), []byte(`{"a":1}`), "sha256=00", uint8(0))
	f.Add([]byte(""), []byte(""), "", uint8(1))
	f.Fuzz(func(t *testing.T, secret, body []byte, other string, flip uint8) {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		good := "sha256=" + Sign(secret, ts, body)
		if !VerifySignature(secret, ts, good, body, time.Minute) {
			t.Fatal("genuine signature rejected")
		}
		if other != good && VerifySignature(secret, ts, other, body, time.Minute) {
			t.Fatalf("accepted forged signature %q", other)
		}
		if len(body) > 0 {
			mutated := append([]byte(nil), body...)
			mutated[int(flip)%len(mutated)] ^= 0x01
			if VerifySignature(secret, ts, good, mutated, time.Minute) {
				t.Fatal("accepted signature over a modified body")
			}
		}
		if VerifySignature(secret, "not-a-timestamp", good, body, time.Minute) {
			t.Fatal("accepted a non-numeric timestamp")
		}
	})
}
