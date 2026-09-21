// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
)

func exportLog(t *testing.T, n int) *Log {
	t.Helper()
	db, err := store.Open(context.Background(), config.DriverSQLite, "file::memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := store.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	l := NewLog(db)
	for i := 0; i < n; i++ {
		ev := Actor{UserID: "u1", IP: "10.0.0.1"}.Event("user.login", "user", "u1", Success, map[string]any{"n": i, "note": "a=b|c\nd"})
		if i%5 == 4 {
			ev.Outcome = Failure
		}
		if _, err := l.Record(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
	}
	return l
}

type flakySink struct {
	mu        sync.Mutex
	failFirst int
	got       [][]int64
}

func (f *flakySink) Name() string { return "flaky" }
func (f *flakySink) Send(_ context.Context, evs []Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failFirst > 0 {
		f.failFirst--
		return errors.New("down")
	}
	ids := make([]int64, len(evs))
	for i, e := range evs {
		ids[i] = e.ID
	}
	f.got = append(f.got, ids)
	return nil
}

func TestFlushIsOrderedAtLeastOnceAndCheckpointed(t *testing.T) {
	l := exportLog(t, 7)
	sink := &flakySink{failFirst: 1}
	e := &Exporter{Log: l, Sinks: []Sink{sink}, BatchSize: 3}
	ctx := context.Background()
	if _, err := e.Flush(ctx, sink); err == nil {
		t.Fatal("first flush should fail")
	}
	if cp, _ := l.ExportCheckpoint(ctx, "flaky"); cp != 0 {
		t.Fatalf("checkpoint advanced on failure: %d", cp)
	}
	n, err := e.Flush(ctx, sink)
	if err != nil || n != 7 {
		t.Fatalf("flush: %d %v", n, err)
	}
	if len(sink.got) != 3 || sink.got[0][0] != 1 || sink.got[2][0] != 7 {
		t.Fatalf("batches: %v", sink.got)
	}
	if cp, _ := l.ExportCheckpoint(ctx, "flaky"); cp != 7 {
		t.Fatalf("checkpoint: %d", cp)
	}
	// Nothing new: no delivery, checkpoint stable.
	if n, _ := e.Flush(ctx, sink); n != 0 {
		t.Fatalf("expected nothing to deliver, got %d", n)
	}
	// New events after the checkpoint are picked up.
	_, _ = l.Record(ctx, Actor{IP: "x"}.Event("target.create", "target", "t1", Success, nil))
	if n, _ := e.Flush(ctx, sink); n != 1 || sink.got[len(sink.got)-1][0] != 8 {
		t.Fatalf("incremental: %d %v", n, sink.got)
	}
}

func TestSyslogSinkFramingAndCEF(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	frames := make(chan string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					lenStr, err := r.ReadString(' ')
					if err != nil {
						return
					}
					n, _ := strconv.Atoi(strings.TrimSpace(lenStr))
					buf := make([]byte, n)
					if _, err := io.ReadFull(r, buf); err != nil {
						return
					}
					frames <- string(buf)
				}
			}()
		}
	}()
	l := exportLog(t, 5)
	s := &SyslogSink{Addr: "tcp://" + ln.Addr().String(), Hostname: "gw1"}
	defer func() { _ = s.Close() }()
	evs, _ := l.ListAfter(context.Background(), 0, 10)
	if err := s.Send(context.Background(), evs); err != nil {
		t.Fatal(err)
	}
	var got []string
	for i := 0; i < 5; i++ {
		select {
		case f := <-frames:
			got = append(got, f)
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d frames", len(got))
		}
	}
	first := got[0]
	if !strings.HasPrefix(first, "<110>1 ") || !strings.Contains(first, " gw1 zanskar - user-login - CEF:0|Zanskar|Zanskar|") {
		t.Fatalf("header: %s", first)
	}
	if !strings.Contains(first, "|user.login|user.login|3|") || !strings.Contains(first, "suser=u1") || !strings.Contains(first, "externalId=1") {
		t.Fatalf("cef body: %s", first)
	}
	// Details are escaped per CEF: '=' and backslashes in the extension value
	// (the JSON already spells the newline as \n, so its backslash doubles);
	// '|' is only special in the header.
	if !strings.Contains(first, `a\=b|c\\nd`) {
		t.Fatalf("escaping: %s", first)
	}
	// Failures carry severity 6 and syslog warning priority.
	if !strings.HasPrefix(got[4], "<108>1 ") || !strings.Contains(got[4], "|user.login|user.login|6|") {
		t.Fatalf("failure event: %s", got[4])
	}
	// JSON format round-trips.
	js := &SyslogSink{Addr: "tcp://" + ln.Addr().String(), Format: "json"}
	defer func() { _ = js.Close() }()
	if err := js.Send(context.Background(), evs[:1]); err != nil {
		t.Fatal(err)
	}
	var f string
	select {
	case f = <-frames:
	case <-time.After(3 * time.Second):
		t.Fatal("json frame not received")
	}
	start := strings.Index(f, "{")
	if start < 0 {
		t.Fatalf("no json body in frame: %s", f)
	}
	var ev Event
	if err := json.Unmarshal([]byte(f[start:]), &ev); err != nil || ev.ID != 1 || ev.Hash == "" {
		t.Fatalf("json frame: %s (%v)", f, err)
	}
	if err := (&SyslogSink{Addr: "udp://127.0.0.1:514"}).Send(context.Background(), evs[:1]); err == nil {
		t.Fatal("udp must be refused")
	}
}

func TestWebhookSinkSignsAndVerifies(t *testing.T) {
	secret := []byte("shared-secret")
	var received int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !VerifySignature(secret, r.Header.Get("X-Zanskar-Timestamp"), r.Header.Get("X-Zanskar-Signature"), body, time.Minute) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var payload struct{ Events []Event }
		if err := json.Unmarshal(body, &payload); err != nil || len(payload.Events) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received += len(payload.Events)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	l := exportLog(t, 4)
	evs, _ := l.ListAfter(context.Background(), 0, 10)
	s := &WebhookSink{URL: srv.URL, Secret: secret, AllowHTTP: true}
	if err := s.Send(context.Background(), evs); err != nil || received != 4 {
		t.Fatalf("send: %v received=%d", err, received)
	}
	bad := &WebhookSink{URL: srv.URL, Secret: []byte("wrong"), AllowHTTP: true}
	if err := bad.Send(context.Background(), evs); err == nil {
		t.Fatal("wrong secret must be rejected by the receiver")
	}
	if err := (&WebhookSink{URL: srv.URL, Secret: secret}).Send(context.Background(), evs); err == nil {
		t.Fatal("plain http must be refused unless allowed")
	}
	if VerifySignature(secret, strconv.FormatInt(time.Now().Add(-2*time.Hour).Unix(), 10), "sha256=x", nil, time.Minute) {
		t.Fatal("stale timestamp must fail")
	}
}
