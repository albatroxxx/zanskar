// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/idp"
)

// 2026-11-03 live audit, idea 1: the sign-in page says a provider is not
// answering before anyone presses its button. These pin what decides it.

// listed reads the public provider list as the sign-in page does, raw and
// decoded.
func listed(t *testing.T, e *env) (string, []publicProvider) {
	t.Helper()
	res, err := http.Get(e.app.URL + "/api/v1/auth/providers")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(res.Body)
	var page struct {
		Items []publicProvider `json:"items"`
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		t.Fatalf("%s: %v", raw, err)
	}
	return string(raw), page.Items
}

func oidcCfg() idp.Config {
	return idp.Config{OIDC: &idp.OIDCConfig{ClientID: "cid", ClientSecret: "s"}, AutoProvision: true}
}

func TestProbeSaysWhenAProviderStopsAndStartsAnswering(t *testing.T) {
	f := newFakeIdP(t)
	e, id := newEnv(t, f, oidcCfg())
	ctx := context.Background()

	raw, items := listed(t, e)
	if len(items) != 1 || items[0].NotAnswering || strings.Contains(raw, "not_answering") {
		t.Fatalf("never probed, nothing is said: %s", raw)
	}
	e.h.probeAll(ctx)
	if raw, items = listed(t, e); items[0].NotAnswering || strings.Contains(raw, "not_answering") {
		t.Fatalf("answering, nothing is said: %s", raw)
	}
	f.down.Store(true)
	e.h.probeAll(ctx)
	if raw, items = listed(t, e); !items[0].NotAnswering || items[0].ID != id {
		t.Fatalf("a 503 from discovery is not answering: %s", raw)
	}
	f.down.Store(false)
	e.h.probeAll(ctx)
	if _, items = listed(t, e); items[0].NotAnswering {
		t.Fatal("answering again clears it")
	}
}

func TestProbeCountsARefusedConnection(t *testing.T) {
	f := newFakeIdP(t)
	e, id := newEnv(t, f, oidcCfg())
	ctx := context.Background()
	op, err := e.repo.Open(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	// Port 1 refuses on loopback: the provider is gone, not erroring.
	cfg := op.Config
	cfg.OIDC.Issuer = "https://127.0.0.1:1"
	if err := e.repo.Update(ctx, &op.Provider, &cfg); err != nil {
		t.Fatal(err)
	}
	e.h.probeAll(ctx)
	if !e.h.notAnswering(id, time.Now()) {
		t.Fatal("a provider that refuses the connection is not answering")
	}
}

func TestAFailedAnswerGoesStale(t *testing.T) {
	e, id := newEnv(t, newFakeIdP(t), oidcCfg())
	now := time.Now()
	e.h.answered(id, false, now.Add(-staleAfter-time.Second))
	if e.h.notAnswering(id, now) {
		t.Fatal("an answer older than staleAfter says nothing")
	}
	e.h.answered(id, false, now.Add(-staleAfter+time.Minute))
	if !e.h.notAnswering(id, now) {
		t.Fatal("a recent failed answer stands")
	}
}

func TestADisabledProviderIsForgotten(t *testing.T) {
	f := newFakeIdP(t)
	e, id := newEnv(t, f, oidcCfg())
	ctx := context.Background()
	f.down.Store(true)
	e.h.probeAll(ctx)
	if !e.h.notAnswering(id, time.Now()) {
		t.Fatal("setup: not answering")
	}
	op, err := e.repo.Open(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	op.Enabled = false
	cfg := op.Config
	if err := e.repo.Update(ctx, &op.Provider, &cfg); err != nil {
		t.Fatal(err)
	}
	e.h.probeAll(ctx)
	if _, ok := e.h.health.Load(id); ok {
		t.Fatal("a disabled provider's answer is dropped, so enabling it again starts clean")
	}
}

func TestASignInThatFailsDiscoveryMarksIt(t *testing.T) {
	f := newFakeIdP(t)
	e, id := newEnv(t, f, oidcCfg())
	f.down.Store(true)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Get(e.app.URL + "/api/v1/auth/oidc/" + id + "/start")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if !strings.Contains(res.Header.Get("Location"), "provider_unavailable") {
		t.Fatalf("start with discovery down: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if !e.h.notAnswering(id, time.Now()) {
		t.Fatal("a sign-in that could not fetch discovery says so to the next visitor")
	}
	f.down.Store(false)
	res, err = client.Get(e.app.URL + "/api/v1/auth/oidc/" + id + "/start")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if e.h.notAnswering(id, time.Now()) {
		t.Fatal("a sign-in that fetched discovery clears it")
	}
}

func TestAStoppingGatewayRecordsNothing(t *testing.T) {
	f := newFakeIdP(t)
	e, id := newEnv(t, f, oidcCfg())
	// A provider still thinking when the gateway stops.
	entered := make(chan struct{})
	slow := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
	}))
	t.Cleanup(slow.Close)
	e.h.HTTPClient = slow.Client()
	ctx := context.Background()
	op, err := e.repo.Open(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	cfg := op.Config
	cfg.OIDC.Issuer = slow.URL
	if err := e.repo.Update(ctx, &op.Provider, &cfg); err != nil {
		t.Fatal(err)
	}
	stop, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { e.h.probe(stop, id); close(done) }()
	<-entered
	cancel()
	<-done
	if _, ok := e.h.health.Load(id); ok {
		t.Fatal("a probe cut short by shutdown is not the provider failing")
	}
}

func TestWatchProbesAtOnceAndStops(t *testing.T) {
	f := newFakeIdP(t)
	e, id := newEnv(t, f, oidcCfg())
	f.down.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.h.Watch(ctx, time.Hour, time.Hour); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for !e.h.notAnswering(id, time.Now()) {
		if time.Now().After(deadline) {
			t.Fatal("Watch probes once at start, not only after the first interval")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Watch returns when its context ends")
	}
}

// 2026-11-11: the sign-in page greys out a provider that is not answering and
// offers to check again, which reads the list. A provider back up must leave
// the list at the retry pace, not the two-minute one.
func TestWatchAsksAFailingProviderAgainSooner(t *testing.T) {
	f := newFakeIdP(t)
	e, id := newEnv(t, f, oidcCfg())
	f.down.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() { cancel(); <-done })
	go func() { e.h.Watch(ctx, time.Hour, 20*time.Millisecond); close(done) }()
	waitFor := func(want bool, what string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for e.h.notAnswering(id, time.Now()) != want {
			if time.Now().After(deadline) {
				t.Fatal(what)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitFor(true, "setup: the first probe finds it down")
	f.down.Store(false)
	waitFor(false, "a failing provider is asked again every retry, so its recovery shows well before the next full probe")
}

// lastAnswer is when provider id was last asked; zero when never.
func lastAnswer(e *env, id string) time.Time {
	v, ok := e.h.health.Load(id)
	if !ok {
		return time.Time{}
	}
	return v.(answer).at
}

func TestProbeFailingAsksOnlyFailingEnabledProviders(t *testing.T) {
	f := newFakeIdP(t)
	e, id := newEnv(t, f, oidcCfg())
	ctx := context.Background()

	e.h.probeAll(ctx)
	before := lastAnswer(e, id)
	e.h.probeFailing(ctx)
	if !lastAnswer(e, id).Equal(before) {
		t.Fatal("an answering provider waits for the full probe")
	}

	f.down.Store(true)
	e.h.probeAll(ctx)
	before = lastAnswer(e, id)
	e.h.probeFailing(ctx)
	if !lastAnswer(e, id).After(before) {
		t.Fatal("a failing provider is asked again")
	}

	op, err := e.repo.Open(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	op.Enabled = false
	cfg := op.Config
	if err := e.repo.Update(ctx, &op.Provider, &cfg); err != nil {
		t.Fatal(err)
	}
	before = lastAnswer(e, id)
	e.h.probeFailing(ctx)
	if !lastAnswer(e, id).Equal(before) {
		t.Fatal("a provider disabled since its failed answer is not called out to again")
	}
}
