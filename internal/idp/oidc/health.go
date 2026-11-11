// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/albatroxxx/zanskar/internal/idp"
)

// 2026-11-03 live audit, idea 1: a provider the gateway cannot reach is
// single sign-on down, and the sign-in page said so only after someone had
// pressed its button and waited. The gateway now asks each enabled OpenID
// provider for its discovery document on a timer, the request a sign-in
// starts with, and the public provider list marks one whose last answer
// failed. The probe runs on the gateway's clock, never a visitor's request,
// so the public list cannot be used to make the gateway call out.

// ProbeEvery is how often Watch asks each enabled provider.
const ProbeEvery = 2 * time.Minute

// RetryEvery is how often Watch asks again a provider whose last answer
// failed. The sign-in page greys such a provider's button out and offers to
// check again, which reads the list; asked only every ProbeEvery, a provider
// back up would stay grey for up to two minutes (2026-11-11).
const RetryEvery = 20 * time.Second

// probeTimeout bounds one probe; a provider slower than this would make a
// sign-in wait as long.
const probeTimeout = 5 * time.Second

// staleAfter is how long a failed answer stands: older than this (the probe
// stopped), nothing is said rather than an old outage.
const staleAfter = 5 * ProbeEvery

// answer is what the gateway last found asking a provider.
type answer struct {
	ok bool
	at time.Time
}

// answered records an answer for provider id, and logs the change when the
// provider stops or starts answering.
func (h *Handler) answered(id string, ok bool, at time.Time) {
	prev, had := h.health.Swap(id, answer{ok: ok, at: at})
	was := !had || prev.(answer).ok
	switch {
	case was && !ok:
		h.Log.Warn("sign-in provider not answering", "idp", id)
	case !was && ok:
		h.Log.Info("sign-in provider answering again", "idp", id)
	}
}

// notAnswering reports whether provider id's last answer, within
// staleAfter of now, failed.
func (h *Handler) notAnswering(id string, now time.Time) bool {
	v, ok := h.health.Load(id)
	if !ok {
		return false
	}
	a := v.(answer)
	return !a.ok && now.Sub(a.at) < staleAfter
}

// Watch probes every enabled OpenID provider at once and then every
// interval, and a provider whose last answer failed every retry, until ctx
// ends.
func (h *Handler) Watch(ctx context.Context, interval, retry time.Duration) {
	h.probeAll(ctx)
	all := time.NewTicker(interval)
	defer all.Stop()
	again := time.NewTicker(retry)
	defer again.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-all.C:
			h.probeAll(ctx)
		case <-again.C:
			h.probeFailing(ctx)
		}
	}
}

// probeFailing probes again each provider whose last answer failed, all at
// once: one after another, several down providers held the Watch loop for
// probeTimeout each, every retry (review, 2026-11-11).
func (h *Handler) probeFailing(ctx context.Context) {
	var ids []string
	h.health.Range(func(k, v any) bool {
		if !v.(answer).ok {
			ids = append(ids, k.(string))
		}
		return true
	})
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Go(func() { h.probe(ctx, id) })
	}
	wg.Wait()
}

// probeAll probes each enabled OpenID provider and forgets the answers of
// providers no longer listed (deleted, disabled, or no longer OpenID).
func (h *Handler) probeAll(ctx context.Context) {
	ps, err := h.Providers.List(ctx, true)
	if err != nil {
		if ctx.Err() == nil {
			h.Log.Warn("list providers to probe", "err", err)
		}
		return
	}
	keep := map[string]bool{}
	for _, p := range ps {
		if p.Type != idp.TypeOIDC {
			continue
		}
		keep[p.ID] = true
		h.probe(ctx, p.ID)
	}
	h.health.Range(func(k, _ any) bool {
		if !keep[k.(string)] {
			h.health.Delete(k)
		}
		return true
	})
}

// probe asks provider id for its discovery document. Only a 200 is an
// answer: a provider that times out, refuses, or serves an error page would
// fail a sign-in the same way. Nothing is recorded when ctx ended (the
// gateway stopping is not the provider failing), nor for a provider no
// longer an enabled OpenID one (probeAll forgets its answer).
func (h *Handler) probe(ctx context.Context, id string) {
	op, err := h.Providers.Open(ctx, id)
	if err != nil || !op.Enabled || op.Type != idp.TypeOIDC || op.Config.OIDC == nil {
		return
	}
	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	ok := false
	req, err := http.NewRequestWithContext(pctx, http.MethodGet, strings.TrimSuffix(op.Config.OIDC.Issuer, "/")+"/.well-known/openid-configuration", nil)
	if err == nil {
		// The issuer is the administrator's, and sign-in fetches this same
		// document from it.
		res, err := h.client().Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
			_ = res.Body.Close()
			ok = res.StatusCode == http.StatusOK
		}
	}
	if ctx.Err() != nil {
		return
	}
	h.answered(id, ok, time.Now())
}
