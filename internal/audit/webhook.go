// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// WebhookSink POSTs batches as JSON to an HTTPS endpoint, signed with an
// HMAC so the receiver can verify origin and integrity. The signature covers
// the timestamp and the body, which lets the receiver reject replays.
//
//	POST <URL>
//	Content-Type: application/json
//	X-Zanskar-Timestamp: <unix seconds>
//	X-Zanskar-Signature: sha256=<hex hmac(secret, timestamp + "." + body)>
//	{"events":[...]}
type WebhookSink struct {
	URL    string
	Secret []byte
	// Client defaults to a 30 s timeout client.
	Client *http.Client
	// AllowHTTP permits a plain http:// URL (development only).
	AllowHTTP bool
}

// Name implements Sink.
func (w *WebhookSink) Name() string { return "webhook" }

// Send implements Sink.
func (w *WebhookSink) Send(ctx context.Context, events []Event) error {
	plainOK := w.AllowHTTP && strings.HasPrefix(w.URL, "http://")
	if !strings.HasPrefix(w.URL, "https://") && !plainOK {
		return errors.New("webhook: url must be https")
	}
	body, err := json.Marshal(map[string]any{"events": events})
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "zanskar-audit-export")
	req.Header.Set("X-Zanskar-Timestamp", ts)
	req.Header.Set("X-Zanskar-Signature", "sha256="+Sign(w.Secret, ts, body))
	client := w.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook: receiver returned %d", resp.StatusCode)
	}
	return nil
}

// Sign computes the webhook signature for a timestamp and body.
func Sign(secret []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature is the receiver-side check, exported so integrators (and
// tests) share one implementation. maxSkew rejects stale timestamps.
func VerifySignature(secret []byte, timestamp, signature string, body []byte, maxSkew time.Duration) bool {
	sec, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	if d := time.Since(time.Unix(sec, 0)); d > maxSkew || d < -maxSkew {
		return false
	}
	want := "sha256=" + Sign(secret, timestamp, body)
	return hmac.Equal([]byte(want), []byte(signature))
}
