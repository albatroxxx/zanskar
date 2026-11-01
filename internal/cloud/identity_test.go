// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestRolePrincipal(t *testing.T) {
	cases := map[string]string{
		"arn:aws:sts::123456789012:assumed-role/zanskar-gateway/i-0abc": "arn:aws:iam::123456789012:role/zanskar-gateway",
		"arn:aws-us-gov:sts::123456789012:assumed-role/gw/session":      "arn:aws-us-gov:iam::123456789012:role/gw",
		"arn:aws:iam::123456789012:role/already-a-role":                 "arn:aws:iam::123456789012:role/already-a-role",
		"arn:aws:iam::123456789012:user/alice":                          "arn:aws:iam::123456789012:user/alice",
		"arn:aws:sts::123456789012:assumed-role/":                       "arn:aws:sts::123456789012:assumed-role/",
		"garbage": "garbage",
	}
	for in, want := range cases {
		if got := RolePrincipal(in); got != want {
			t.Errorf("RolePrincipal(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestGatewayIdentityPrecedence: the environment override wins and never
// triggers detection; otherwise detection runs once, is cached, and a
// failure is reported as source none with the reason, until a refresh.
func TestGatewayIdentityPrecedence(t *testing.T) {
	ctx := context.Background()
	calls := 0
	env := NewGatewayIdentity(" arn:aws:iam::1:role/gw ")
	env.detect = func(context.Context) (Identity, error) { calls++; return Identity{}, errors.New("must not run") }
	env.platform = func(context.Context) string { return PlatformNone }
	if id := env.Get(ctx); id.Principal != "arn:aws:iam::1:role/gw" || id.Source != SourceEnvironment || calls != 0 {
		t.Fatalf("override: %+v calls=%d", id, calls)
	}
	if id := env.Refresh(ctx); id.Source != SourceEnvironment || calls != 0 {
		t.Fatalf("refresh with override: %+v calls=%d", id, calls)
	}

	det := NewGatewayIdentity("")
	det.detect = func(context.Context) (Identity, error) {
		calls++
		if calls == 1 {
			return Identity{}, errors.New("no EC2 IMDS role found")
		}
		return Identity{Principal: "arn:aws:iam::2:role/detected", RawARN: "arn:aws:sts::2:assumed-role/detected/i-1", AccountID: "2", Source: SourceDetected}, nil
	}
	id := det.Get(ctx)
	if id.Source != SourceNone || id.Error == "" || id.Principal != "" || id.CheckedAt.IsZero() {
		t.Fatalf("failed detection: %+v", id)
	}
	if again := det.Get(ctx); again.Source != SourceNone || calls != 1 {
		t.Fatalf("a failed detection is cached until refresh: %+v calls=%d", again, calls)
	}
	id = det.Refresh(ctx)
	if id.Source != SourceDetected || id.Principal != "arn:aws:iam::2:role/detected" || id.AccountID != "2" || calls != 2 {
		t.Fatalf("refresh: %+v calls=%d", id, calls)
	}
	if id = det.Get(ctx); id.Source != SourceDetected || calls != 2 {
		t.Fatalf("cached after refresh: %+v calls=%d", id, calls)
	}
}

// TestPlainReason: the Autoscaling page showed the SDK's error whole, in
// monospace, on an EC2 gateway without an instance profile (the live
// console, 2026-11-01). Each common failure reads as a sentence.
func TestPlainReason(t *testing.T) {
	for _, c := range []struct{ err, want string }{
		// the live box: on EC2, no instance profile
		{"cloud: no AWS identity: operation error STS: GetCallerIdentity, get identity: get credentials: failed to refresh cached credentials, no EC2 IMDS role found, operation error ec2imds: GetMetadata, http response error StatusCode: 404, request to EC2 IMDS failed",
			"This machine has no IAM role. Attach an instance profile to it."},
		{"operation error STS: GetCallerIdentity, https response error StatusCode: 403, RequestID: x, api error ExpiredToken: The security token included in the request is expired",
			"AWS turned down the gateway's credentials: they have expired or are wrong."},
		{"operation error STS: GetCallerIdentity, https response error StatusCode: 403, api error AccessDenied: explicit deny",
			"AWS refused to say who the gateway is (access denied)."},
		{"operation error STS: GetCallerIdentity, context deadline exceeded", "AWS did not answer in time."},
		{"get identity: get credentials: failed to refresh cached credentials, no valid providers in chain", "The gateway found no AWS credentials."},
		{"something new", "AWS could not say who the gateway is; the gateway's log has the details."},
	} {
		if got := plainReason(errors.New(c.err)); got != c.want {
			t.Errorf("%.60s…: %q, want %q", c.err, got, c.want)
		}
	}
}

// TestIdentityPlatform: off AWS a missing identity is the ordinary case and
// says so plainly; on AWS it keeps the real error, because there it is a
// misconfiguration worth reading.
func TestIdentityPlatform(t *testing.T) {
	ctx := context.Background()
	off := NewGatewayIdentity("")
	off.detect = func(context.Context) (Identity, error) { return Identity{}, errors.New("sts: deadline exceeded") }
	off.platform = func(context.Context) string { return PlatformNone }
	if id := off.Get(ctx); id.Platform != PlatformNone || id.Source != SourceNone || id.Error != "not running on AWS" {
		t.Fatalf("off AWS: %+v", id)
	}

	on := NewGatewayIdentity("")
	on.detect = func(context.Context) (Identity, error) { return Identity{}, errors.New("sts: AccessDenied") }
	on.platform = func(context.Context) string { return PlatformAWS }
	if id := on.Get(ctx); id.Platform != PlatformAWS || id.Error != "AWS refused to say who the gateway is (access denied)." || id.Detail != "sts: AccessDenied" {
		t.Fatalf("on AWS: %+v", id)
	}
	// the SDK's paragraph is for the log; the console is told the sentence
	if b, _ := json.Marshal(on.Get(ctx)); strings.Contains(string(b), "sts:") {
		t.Fatalf("the detail reached the API: %s", b)
	}
	if id := off.Get(ctx); id.Detail != "" {
		t.Fatalf("off AWS there is nothing worth logging: %+v", id)
	}

	over := NewGatewayIdentity("arn:aws:iam::1:role/gw")
	over.platform = func(context.Context) string { return PlatformNone }
	if id := over.Get(ctx); id.Platform != PlatformNone || id.Source != SourceEnvironment || id.Error != "" {
		t.Fatalf("override off AWS: %+v", id)
	}
}
