// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/smithy-go"
)

// fakeTrail is CloudTrail as the reader sees it: pages keyed by the token
// that asks for them ("" first), every input kept, an error when told.
type fakeTrail struct {
	mu     sync.Mutex
	pages  map[string]*cloudtrail.LookupEventsOutput
	inputs []*cloudtrail.LookupEventsInput
	err    error
	// endless answers a fresh token on every page, for the page bound.
	endless bool
}

func (f *fakeTrail) LookupEvents(_ context.Context, in *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inputs = append(f.inputs, in)
	if f.err != nil {
		return nil, f.err
	}
	if f.endless {
		n := len(f.inputs)
		return &cloudtrail.LookupEventsOutput{Events: []cttypes.Event{event(fmt.Sprintf("e%d", n), "2026-11-17T10:00:00Z", "s3.amazonaws.com", "ListBuckets", "true")},
			NextToken: aws.String(fmt.Sprintf("t%d", n))}, nil
	}
	out, ok := f.pages[aws.ToString(in.NextToken)]
	if !ok {
		return nil, &smithy.GenericAPIError{Code: "InvalidNextTokenException", Message: "no such page"}
	}
	return out, nil
}

// fakeAuditMinter answers one set of credentials and keeps the request.
type fakeAuditMinter struct {
	req MintRequest
	err error
}

func (m *fakeAuditMinter) Mint(_ context.Context, req MintRequest) (Credentials, error) {
	m.req = req
	if m.err != nil {
		return Credentials{}, m.err
	}
	return Credentials{AccessKeyID: "ASIAAUDIT", SecretAccessKey: "s", SessionToken: "t", Expires: time.Now().Add(req.Duration)}, nil
}

func (m *fakeAuditMinter) CallerIdentity(context.Context, Credentials) (string, error) {
	return "", nil
}

// fakeClock is the pacing's clock: Sleep moves it and is remembered.
type fakeClock struct {
	now    time.Time
	sleeps []time.Duration
}

func (c *fakeClock) Now() time.Time        { return c.now }
func (c *fakeClock) Sleep(d time.Duration) { c.sleeps = append(c.sleeps, d); c.now = c.now.Add(d) }

func event(id, at, source, name, readOnly string, resources ...string) cttypes.Event {
	t, _ := time.Parse(time.RFC3339, at)
	e := cttypes.Event{EventId: aws.String(id), EventTime: aws.Time(t), EventSource: aws.String(source), EventName: aws.String(name),
		CloudTrailEvent: aws.String(`{"requestParameters":{"secret":"never-written"}}`)}
	if readOnly != "" {
		e.ReadOnly = aws.String(readOnly)
	}
	for _, r := range resources {
		e.Resources = append(e.Resources, cttypes.Resource{ResourceName: aws.String(r), ResourceType: aws.String("AWS::Thing")})
	}
	return e
}

// A read (ADR 0050, phase C): the role is assumed under the gateway's own
// session name with its purpose as a tag; LookupEvents asks by Username
// for the session's name over the window, fifty a page, following the
// token; the pages are half a second apart on the clock and the first waits
// for nothing; what Seen already holds, and what a page repeats, is left
// out and Seen gains the rest; the events come back in time order.
func TestActivityReadPagesPacesAndSorts(t *testing.T) {
	trail := &fakeTrail{pages: map[string]*cloudtrail.LookupEventsOutput{
		"": {Events: []cttypes.Event{
			event("e3", "2026-11-17T10:02:00Z", "ec2.amazonaws.com", "TerminateInstances", "false", "i-0abc", "i-0def"),
			event("e1", "2026-11-17T10:00:00Z", "s3.amazonaws.com", "ListBuckets", "true"),
		}, NextToken: aws.String("p2")},
		"p2": {Events: []cttypes.Event{
			event("e2", "2026-11-17T10:01:00Z", "iam.amazonaws.com", "GetUser", "true", "alice"),
			event("e1", "2026-11-17T10:00:00Z", "s3.amazonaws.com", "ListBuckets", "true"), // repeated by CloudTrail
			event("old", "2026-11-17T09:59:00Z", "sts.amazonaws.com", "GetCallerIdentity", "true"),
		}, NextToken: aws.String("p3")},
		"p3": {Events: []cttypes.Event{event("e4", "2026-11-17T10:03:00Z", "monitoring.amazonaws.com.cn", "PutMetricData", "")}},
	}}
	clock := &fakeClock{now: time.Date(2026, 11, 17, 10, 20, 0, 0, time.UTC)}
	minter := &fakeAuditMinter{}
	var gotRegion string
	r := &ActivityReader{Minter: minter, Now: clock.Now, Sleep: clock.Sleep, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		NewTrail: func(_ context.Context, region string, c Credentials) (TrailReader, error) {
			gotRegion = region
			if c.AccessKeyID != "ASIAAUDIT" {
				t.Errorf("the trail reader got credentials %q, not the audit mint's", c.AccessKeyID)
			}
			return trail, nil
		}}
	from, to := clock.now.Add(-20*time.Minute), clock.now
	seen := map[string]bool{"old": true}
	events, err := r.Read(context.Background(), ActivityRequest{RoleARN: "arn:aws:iam::123456789012:role/Admin", ExternalID: "zanskar-" + strings.Repeat("a", 32),
		Region: "eu-west-1", SessionName: "zanskar-sess1", From: from, To: to, Seen: seen})
	if err != nil {
		t.Fatal(err)
	}
	if minter.req.SessionName != AuditSessionName || minter.req.SourceIdentity != AuditSourceIdentity || minter.req.Duration != 15*time.Minute ||
		minter.req.Tags["zanskar:purpose"] != "audit" || minter.req.RoleARN != "arn:aws:iam::123456789012:role/Admin" || minter.req.ExternalID != "zanskar-"+strings.Repeat("a", 32) {
		t.Fatalf("the audit mint: %+v", minter.req)
	}
	if gotRegion != "eu-west-1" {
		t.Fatalf("region %q", gotRegion)
	}
	if len(trail.inputs) != 3 {
		t.Fatalf("%d calls, want 3 pages", len(trail.inputs))
	}
	for i, in := range trail.inputs {
		if len(in.LookupAttributes) != 1 || in.LookupAttributes[0].AttributeKey != cttypes.LookupAttributeKeyUsername || aws.ToString(in.LookupAttributes[0].AttributeValue) != "zanskar-sess1" ||
			!in.StartTime.Equal(from) || !in.EndTime.Equal(to) || aws.ToInt32(in.MaxResults) != 50 {
			t.Fatalf("call %d: %+v", i, in)
		}
	}
	if aws.ToString(trail.inputs[0].NextToken) != "" || aws.ToString(trail.inputs[1].NextToken) != "p2" || aws.ToString(trail.inputs[2].NextToken) != "p3" {
		t.Fatalf("tokens: %q %q %q", aws.ToString(trail.inputs[0].NextToken), aws.ToString(trail.inputs[1].NextToken), aws.ToString(trail.inputs[2].NextToken))
	}
	// Two calls a second: the first at once, each next half a second after
	// the one before on the clock.
	if len(clock.sleeps) != 2 || clock.sleeps[0] != 500*time.Millisecond || clock.sleeps[1] != 500*time.Millisecond {
		t.Fatalf("sleeps %v, want two of 500ms", clock.sleeps)
	}
	ids := make([]string, 0, len(events))
	for _, e := range events {
		ids = append(ids, e.ID)
	}
	if strings.Join(ids, ",") != "e1,e2,e3,e4" {
		t.Fatalf("events %v, want e1,e2,e3,e4 in time order, e1 once, old left out", ids)
	}
	for _, id := range []string{"e1", "e2", "e3", "e4", "old"} {
		if !seen[id] {
			t.Errorf("seen lacks %s", id)
		}
	}
	// The event as the line says it; the raw CloudTrailEvent is nowhere.
	if events[2].Source != "ec2" || events[2].Name != "TerminateInstances" || events[2].ReadOnly == nil || *events[2].ReadOnly || strings.Join(events[2].Resources, ",") != "i-0abc,i-0def" {
		t.Fatalf("e3: %+v", events[2])
	}
	if events[3].Source != "monitoring" || events[3].ReadOnly != nil {
		t.Fatalf("e4: %+v", events[3])
	}
	b, _ := json.Marshal(events)
	if strings.Contains(string(b), "never-written") {
		t.Fatal("the raw event reached the record")
	}
	// A second read of an overlapping window adds nothing already seen.
	again, err := r.Read(context.Background(), ActivityRequest{SessionName: "zanskar-sess1", From: from, To: to, Seen: seen})
	if err != nil || len(again) != 0 {
		t.Fatalf("second read: %v %v", again, err)
	}
}

// A read stops at forty pages (2,000 events) and says so in the log rather
// than run on; nothing read is lost.
func TestActivityReadStopsAtThePageBound(t *testing.T) {
	trail := &fakeTrail{endless: true}
	clock := &fakeClock{now: time.Date(2026, 11, 17, 10, 20, 0, 0, time.UTC)}
	var logged strings.Builder
	r := &ActivityReader{Minter: &fakeAuditMinter{}, Now: clock.Now, Sleep: clock.Sleep, Log: slog.New(slog.NewTextHandler(&logged, nil)),
		NewTrail: func(context.Context, string, Credentials) (TrailReader, error) { return trail, nil }}
	events, err := r.Read(context.Background(), ActivityRequest{SessionName: "zanskar-sess1", From: clock.now.Add(-time.Hour), To: clock.now})
	if err != nil || len(events) != 40 || len(trail.inputs) != 40 {
		t.Fatalf("%d events over %d calls (%v), want 40 and 40", len(events), len(trail.inputs), err)
	}
	if len(clock.sleeps) != 39 {
		t.Fatalf("%d sleeps, want one between each pair of pages", len(clock.sleeps))
	}
	if !strings.Contains(logged.String(), "page bound") || !strings.Contains(logged.String(), "zanskar-sess1") {
		t.Fatalf("the bound was not logged: %s", logged.String())
	}
}

// What a read's refusals read as: AccessDenied on LookupEvents is the role
// lacking the statement; throttling is named; another error and a mint
// refusal pass through with their own cause. LookupAllowed, the role test's
// one call, asks for one event of the last minute and nothing by name.
func TestActivityRefusalsAndLookupAllowed(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 17, 10, 20, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		err  error
		want error
	}{
		{"access denied", &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized to perform: cloudtrail:LookupEvents"}, ErrLookupDenied},
		{"throttled", &smithy.GenericAPIError{Code: "ThrottlingException", Message: "Rate exceeded"}, ErrLookupThrottled},
	} {
		trail := &fakeTrail{err: tc.err}
		r := &ActivityReader{Minter: &fakeAuditMinter{}, NewTrail: func(context.Context, string, Credentials) (TrailReader, error) { return trail, nil }}
		if _, err := r.Read(ctx, ActivityRequest{SessionName: "zanskar-s", From: now.Add(-time.Minute), To: now}); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
		if err := LookupAllowed(ctx, trail, now); !errors.Is(err, tc.want) {
			t.Errorf("%s: LookupAllowed %v, want %v", tc.name, err, tc.want)
		}
	}
	network := errors.New("dial tcp: i/o timeout")
	trail := &fakeTrail{err: network}
	r := &ActivityReader{Minter: &fakeAuditMinter{}, NewTrail: func(context.Context, string, Credentials) (TrailReader, error) { return trail, nil }}
	if _, err := r.Read(ctx, ActivityRequest{SessionName: "zanskar-s", From: now.Add(-time.Minute), To: now}); !errors.Is(err, network) || errors.Is(err, ErrLookupDenied) {
		t.Fatalf("network: %v", err)
	}
	refused := &fakeAuditMinter{err: fmt.Errorf("%w: not trusted", ErrMintRefused)}
	r = &ActivityReader{Minter: refused, NewTrail: func(context.Context, string, Credentials) (TrailReader, error) {
		t.Fatal("the trail was built although the mint was refused")
		return nil, nil
	}}
	if _, err := r.Read(ctx, ActivityRequest{SessionName: "zanskar-s"}); !errors.Is(err, ErrMintRefused) {
		t.Fatalf("mint refused: %v", err)
	}
	// Allowed: one event of the last minute, no attribute, no token.
	ok := &fakeTrail{pages: map[string]*cloudtrail.LookupEventsOutput{"": {}}}
	if err := LookupAllowed(ctx, ok, now); err != nil {
		t.Fatal(err)
	}
	in := ok.inputs[0]
	if aws.ToInt32(in.MaxResults) != 1 || len(in.LookupAttributes) != 0 || !in.EndTime.Equal(now) || !in.StartTime.Equal(now.Add(-time.Minute)) || in.NextToken != nil {
		t.Fatalf("the test's call: %+v", in)
	}
}

// ActivityLine: the time in UTC, the service and the call, read-only or
// write as CloudTrail said it (or - when it did not), the names joined, at
// most ten of them, - for none; a control character is not written to a
// terminal player.
func TestActivityLine(t *testing.T) {
	at := time.Date(2026, 11, 17, 10, 15, 32, 0, time.UTC)
	many := make([]string, 12)
	for i := range many {
		many[i] = fmt.Sprintf("i-%02d", i)
	}
	for _, tc := range []struct {
		name string
		ev   ActivityEvent
		want string
	}{
		{"a read-only call with no resource", ActivityEvent{Time: at, Source: "s3", Name: "ListBuckets", ReadOnly: aws.Bool(true)}, "10:15:32 UTC  s3 ListBuckets  read-only  -"},
		{"a write with two resources", ActivityEvent{Time: at, Source: "ec2", Name: "TerminateInstances", ReadOnly: aws.Bool(false), Resources: []string{"i-0abc", "i-0def"}}, "10:15:32 UTC  ec2 TerminateInstances  write  i-0abc, i-0def"},
		{"CloudTrail silent on read-only", ActivityEvent{Time: at, Source: "monitoring", Name: "PutMetricData"}, "10:15:32 UTC  monitoring PutMetricData  -  -"},
		{"a local time is said in UTC", ActivityEvent{Time: at.In(time.FixedZone("IST", 5*3600+1800)), Source: "iam", Name: "GetUser", ReadOnly: aws.Bool(true), Resources: []string{"alice"}}, "10:15:32 UTC  iam GetUser  read-only  alice"},
		{"twelve resources", ActivityEvent{Time: at, Source: "ec2", Name: "DescribeInstances", ReadOnly: aws.Bool(true), Resources: many}, "10:15:32 UTC  ec2 DescribeInstances  read-only  " + strings.Join(many[:10], ", ") + ", +2"},
		{"nothing named", ActivityEvent{Time: at}, "10:15:32 UTC  - -  -  -"},
	} {
		if got := ActivityLine(tc.ev); got != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
	ev := activityEventOf(event("e", "2026-11-17T10:15:32Z", "s3.amazonaws.com", "Put\x1b[31mObject", "FALSE", "bucket\x07/key", ""))
	if ev.Name != "Put_[31mObject" || len(ev.Resources) != 1 || ev.Resources[0] != "bucket_/key" || ev.ReadOnly == nil || *ev.ReadOnly {
		t.Fatalf("sanitised event: %+v", ev)
	}
}

// The activity policy (Setup, phase C): one statement, cloudtrail:LookupEvents
// on *, since the action takes no resource; the CLI puts it on the role as
// an inline policy and the CloudFormation carries it under Policies.
func TestActivityPermissionsPolicyAndPastes(t *testing.T) {
	pol := ActivityPermissionsPolicy()
	var doc struct {
		Version   string
		Statement []struct {
			Sid, Effect, Action, Resource string
		}
	}
	if err := json.Unmarshal([]byte(pol), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, pol)
	}
	if doc.Version != "2012-10-17" || len(doc.Statement) != 1 || doc.Statement[0].Effect != "Allow" || doc.Statement[0].Action != "cloudtrail:LookupEvents" || doc.Statement[0].Resource != "*" {
		t.Fatalf("policy: %s", pol)
	}
	trust := CloudTrustPolicy("arn:aws:iam::111111111111:role/zanskar-gw", "zanskar-"+strings.Repeat("b", 32))
	cli := CloudRoleCLI("Admin", trust, pol)
	for _, want := range []string{"cat > zanskar-activity.json <<'EOF'\n" + pol + "\nEOF\n", "aws iam put-role-policy --role-name Admin --policy-name ZanskarActivity --policy-document file://zanskar-activity.json\n"} {
		if !strings.Contains(cli, want) {
			t.Errorf("cli lacks %q:\n%s", want, cli)
		}
	}
	cf := CloudRoleCloudFormation("Admin", trust, pol)
	for _, want := range []string{"      Policies:\n        - PolicyName: ZanskarActivity\n          PolicyDocument:\n            {\n", `            "Version": "2012-10-17"`, `"Action": "cloudtrail:LookupEvents"`} {
		if !strings.Contains(cf, want) {
			t.Errorf("cloudformation lacks %q:\n%s", want, cf)
		}
	}
}
