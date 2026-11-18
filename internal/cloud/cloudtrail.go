// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/smithy-go"
)

// A cloud session's activity (ADR 0050, phase C) is what the person did in
// the account, read from CloudTrail: LookupEvents by Username, which for the
// calls a session makes is its role session name (zanskar-<session id>),
// through the enrolled role under the gateway's own session name, so the
// read is itself on the account's record as the gateway's and never as the
// person. CloudTrail delivers a management event up to fifteen minutes after
// it happened and answers two LookupEvents a second per account and region;
// the reader paces itself to that, and the session's last read waits the
// fifteen minutes. LookupEvents is regional: the read is made in the
// target's region, where its console opens, or the gateway's own without
// one; a call the person made in another region is in that region's trail.

// Names the gateway's own reads carry in the account, so an auditor there
// tells the gateway's lookups from the person's calls.
const (
	AuditSessionName    = "zanskar-gateway-audit"
	AuditSourceIdentity = "zanskar-gateway"
)

// TrailReader is what the reader needs of CloudTrail, LookupEvents as the
// SDK's client signs it; tests stand in a fake that never reaches AWS.
type TrailReader interface {
	LookupEvents(ctx context.Context, in *cloudtrail.LookupEventsInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

// TrailFactory builds the CloudTrail client that acts with minted
// credentials in a region; NewTrailReader is the real one.
type TrailFactory func(ctx context.Context, region string, c Credentials) (TrailReader, error)

// NewTrailReader builds the SDK's CloudTrail client over c, in region or the
// gateway's own when the target has none (us-east-1 when neither is set, as
// NewSTS falls back).
func NewTrailReader(ctx context.Context, region string, c Credentials) (TrailReader, error) {
	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, c.SessionToken)),
	}
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("cloud: aws config for CloudTrail: %w", err)
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	return cloudtrail.NewFromConfig(cfg), nil
}

// ActivityEvent is one thing done in the account, as the recording says it.
type ActivityEvent struct {
	ID   string
	Time time.Time
	// Source is the event source's short name (s3, ec2, iam), Name the call.
	Source string
	Name   string
	// ReadOnly is CloudTrail's word on whether the call changed anything;
	// nil when it gave none.
	ReadOnly *bool
	// Resources are the names of what the call named, as CloudTrail lists them.
	Resources []string
}

// ActivityRequest is one read of a session's activity.
type ActivityRequest struct {
	RoleARN    string
	ExternalID string
	Region     string
	// SessionName is the Zanskar session's role session name, CloudTrail's
	// Username for every call the session made.
	SessionName string
	From, To    time.Time
	// Seen holds the ids of the events already on the record and gains the
	// ones this read returns. Successive reads of a session overlap by the
	// lateness, since an event may arrive after a window that covered its
	// time was read; Seen keeps each event on the record once.
	Seen map[string]bool
}

// Bounds of a read.
const (
	// activityPageSize is the most LookupEvents answers a call.
	activityPageSize = 50
	// activityMaxPages bounds one read at 2,000 events; a session busier
	// than that has the rest left unread, and the log says so.
	activityMaxPages = 40
	// activityPace spaces two calls: CloudTrail allows two LookupEvents a
	// second per account and region.
	activityPace = 500 * time.Millisecond
	// activityMaxResources bounds how many names a line carries.
	activityMaxResources = 10
)

// Refusals a read tells apart, so the recording names the cause.
var (
	// ErrLookupDenied is AccessDenied on LookupEvents: the role lacks the
	// statement the Setup prints (cloudtrail:LookupEvents).
	ErrLookupDenied = errors.New("cloud: the role lacks cloudtrail:LookupEvents")
	// ErrLookupThrottled is CloudTrail refusing the pace.
	ErrLookupThrottled = errors.New("cloud: CloudTrail throttled the read")
)

// ActivityReader reads a session's activity: a mint of the role under the
// gateway's own session name, then LookupEvents by the session's name,
// paged and paced. Now and Sleep are the clock the pacing reads; tests move
// them. NewTrail nil is the SDK's client.
type ActivityReader struct {
	Minter   RoleMinter
	NewTrail TrailFactory
	Now      func() time.Time
	Sleep    func(time.Duration)
	Log      *slog.Logger
}

// Read assumes the role as the gateway and reads the events of req's window
// for its session name, deduplicated against req.Seen and sorted by time. A
// refusal to assume is the minter's error; a refusal to read is
// ErrLookupDenied or ErrLookupThrottled where CloudTrail said so.
func (a *ActivityReader) Read(ctx context.Context, req ActivityRequest) ([]ActivityEvent, error) {
	creds, err := a.Minter.Mint(ctx, MintRequest{RoleARN: req.RoleARN, ExternalID: req.ExternalID, SessionName: AuditSessionName,
		SourceIdentity: AuditSourceIdentity, Duration: MintMinDuration, Tags: map[string]string{"zanskar:purpose": "audit"}})
	if err != nil {
		return nil, err
	}
	newTrail := a.NewTrail
	if newTrail == nil {
		newTrail = NewTrailReader
	}
	trail, err := newTrail(ctx, req.Region, creds)
	if err != nil {
		return nil, err
	}
	return a.lookup(ctx, trail, req)
}

// lookup pages through LookupEvents for the window, two calls a second at
// most, up to activityMaxPages.
func (a *ActivityReader) lookup(ctx context.Context, trail TrailReader, req ActivityRequest) ([]ActivityEvent, error) {
	now, sleep := a.Now, a.Sleep
	if now == nil {
		now = time.Now
	}
	if sleep == nil {
		sleep = time.Sleep
	}
	seen := req.Seen
	if seen == nil {
		seen = map[string]bool{}
	}
	var (
		out  []ActivityEvent
		next *string
		last time.Time
		more bool
	)
	for page := 0; page < activityMaxPages; page++ {
		if page > 0 {
			if wait := activityPace - now().Sub(last); wait > 0 {
				sleep(wait)
			}
		}
		last = now()
		res, err := trail.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
			LookupAttributes: []cttypes.LookupAttribute{{AttributeKey: cttypes.LookupAttributeKeyUsername, AttributeValue: aws.String(req.SessionName)}},
			StartTime:        aws.Time(req.From), EndTime: aws.Time(req.To), MaxResults: aws.Int32(activityPageSize), NextToken: next})
		if err != nil {
			return nil, classifyLookup(err)
		}
		for _, e := range res.Events {
			ev := activityEventOf(e)
			// An event without an id cannot be told from one already on
			// the record; CloudTrail gives every event one.
			if ev.ID != "" {
				if seen[ev.ID] {
					continue
				}
				seen[ev.ID] = true
			}
			out = append(out, ev)
		}
		next = res.NextToken
		more = aws.ToString(next) != ""
		if !more {
			break
		}
	}
	if more && a.Log != nil {
		a.Log.Warn("activity read stopped at its page bound; the rest of the window is left unread", "pages", activityMaxPages, "session_name", req.SessionName)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out, nil
}

// LookupAllowed makes the one call a role's test makes: LookupEvents for
// the last minute, one event at most, under the test's credentials. It
// returns nil when the role may read CloudTrail, ErrLookupDenied when it may
// not, and the call's own error otherwise.
func LookupAllowed(ctx context.Context, trail TrailReader, now time.Time) error {
	_, err := trail.LookupEvents(ctx, &cloudtrail.LookupEventsInput{StartTime: aws.Time(now.Add(-time.Minute)), EndTime: aws.Time(now), MaxResults: aws.Int32(1)})
	return classifyLookup(err)
}

// classifyLookup names what CloudTrail refused, in Zanskar's terms.
func classifyLookup(err error) error {
	if err == nil {
		return nil
	}
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "AccessDeniedException", "AccessDenied":
			return fmt.Errorf("%w: %s", ErrLookupDenied, ae.ErrorMessage())
		case "ThrottlingException", "Throttling":
			return fmt.Errorf("%w: %s", ErrLookupThrottled, ae.ErrorMessage())
		}
	}
	return err
}

// activityEventOf is CloudTrail's event as the recording takes it: the raw
// CloudTrailEvent JSON is not kept (it carries request parameters, which
// may name what the person typed).
func activityEventOf(e cttypes.Event) ActivityEvent {
	ev := ActivityEvent{ID: aws.ToString(e.EventId), Time: aws.ToTime(e.EventTime), Source: shortSource(aws.ToString(e.EventSource)), Name: printable(aws.ToString(e.EventName))}
	switch strings.ToLower(aws.ToString(e.ReadOnly)) {
	case "true":
		ev.ReadOnly = aws.Bool(true)
	case "false":
		ev.ReadOnly = aws.Bool(false)
	}
	for _, r := range e.Resources {
		if n := printable(aws.ToString(r.ResourceName)); n != "" {
			ev.Resources = append(ev.Resources, n)
		}
	}
	return ev
}

// shortSource is the service of an event source: s3 of s3.amazonaws.com.
func shortSource(s string) string {
	s = strings.TrimSuffix(strings.TrimSuffix(s, ".amazonaws.com.cn"), ".amazonaws.com")
	return printable(s)
}

// printable keeps a value CloudTrail answered to what a terminal player
// shows as text: a control character becomes _.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, s)
}

// ActivityLine is one event as a recording line: the time, the service and
// the call, whether it only read, and what it named, or "-" where CloudTrail
// said nothing.
func ActivityLine(ev ActivityEvent) string {
	rw := "-"
	if ev.ReadOnly != nil {
		rw = "write"
		if *ev.ReadOnly {
			rw = "read-only"
		}
	}
	res := "-"
	if len(ev.Resources) > 0 {
		names, more := ev.Resources, ""
		if len(names) > activityMaxResources {
			more = fmt.Sprintf(", +%d", len(names)-activityMaxResources)
			names = names[:activityMaxResources]
		}
		res = strings.Join(names, ", ") + more
	}
	src, name := ev.Source, ev.Name
	if src == "" {
		src = "-"
	}
	if name == "" {
		name = "-"
	}
	return ev.Time.UTC().Format("15:04:05 UTC") + "  " + src + " " + name + "  " + rw + "  " + res
}

// ActivityPolicyName names the inline policy the Setup's pastes put on the
// role for the activity read.
const ActivityPolicyName = "ZanskarActivity"

// ActivityPermissionsPolicy is the one statement phase C needs of the
// enrolled role: cloudtrail:LookupEvents, which takes no resource. Without
// it the session's activity is not read, and the role's test says so.
func ActivityPermissionsPolicy() string {
	return RenderPolicy(map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{{
			"Sid":      ActivityPolicyName,
			"Effect":   "Allow",
			"Action":   "cloudtrail:LookupEvents",
			"Resource": "*",
		}},
	})
}
