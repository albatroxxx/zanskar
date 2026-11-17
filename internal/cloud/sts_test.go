// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
)

// SourceIdentityFor (ADR 0050, 1): the username where it fits STS's rule, 2
// to 64 characters of letters, digits and _+=,.@-; anything else becomes _,
// longer is cut at 64, and AWS's reserved prefix is pushed behind zanskar-.
func TestSourceIdentityFor(t *testing.T) {
	long := strings.Repeat("abcdefghij", 7) // 70 characters
	for _, tc := range []struct{ name, in, want string }{
		{"a plain username", "alice", "alice"},
		{"an email-form username (ADR 0035)", "bob.o-neil+ops@example.com", "bob.o-neil+ops@example.com"},
		{"spaces become underscores", "ann marie smith", "ann_marie_smith"},
		{"a 70-character username is cut at 64", long, long[:64]},
		{"a character outside the set", "jörg/ops", "j_rg_ops"},
		{"aws: is reserved", "aws:admin", "zanskar-aws_admin"},
		{"AWS: in any case", "AWS:root", "zanskar-AWS_root"},
		{"one character is too short", "x", "zanskar-user"},
		{"nothing at all", "", "zanskar-user"},
	} {
		if got := SourceIdentityFor(tc.in); got != tc.want {
			t.Errorf("%s: %q -> %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// SessionNameFor: zanskar- and the session id, the first 48 characters of a
// longer one, so the role session name stays within STS's 64.
func TestSessionNameFor(t *testing.T) {
	id := "3f9a1c20aaaaaaaaaaaaaaaaaaaaaaaa"
	if got := SessionNameFor(id); got != "zanskar-"+id {
		t.Fatalf("a 32-character id: %q", got)
	}
	long := strings.Repeat("0123456789", 6)
	if got := SessionNameFor(long); got != "zanskar-"+long[:48] || len(got) != 56 {
		t.Fatalf("a 60-character id: %q (%d)", got, len(got))
	}
	tags := SessionTags("ann marie", id)
	if tags["zanskar:user"] != "ann marie" || tags["zanskar:session"] != id {
		t.Fatalf("tags: %v", tags)
	}
	if v := tagValue("x\ty" + strings.Repeat("z", 300)); !strings.HasPrefix(v, "x_y") || len(v) != 256 {
		t.Fatalf("tag value: %q (%d)", v[:10], len(v))
	}
}

// fakeAssumer is STS as a unit test sees it: the one AssumeRole it was given,
// and the answer or error it was told to give.
type fakeAssumer struct {
	mu   sync.Mutex
	last *sts.AssumeRoleInput
	err  error
}

func (f *fakeAssumer) AssumeRole(_ context.Context, in *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.last = in
	if f.err != nil {
		return nil, f.err
	}
	exp := time.Now().Add(time.Duration(*in.DurationSeconds) * time.Second)
	return &sts.AssumeRoleOutput{
		Credentials:     &ststypes.Credentials{AccessKeyId: aws.String("ASIAFAKE"), SecretAccessKey: aws.String("secret"), SessionToken: aws.String("token"), Expiration: &exp},
		AssumedRoleUser: &ststypes.AssumedRoleUser{Arn: aws.String("arn:aws:sts::123456789012:assumed-role/Admin/" + *in.RoleSessionName)},
	}, nil
}

type fakeIdentifier struct {
	arn string
	err error
}

func (f fakeIdentifier) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &sts.GetCallerIdentityOutput{Arn: aws.String(f.arn)}, nil
}

// STS.Mint sends what a session needs CloudTrail to see (ADR 0050): the
// ExternalId, the source identity, the session name, the tags in a fixed
// order and the duration in seconds; refusals are told apart by stage, and a
// duration outside AWS's bounds never reaches AWS.
func TestSTSMintRequestAndRefusals(t *testing.T) {
	ctx := context.Background()
	fa := &fakeAssumer{}
	s := &STS{client: fa}
	req := MintRequest{RoleARN: "arn:aws:iam::123456789012:role/Admin", ExternalID: "zanskar-" + strings.Repeat("a", 32), SessionName: "zanskar-s1",
		SourceIdentity: "alice", Duration: 15 * time.Minute, Tags: map[string]string{"zanskar:user": "alice", "zanskar:session": "s1"}}
	c, err := s.Mint(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	in := fa.last
	if aws.ToString(in.RoleArn) != req.RoleARN || aws.ToString(in.ExternalId) != req.ExternalID || aws.ToString(in.RoleSessionName) != "zanskar-s1" ||
		aws.ToString(in.SourceIdentity) != "alice" || aws.ToInt32(in.DurationSeconds) != 900 {
		t.Fatalf("the request: %+v", in)
	}
	if len(in.Tags) != 2 || aws.ToString(in.Tags[0].Key) != "zanskar:session" || aws.ToString(in.Tags[1].Key) != "zanskar:user" {
		t.Fatalf("tags: %v", in.Tags)
	}
	if c.AccessKeyID != "ASIAFAKE" || c.SessionToken != "token" || c.AssumedARN != "arn:aws:sts::123456789012:assumed-role/Admin/zanskar-s1" || c.Expires.IsZero() {
		t.Fatalf("credentials: %+v", c)
	}

	// Outside AWS's bounds: refused here, nothing sent.
	fa.last = nil
	for _, d := range []time.Duration{14 * time.Minute, 13 * time.Hour, 0} {
		if _, err := s.Mint(ctx, MintRequest{RoleARN: req.RoleARN, SessionName: "x", Duration: d}); !errors.Is(err, ErrMintDuration) {
			t.Errorf("duration %v: %v", d, err)
		}
	}
	if fa.last != nil {
		t.Fatal("a duration outside the bounds reached AWS")
	}

	// What STS refuses, named by stage.
	for _, tc := range []struct {
		name, code, msg string
		want            error
	}{
		{"the trust policy", "AccessDenied", "User is not authorized to perform: sts:AssumeRole", ErrMintRefused},
		{"a missing sts:TagSession", "AccessDeniedException", "not authorized to perform: sts:TagSession", ErrMintRefused},
		{"above the role's maximum", "ValidationError", "The requested DurationSeconds exceeds the MaxSessionDuration set for this role.", ErrMintDuration},
	} {
		fa.err = &smithy.GenericAPIError{Code: tc.code, Message: tc.msg}
		_, err := s.Mint(ctx, req)
		if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), tc.msg) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	// Anything else passes as it is: the network, a malformed answer.
	fa.err = errors.New("dial tcp: i/o timeout")
	if _, err := s.Mint(ctx, req); errors.Is(err, ErrMintRefused) || errors.Is(err, ErrMintDuration) || err == nil {
		t.Fatalf("a network error: %v", err)
	}

	// The identity stage, with the minted credentials.
	s.as = func(c Credentials) stsIdentifier {
		if c.AccessKeyID != "ASIAFAKE" {
			t.Errorf("the identity call was given %+v", c)
		}
		return fakeIdentifier{arn: "arn:aws:sts::123456789012:assumed-role/Admin/zanskar-s1"}
	}
	if arn, err := s.CallerIdentity(ctx, c); err != nil || arn != "arn:aws:sts::123456789012:assumed-role/Admin/zanskar-s1" {
		t.Fatalf("identity: %q %v", arn, err)
	}
	s.as = func(Credentials) stsIdentifier {
		return fakeIdentifier{err: &smithy.GenericAPIError{Code: "AccessDenied", Message: "explicit deny in a permissions boundary"}}
	}
	if _, err := s.CallerIdentity(ctx, c); err == nil || !strings.Contains(err.Error(), "permissions boundary") || strings.Contains(err.Error(), "RequestID") {
		t.Fatalf("identity refused: %v", err)
	}
	if _, err := (&STS{client: fa}).CallerIdentity(ctx, c); err == nil {
		t.Fatal("no client for the credentials passed")
	}
}

// federation is AWS's sign-in endpoint as a test runs it: it records each
// call and can refuse SessionDuration, as AWS does for chained credentials.
type federation struct {
	mu            sync.Mutex
	calls         []fedCall
	refuseWithDur bool
	status        int
	body          string
}

type fedCall struct {
	action, session, duration string
}

func (f *federation) handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f.mu.Lock()
	f.calls = append(f.calls, fedCall{q.Get("Action"), q.Get("Session"), q.Get("SessionDuration")})
	refuse := f.refuseWithDur && q.Get("SessionDuration") != ""
	status, body := f.status, f.body
	f.mu.Unlock()
	switch {
	case refuse:
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"SessionDuration is not allowed for these credentials"}`))
	case status != 0:
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	default:
		_ = json.NewEncoder(w).Encode(map[string]string{"SigninToken": "signin-" + q.Get("SessionDuration")})
	}
}

// Federation.SignIn (ADR 0050, 3): the credentials go to getSigninToken as
// the Session document with the duration asked for; the answer is the login
// form the portal POSTs, never a URL. When AWS refuses the duration, the
// token is asked for again without it and honoured says so.
func TestFederationSignIn(t *testing.T) {
	ctx := context.Background()
	fed := &federation{}
	srv := httptest.NewServer(http.HandlerFunc(fed.handler))
	defer srv.Close()
	f := &Federation{Endpoint: srv.URL, Client: srv.Client()}
	creds := Credentials{AccessKeyID: "AKIA", SecretAccessKey: "sk", SessionToken: "st"}

	form, honoured, err := f.SignIn(ctx, creds, 2*time.Hour, "https://gw.example", "https://eu-west-1.console.aws.amazon.com/")
	if err != nil || !honoured {
		t.Fatalf("sign-in: %v honoured %v", err, honoured)
	}
	if form.Action != srv.URL || form.Fields["Action"] != "login" || form.Fields["Issuer"] != "https://gw.example" ||
		form.Fields["Destination"] != "https://eu-west-1.console.aws.amazon.com/" || form.Fields["SigninToken"] != "signin-7200" {
		t.Fatalf("form: %+v", form)
	}
	if len(fed.calls) != 1 || fed.calls[0].action != "getSigninToken" || fed.calls[0].duration != "7200" {
		t.Fatalf("calls: %+v", fed.calls)
	}
	var session map[string]string
	if err := json.Unmarshal([]byte(fed.calls[0].session), &session); err != nil || session["sessionId"] != "AKIA" || session["sessionKey"] != "sk" || session["sessionToken"] != "st" {
		t.Fatalf("session document: %q %v", fed.calls[0].session, err)
	}

	// AWS refuses the duration: asked again without it, not honoured.
	fed.refuseWithDur, fed.calls = true, nil
	form, honoured, err = f.SignIn(ctx, creds, 2*time.Hour, "https://gw.example", "")
	if err != nil || honoured || form.Fields["SigninToken"] != "signin-" || form.Fields["Destination"] != "https://console.aws.amazon.com/" {
		t.Fatalf("fallback: %+v honoured %v err %v", form, honoured, err)
	}
	if len(fed.calls) != 2 || fed.calls[0].duration != "7200" || fed.calls[1].duration != "" {
		t.Fatalf("fallback calls: %+v", fed.calls)
	}
	// No duration asked for: one call, not honoured by definition.
	fed.calls = nil
	if _, honoured, err := f.SignIn(ctx, creds, 0, "https://gw.example", ""); err != nil || honoured || len(fed.calls) != 1 || fed.calls[0].duration != "" {
		t.Fatalf("without a duration: %v %v %+v", honoured, err, fed.calls)
	}

	// A 5xx is a refusal, with no second try; an answer without a token too.
	fed.refuseWithDur, fed.status, fed.body, fed.calls = false, http.StatusInternalServerError, "", nil
	if _, _, err := f.SignIn(ctx, creds, time.Hour, "https://gw.example", ""); !errors.Is(err, ErrFederation) || len(fed.calls) != 1 {
		t.Fatalf("a 500: %v after %d calls", err, len(fed.calls))
	}
	fed.status, fed.body = http.StatusOK, `{"nothing":true}`
	if _, _, err := f.SignIn(ctx, creds, time.Hour, "https://gw.example", ""); !errors.Is(err, ErrFederation) {
		t.Fatalf("no token: %v", err)
	}
	// A 4xx without a duration to drop is the end of it.
	fed.status, fed.body, fed.calls = http.StatusForbidden, `{"message":"no"}`, nil
	if _, _, err := f.SignIn(ctx, creds, time.Hour, "https://gw.example", ""); !errors.Is(err, ErrFederation) || len(fed.calls) != 2 {
		t.Fatalf("a 403 twice: %v after %d calls", err, len(fed.calls))
	}
}

// The destinations and STS hosts follow the region and its partition.
func TestConsoleDestinationAndSTSHost(t *testing.T) {
	for _, tc := range []struct{ region, console, sts string }{
		{"", "https://console.aws.amazon.com/", "sts.amazonaws.com"},
		{"eu-west-1", "https://eu-west-1.console.aws.amazon.com/", "sts.eu-west-1.amazonaws.com"},
		{"cn-north-1", "https://cn-north-1.console.amazonaws.cn/", "sts.cn-north-1.amazonaws.com.cn"},
	} {
		if got := ConsoleDestination(tc.region); got != tc.console {
			t.Errorf("console %q: %q", tc.region, got)
		}
		if got := STSHost(tc.region); got != tc.sts {
			t.Errorf("sts %q: %q", tc.region, got)
		}
	}
}

// The trust policy a role's account pastes (ADR 0050, 1): this gateway's
// principal, the three actions a mint needs, the ExternalId condition; empty
// while the principal is unknown, never a placeholder. The CLI and the
// CloudFormation name the role.
func TestCloudTrustDocuments(t *testing.T) {
	if CloudTrustPolicy("", "zanskar-x") != "" {
		t.Fatal("a policy without a principal is not a policy")
	}
	trust := CloudTrustPolicy("arn:aws:iam::111111111111:role/zanskar-gw", "zanskar-"+strings.Repeat("b", 32))
	var doc struct {
		Version   string
		Statement []struct {
			Effect    string
			Principal map[string]string
			Action    []string
			Condition map[string]map[string]string
		}
	}
	if err := json.Unmarshal([]byte(trust), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, trust)
	}
	st := doc.Statement[0]
	if doc.Version != "2012-10-17" || len(doc.Statement) != 1 || st.Effect != "Allow" || st.Principal["AWS"] != "arn:aws:iam::111111111111:role/zanskar-gw" ||
		strings.Join(st.Action, ",") != "sts:AssumeRole,sts:SetSourceIdentity,sts:TagSession" || st.Condition["StringEquals"]["sts:ExternalId"] != "zanskar-"+strings.Repeat("b", 32) {
		t.Fatalf("trust policy: %s", trust)
	}
	cli := CloudRoleCLI("Admin", trust, ActivityPermissionsPolicy())
	for _, want := range []string{"update-assume-role-policy --role-name Admin", "create-role --role-name Admin", "--max-session-duration 43200", trust} {
		if !strings.Contains(cli, want) {
			t.Errorf("cli lacks %q:\n%s", want, cli)
		}
	}
	cf := CloudRoleCloudFormation("Admin", trust, ActivityPermissionsPolicy())
	for _, want := range []string{"RoleName: Admin", "MaxSessionDuration: 43200", "AssumeRolePolicyDocument:", `        "Version": "2012-10-17"`, "ManagedPolicyArns: []"} {
		if !strings.Contains(cf, want) {
			t.Errorf("cloudformation lacks %q:\n%s", want, cf)
		}
	}
	for arn, want := range map[string]string{
		"arn:aws:iam::123456789012:role/Admin":          "Admin",
		"arn:aws:iam::123456789012:role/team/ops/Admin": "Admin",
		"not-an-arn": "not-an-arn",
	} {
		if got := RoleNameOf(arn); got != want {
			t.Errorf("RoleNameOf(%q) = %q", arn, got)
		}
	}
	if AccountOf("arn:aws:iam::123456789012:role/Admin") != "123456789012" || AccountOf("x") != "" {
		t.Fatal("AccountOf")
	}
}
