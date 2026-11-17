// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
)

// A cloud account's role (ADR 0050) is assumed for the person: the gateway's
// own AWS identity calls AssumeRole on the enrolled role with the ExternalId
// its trust policy carries, the person's username as the source identity and
// the session's id as the session name, so CloudTrail in the account names
// both on every call made with the credentials. Nothing long-lived is held
// for any account.

// MintRequest is one AssumeRole as a cloud session asks for it.
type MintRequest struct {
	RoleARN        string
	ExternalID     string
	SessionName    string
	SourceIdentity string
	Duration       time.Duration
	Tags           map[string]string
}

// Credentials are what AssumeRole answered: the three parts a client signs
// with, when they end, and the ARN the session acts as.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expires         time.Time
	AssumedARN      string
}

// RoleMinter assumes an enrolled role. STS is the real one; tests use a fake
// that never reaches AWS. CallerIdentity asks STS who the minted credentials
// are (GetCallerIdentity), the second stage of a role's test: a role assumed
// whose credentials then fail the simplest call has a permissions boundary
// or a policy that denies everything, which the mint alone would not show.
type RoleMinter interface {
	Mint(ctx context.Context, req MintRequest) (Credentials, error)
	CallerIdentity(ctx context.Context, c Credentials) (string, error)
}

// Mint refusals, told apart so the console names the stage.
var (
	// ErrMintRefused is AccessDenied: the trust policy does not name this
	// gateway, the ExternalId differs, or the trust policy lacks
	// sts:SetSourceIdentity or sts:TagSession.
	ErrMintRefused = errors.New("cloud: the role could not be assumed")
	// ErrMintDuration is a DurationSeconds above the role's maximum session.
	ErrMintDuration = errors.New("cloud: the duration exceeds the role's maximum session")
)

// Mint limits, AWS's: a session of 15 minutes to 12 hours.
const (
	MintMinDuration = 15 * time.Minute
	MintMaxDuration = 12 * time.Hour
)

type stsAssumer interface {
	AssumeRole(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

type stsIdentifier interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// STS mints with the gateway's own AWS identity (the instance profile, the
// environment, a mounted profile), as the autoscaling and EKS roles are
// assumed; not through a chained role, which would cap every session at an
// hour (AWS: role chaining).
type STS struct {
	client stsAssumer
	// as builds the client that acts with minted credentials, for
	// CallerIdentity; tests replace it with one that never reaches AWS.
	as func(c Credentials) stsIdentifier
}

// NewSTS returns a minter in region: the target's, or the gateway's own when
// the target has none; STS is global, the region picks the endpoint.
func NewSTS(ctx context.Context, region string) (*STS, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	base, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("cloud: aws base config: %w", err)
	}
	if base.Region == "" {
		base.Region = "us-east-1"
	}
	return &STS{client: sts.NewFromConfig(base), as: func(c Credentials) stsIdentifier {
		return sts.NewFromConfig(base, func(o *sts.Options) {
			o.Credentials = credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, c.SessionToken)
		})
	}}, nil
}

// CallerIdentity asks STS, with the minted credentials, who they are: the
// assumed-role ARN, which a test shows; an error names what refused.
func (s *STS) CallerIdentity(ctx context.Context, c Credentials) (string, error) {
	if s.as == nil {
		return "", errors.New("cloud: no client for the minted credentials")
	}
	out, err := s.as(c).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) {
			return "", fmt.Errorf("cloud: GetCallerIdentity: %s: %s", ae.ErrorCode(), ae.ErrorMessage())
		}
		return "", fmt.Errorf("cloud: GetCallerIdentity: %w", err)
	}
	return aws.ToString(out.Arn), nil
}

// Mint assumes the role once for the request.
func (s *STS) Mint(ctx context.Context, req MintRequest) (Credentials, error) {
	if req.Duration < MintMinDuration || req.Duration > MintMaxDuration {
		return Credentials{}, fmt.Errorf("%w: %s is outside 15 minutes to 12 hours", ErrMintDuration, req.Duration)
	}
	in := &sts.AssumeRoleInput{RoleArn: aws.String(req.RoleARN), RoleSessionName: aws.String(req.SessionName),
		DurationSeconds: aws.Int32(int32(req.Duration / time.Second))} // #nosec G115 -- bounded to 12 hours above
	if req.ExternalID != "" {
		in.ExternalId = aws.String(req.ExternalID)
	}
	if req.SourceIdentity != "" {
		in.SourceIdentity = aws.String(req.SourceIdentity)
	}
	keys := make([]string, 0, len(req.Tags))
	for k := range req.Tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		in.Tags = append(in.Tags, ststypes.Tag{Key: aws.String(k), Value: aws.String(req.Tags[k])})
	}
	out, err := s.client.AssumeRole(ctx, in)
	if err != nil {
		return Credentials{}, classifyMint(err)
	}
	if out.Credentials == nil {
		return Credentials{}, errors.New("cloud: AssumeRole answered no credentials")
	}
	c := Credentials{AccessKeyID: aws.ToString(out.Credentials.AccessKeyId), SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken: aws.ToString(out.Credentials.SessionToken), Expires: aws.ToTime(out.Credentials.Expiration)}
	if out.AssumedRoleUser != nil {
		c.AssumedARN = aws.ToString(out.AssumedRoleUser.Arn)
	}
	return c, nil
}

// classifyMint names what STS refused, in Zanskar's terms.
func classifyMint(err error) error {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "AccessDenied", "AccessDeniedException":
			return fmt.Errorf("%w: %s", ErrMintRefused, ae.ErrorMessage())
		case "ValidationError":
			if strings.Contains(ae.ErrorMessage(), "DurationSeconds") {
				return fmt.Errorf("%w: %s", ErrMintDuration, ae.ErrorMessage())
			}
		}
	}
	return err
}

// SourceIdentityFor is the person's username as STS takes a source identity:
// 2 to 64 characters of ASCII letters, digits and _+=,.@- (an email-form
// username passes as it is); a character outside the set becomes _, longer
// is cut at 64, and a value that would begin aws: (AWS's reserved prefix) is
// prefixed zanskar-. The audit event carries the full username, and the
// session name is the join in every case.
func SourceIdentityFor(username string) string {
	var b strings.Builder
	for _, r := range username {
		switch {
		case r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'):
			b.WriteRune(r)
		case strings.ContainsRune("_+=,.@-", r):
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	s := b.String()
	if strings.HasPrefix(strings.ToLower(username), "aws:") {
		s = "zanskar-" + s
	}
	if len(s) > 64 {
		s = s[:64]
	}
	if len(s) < 2 {
		s = "zanskar-user"
	}
	return s
}

// SessionNameFor is the role session name of a Zanskar session: zanskar- and
// the first 48 characters of the session id (the whole of a 32-character
// id), within STS's 64, so CloudTrail's userName and the assumed-role ARN
// name the session on the record.
func SessionNameFor(sessionID string) string {
	if len(sessionID) > 48 {
		sessionID = sessionID[:48]
	}
	return SourceIdentityFor("zanskar-" + sessionID)
}

// SessionTags are the session tags every mint carries, so a policy in the
// account may condition on them (aws:PrincipalTag).
func SessionTags(username, sessionID string) map[string]string {
	return map[string]string{"zanskar:user": tagValue(username), "zanskar:session": tagValue(sessionID)}
}

// tagValue keeps a value within AWS's tag alphabet and 256 characters.
func tagValue(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'):
			b.WriteRune(r)
		case strings.ContainsRune(" _.:/=+-@", r):
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if len(out) > 256 {
		out = out[:256]
	}
	return out
}

// FederationEndpoint is AWS's sign-in federation endpoint, where temporary
// credentials become a console sign-in (the custom identity broker flow).
// The portal POSTs the sign-in form here from a page under the console's
// Content-Security-Policy, whose form-action names this host and the console
// hosts the login redirects to (internal/server/spa.go, uiCSP): a change here
// or in ConsoleDestination must follow there, or the browser refuses the POST
// in silence.
const FederationEndpoint = "https://signin.aws.amazon.com/federation"

// Federation exchanges a role's credentials for a console sign-in. Endpoint
// and Client are injectable so tests run against a local server.
type Federation struct {
	Endpoint string
	Client   *http.Client
}

// SignIn is the console sign-in as the portal submits it: a form POSTed to
// Action, never a URL kept in a browser's history. The sign-in token is good
// for 15 minutes; the console session it opens runs for the duration asked
// for, or the credentials' when AWS did not honour it.
type SignIn struct {
	Action string            `json:"action"`
	Fields map[string]string `json:"fields"`
}

// ErrFederation is a refusal by the federation endpoint.
var ErrFederation = errors.New("cloud: the console sign-in could not be issued")

// federationTimeout bounds each call to the endpoint.
const federationTimeout = 15 * time.Second

// SignIn asks for a sign-in token for c, for a console session of
// sessionDuration (0 leaves AWS to the credentials' own length). AWS refuses
// SessionDuration when the credentials come from a chained role; a refusal
// is retried without it, and honoured says which way the session was made.
func (f *Federation) SignIn(ctx context.Context, c Credentials, sessionDuration time.Duration, issuer, destination string) (SignIn, bool, error) {
	endpoint := f.Endpoint
	if endpoint == "" {
		endpoint = FederationEndpoint
	}
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: federationTimeout}
	}
	sess, err := json.Marshal(map[string]string{"sessionId": c.AccessKeyID, "sessionKey": c.SecretAccessKey, "sessionToken": c.SessionToken})
	if err != nil {
		return SignIn{}, false, err
	}
	token, honoured, err := signinToken(ctx, client, endpoint, string(sess), sessionDuration)
	if err != nil {
		return SignIn{}, false, err
	}
	if destination == "" {
		destination = ConsoleDestination("")
	}
	return SignIn{Action: endpoint, Fields: map[string]string{"Action": "login", "Issuer": issuer, "Destination": destination, "SigninToken": token}}, honoured, nil
}

func signinToken(ctx context.Context, client *http.Client, endpoint, session string, d time.Duration) (string, bool, error) {
	ask := func(withDuration bool) (string, int, error) {
		q := url.Values{"Action": {"getSigninToken"}, "Session": {session}}
		if withDuration {
			q.Set("SessionDuration", fmt.Sprint(int(d/time.Second)))
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+q.Encode(), nil)
		if err != nil {
			return "", 0, err
		}
		res, err := client.Do(req)
		if err != nil {
			// A *url.Error prints the URL, and the URL's Session query is the
			// credentials: the dial or timeout error alone is kept, never
			// the address (review 2026-11-17, C2).
			var ue *url.Error
			if errors.As(err, &ue) {
				err = ue.Err
			}
			return "", 0, fmt.Errorf("%w: %w", ErrFederation, err)
		}
		defer func() { _ = res.Body.Close() }()
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
		if res.StatusCode != http.StatusOK {
			return "", res.StatusCode, fmt.Errorf("%w: the endpoint answered %d", ErrFederation, res.StatusCode)
		}
		var out struct {
			SigninToken string `json:"SigninToken"`
		}
		if err := json.Unmarshal(body, &out); err != nil || out.SigninToken == "" {
			return "", res.StatusCode, fmt.Errorf("%w: the endpoint answered no token", ErrFederation)
		}
		return out.SigninToken, res.StatusCode, nil
	}
	if d > 0 {
		token, status, err := ask(true)
		if err == nil {
			return token, true, nil
		}
		if status < 400 || status >= 500 {
			return "", false, err
		}
		// A 4xx with SessionDuration: AWS refuses it for chained credentials
		// (and above the role's maximum); the session takes the credentials'
		// own length instead.
	}
	token, _, err := ask(false)
	return token, false, err
}

// ConsoleDestination is where the console opens: the region's console, or
// the global one without a region.
func ConsoleDestination(region string) string {
	if region == "" {
		return "https://console.aws.amazon.com/"
	}
	if Partition(region) == "aws-cn" {
		return "https://" + region + ".console.amazonaws.cn/"
	}
	return "https://" + region + ".console.aws.amazon.com/"
}

// STSHost is the STS endpoint a cloud target's address names: what the
// gateway reaches for it, as a cluster's address is its API server's host.
func STSHost(region string) string {
	switch {
	case region == "":
		return "sts.amazonaws.com"
	case Partition(region) == "aws-cn":
		return "sts." + region + ".amazonaws.com.cn"
	}
	return "sts." + region + ".amazonaws.com"
}

// CloudTrustPolicy is the enrolled role's trust policy for the gateway
// principal, or "" while the principal is unknown (a policy with a
// placeholder looks finished and is not, ADR 0023). Beside sts:AssumeRole
// it allows sts:SetSourceIdentity and sts:TagSession, which every mint
// needs: without them STS refuses a source identity or a tag.
func CloudTrustPolicy(gatewayPrincipal, externalID string) string {
	if gatewayPrincipal == "" {
		return ""
	}
	return RenderPolicy(map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{{
			"Effect":    "Allow",
			"Principal": map[string]any{"AWS": gatewayPrincipal},
			"Action":    []string{"sts:AssumeRole", "sts:SetSourceIdentity", "sts:TagSession"},
			"Condition": map[string]any{"StringEquals": map[string]any{"sts:ExternalId": externalID}},
		}},
	})
}

// CloudRoleCLI puts the trust policy on the role: on one that exists, as
// the usual case is (the role carries the permissions the person will act
// with, which are the account's business), or as a new role to which the
// administrator then attaches them. Either way the activity policy goes on
// as an inline policy (phase C): the one statement the gateway's own read
// of CloudTrail needs.
func CloudRoleCLI(roleName, trustPolicy, activityPolicy string) string {
	return "cat > zanskar-trust.json <<'EOF'\n" + trustPolicy + "\nEOF\n" +
		"cat > zanskar-activity.json <<'EOF'\n" + activityPolicy + "\nEOF\n" +
		"# an existing role: replace its trust policy\n" +
		"aws iam update-assume-role-policy --role-name " + roleName + " --policy-document file://zanskar-trust.json\n" +
		"# or a new role, to which you then attach the permissions it should carry\n" +
		"aws iam create-role --role-name " + roleName + " --assume-role-policy-document file://zanskar-trust.json \\\n" +
		"  --description 'Zanskar gateway: assumed for approved people' --max-session-duration 43200\n" +
		"# either way: the session's activity is read from CloudTrail\n" +
		"aws iam put-role-policy --role-name " + roleName + " --policy-name " + ActivityPolicyName + " --policy-document file://zanskar-activity.json\n"
}

// CloudRoleCloudFormation is a new role as a CloudFormation template, its
// permissions left for the administrator to add (ManagedPolicyArns), the
// activity policy inline. JSON policy documents are valid YAML, so they are
// embedded as they are.
func CloudRoleCloudFormation(roleName, trustPolicy, activityPolicy string) string {
	return "AWSTemplateFormatVersion: \"2010-09-09\"\n" +
		"Description: " + yamlString("Zanskar gateway: a role assumed for approved people") + "\n" +
		"Resources:\n  ZanskarRole:\n    Type: AWS::IAM::Role\n    Properties:\n      RoleName: " + roleName + "\n" +
		"      MaxSessionDuration: 43200\n" +
		"      AssumeRolePolicyDocument:\n" + indentLines(trustPolicy, "        ") +
		"      ManagedPolicyArns: []  # the permissions the role should carry\n" +
		"      Policies:\n        - PolicyName: " + ActivityPolicyName + "\n          PolicyDocument:\n" + indentLines(activityPolicy, "            ") +
		"Outputs:\n  RoleArn:\n    Value: !GetAtt ZanskarRole.Arn\n"
}

// RoleNameOf is the role's name from its ARN, the last path element.
func RoleNameOf(roleARN string) string {
	_, name, ok := strings.Cut(roleARN, ":role/")
	if !ok {
		return roleARN
	}
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// AccountOf is the account id an IAM ARN names, "" when it names none.
func AccountOf(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return ""
	}
	return parts[4]
}

func yamlString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func indentLines(s, prefix string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		b.WriteString(prefix + line + "\n")
	}
	return b.String()
}
