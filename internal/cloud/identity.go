// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Identity is the AWS principal the gateway runs as, which the customer's
// cross-account role must trust (ADR 0023). Principal is the form a trust
// policy needs: the IAM role ARN, never the assumed-role session ARN STS
// reports and never an instance-profile ARN.
type Identity struct {
	Principal string `json:"principal,omitempty"`
	// Source: environment (ZANSKAR_AWS_GATEWAY_PRINCIPAL), detected (STS
	// GetCallerIdentity through the SDK's default chain), or none.
	Source    string `json:"source"`
	AccountID string `json:"account_id,omitempty"`
	RawARN    string `json:"raw_arn,omitempty"`
	// Platform says where the gateway runs as far as AWS is concerned:
	// "aws" on EC2, EKS or ECS, "none" anywhere else. The console uses it
	// to tell a misconfiguration (on AWS, no role) from the ordinary case
	// of a gateway that simply does not live on AWS, which is no error.
	Platform  string    `json:"platform"`
	CheckedAt time.Time `json:"checked_at"`
	Error     string    `json:"error,omitempty"`
}

// Identity sources.
const (
	SourceEnvironment = "environment"
	SourceDetected    = "detected"
	SourceNone        = "none"
)

// Platforms.
const (
	PlatformAWS  = "aws"
	PlatformNone = "none"
)

// imdsProbe reports whether the EC2 instance metadata service answers the
// IMDSv2 token request. Only a 200 counts: Azure and GCP serve their own
// metadata at the same address and answer this request with errors, so a
// mere response proves nothing about AWS. Swapped in tests.
var imdsProbe = func(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://169.254.169.254/latest/api/token", nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// DetectPlatform says whether the gateway runs on AWS compute: the serving
// environment's own variables first (IRSA, ECS, Elastic Beanstalk and
// friends), the metadata service's presence otherwise. It shapes what the
// console says, never what the gateway may do.
func DetectPlatform(ctx context.Context) string {
	for _, v := range []string{"AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_EXECUTION_ENV"} {
		if os.Getenv(v) != "" {
			return PlatformAWS
		}
	}
	if imdsProbe(ctx) {
		return PlatformAWS
	}
	return PlatformNone
}

// detectTimeout bounds one detection: off AWS, the instance metadata
// service does not answer and the SDK gives up on its own, but never later
// than this.
const detectTimeout = 5 * time.Second

// GatewayIdentity resolves the gateway's principal once and caches it. An
// explicit override from the environment always wins over detection, so an
// operator can name a different principal (a proxying role, or the ARN of a
// gateway that runs outside AWS).
type GatewayIdentity struct {
	override string
	detect   func(context.Context) (Identity, error)
	platform func(context.Context) string

	mu     sync.Mutex
	cached *Identity
}

// NewGatewayIdentity returns a resolver; override, when set, is used as is.
func NewGatewayIdentity(override string) *GatewayIdentity {
	return &GatewayIdentity{override: strings.TrimSpace(override), detect: DetectIdentity, platform: DetectPlatform}
}

// Get returns the cached identity, detecting it on first use.
func (g *GatewayIdentity) Get(ctx context.Context) Identity {
	g.mu.Lock()
	c := g.cached
	g.mu.Unlock()
	if c != nil {
		return *c
	}
	return g.Refresh(ctx)
}

// Refresh detects the identity again, replacing the cache. An override still
// learns its platform, so the console can say "set by the environment,
// running outside AWS" truthfully.
func (g *GatewayIdentity) Refresh(ctx context.Context) Identity {
	ctx, cancel := context.WithTimeout(ctx, detectTimeout)
	defer cancel()
	var id Identity
	if g.override != "" {
		id = Identity{Principal: g.override, Source: SourceEnvironment}
	} else if detected, err := g.detect(ctx); err == nil {
		id = detected
	} else {
		id = Identity{Source: SourceNone, Error: err.Error()}
	}
	id.Platform = g.platform(ctx)
	if id.Source == SourceNone && id.Platform == PlatformNone {
		// Off AWS, a missing identity is the ordinary case, not a fault:
		// the SDK's chain-of-providers error would only alarm.
		id.Error = "not running on AWS"
	}
	id.CheckedAt = time.Now().UTC()
	g.mu.Lock()
	g.cached = &id
	g.mu.Unlock()
	return id
}

// DetectIdentity asks STS who the gateway is, using the SDK's default chain
// (instance profile, IRSA, environment, shared profile). STS is global; the
// region only selects an endpoint, so a gateway without a configured region
// still gets an answer.
func DetectIdentity(ctx context.Context) (Identity, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithEC2IMDSRegion())
	if err != nil {
		return Identity{}, fmt.Errorf("cloud: aws config: %s", clipProviderError(err.Error()))
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return Identity{}, fmt.Errorf("cloud: no AWS identity: %s", clipProviderError(err.Error()))
	}
	raw := aws.ToString(out.Arn)
	return Identity{Principal: RolePrincipal(raw), RawARN: raw, AccountID: aws.ToString(out.Account), Source: SourceDetected}, nil
}

// RolePrincipal converts the ARN STS reports for a session into the ARN a
// trust policy must name: arn:aws:sts::ACCT:assumed-role/ROLE/session becomes
// arn:aws:iam::ACCT:role/ROLE. Any other ARN (an IAM user, a role) is
// returned unchanged. An instance profile is not a valid principal, and STS
// never reports one, so it cannot come out of here.
func RolePrincipal(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[2] != "sts" || !strings.HasPrefix(parts[5], "assumed-role/") {
		return arn
	}
	seg := strings.Split(strings.TrimPrefix(parts[5], "assumed-role/"), "/")
	if seg[0] == "" {
		return arn
	}
	return "arn:" + parts[1] + ":iam::" + parts[4] + ":role/" + seg[0]
}
