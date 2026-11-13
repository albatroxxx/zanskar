// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// An EKS cluster is reached through a role (ADR 0045, 8). The gateway's own
// AWS identity assumes the role named by the kube_eks credential, as it
// assumes an autoscaling group's (ADR 0023), and the cluster accepts a
// token that is a presigned STS GetCallerIdentity request carrying the
// cluster's name in a signed header: the shape aws-iam-authenticator
// defined and the cluster's authenticator verifies. Nothing of the
// person's goes into it; the person is impersonated through it as through
// a service account's token.

// EKSAccess names the cluster and the role that reaches it.
type EKSAccess struct {
	AWSAccess
	// Cluster is the cluster's name in the region, which the token names.
	Cluster string
}

// EKSCluster is what the cluster says about itself, for enrolment: the
// endpoint and the CA the target takes, and how it maps IAM principals.
type EKSCluster struct {
	Name     string `json:"name"`
	ARN      string `json:"arn"`
	Endpoint string `json:"endpoint"`
	// CAPEM is the cluster's certificate authority, decoded from the base64
	// DescribeCluster carries it in.
	CAPEM   string `json:"ca_pem"`
	Version string `json:"version"`
	Status  string `json:"status"`
	// AuthenticationMode is API, API_AND_CONFIG_MAP or CONFIG_MAP: the first
	// two take an access entry for Zanskar's role, the last the aws-auth
	// ConfigMap.
	AuthenticationMode string `json:"authentication_mode"`
}

// EKSCheck is the result of an access test: which stage failed, if one did.
type EKSCheck struct {
	OK bool `json:"ok"`
	// Stage that failed: assume (trust policy or ExternalId), describe
	// (permissions policy, or no such cluster in that region); "" when OK.
	Stage      string      `json:"stage,omitempty"`
	Error      string      `json:"error,omitempty"`
	AssumedARN string      `json:"assumed_arn,omitempty"`
	Cluster    *EKSCluster `json:"cluster,omitempty"`
}

// ErrClusterNotFound is a region with no cluster of that name.
var ErrClusterNotFound = errors.New("cloud: no EKS cluster of that name in the region")

// The token's shape (aws-iam-authenticator, pkg/token): the cluster goes in a
// signed header; the presign asks for 60 s, which STS ignores and the
// cluster's authenticator caps; the cluster accepts the token for 15 min from
// signing. It is used for twelve of them here, since the gateway's clock and
// AWS's need not agree to the minute.
const (
	eksClusterHeader  = "x-k8s-aws-id"
	eksTokenPrefix    = "k8s-aws-v1." // #nosec G101 -- the token format's public prefix, not a credential
	eksPresignExpires = "60"
	eksTokenAccepted  = 15 * time.Minute
	eksTokenMargin    = 3 * time.Minute
)

type (
	eksAPI interface {
		DescribeCluster(context.Context, *eks.DescribeClusterInput, ...func(*eks.Options)) (*eks.DescribeClusterOutput, error)
		ListClusters(context.Context, *eks.ListClustersInput, ...func(*eks.Options)) (*eks.ListClustersOutput, error)
	}
	stsPresigner interface {
		PresignGetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.PresignOptions)) (*v4.PresignedHTTPRequest, error)
	}
)

// EKS reaches one cluster's control plane as the role and mints its tokens.
type EKS struct {
	cluster string
	eks     eksAPI
	sts     stsAPI
	presign stsPresigner
	now     func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time // when the cached token is no longer handed out
}

// NewEKS builds the client for the cluster, assuming the role lazily.
func NewEKS(ctx context.Context, a EKSAccess) (*EKS, error) {
	if strings.TrimSpace(a.Cluster) == "" {
		return nil, errors.New("cloud: the cluster's name is required")
	}
	cfg, err := assumedConfig(ctx, a.AWSAccess)
	if err != nil {
		return nil, err
	}
	return newEKS(cfg, a.Cluster), nil
}

// newEKS wires the clients over cfg, whatever its credentials: tests give
// static ones and never reach AWS.
func newEKS(cfg aws.Config, cluster string) *EKS {
	stsc := sts.NewFromConfig(cfg)
	return &EKS{cluster: cluster, eks: eks.NewFromConfig(cfg), sts: stsc, presign: sts.NewPresignClient(stsc), now: time.Now}
}

// Token is a bearer the cluster accepts for the role: the cached one while
// it has time left, else one minted now. Minting is a local signature; it
// reaches AWS only when the role's temporary credentials must be renewed.
func (e *EKS) Token(ctx context.Context) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	if e.token != "" && now.Before(e.expires) {
		return e.token, nil
	}
	req, err := e.presign.PresignGetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}, func(po *sts.PresignOptions) {
		po.ClientOptions = append(po.ClientOptions, func(o *sts.Options) {
			o.APIOptions = append(o.APIOptions,
				smithyhttp.SetHeaderValue(eksClusterHeader, e.cluster),
				smithyhttp.SetHeaderValue("X-Amz-Expires", eksPresignExpires))
		})
	})
	if err != nil {
		return "", fmt.Errorf("cloud: eks token: %w", err)
	}
	e.token = eksTokenPrefix + base64.RawURLEncoding.EncodeToString([]byte(req.URL))
	e.expires = now.Add(eksTokenAccepted - eksTokenMargin)
	return e.token, nil
}

// Describe asks the control plane about the cluster.
func (e *EKS) Describe(ctx context.Context) (*EKSCluster, error) {
	out, err := e.eks.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: aws.String(e.cluster)})
	if err != nil {
		var api smithy.APIError
		if errors.As(err, &api) && api.ErrorCode() == "ResourceNotFoundException" {
			return nil, ErrClusterNotFound
		}
		return nil, wrapAWS(err)
	}
	c := out.Cluster
	if c == nil {
		return nil, ErrClusterNotFound
	}
	d := &EKSCluster{Name: aws.ToString(c.Name), ARN: aws.ToString(c.Arn), Endpoint: aws.ToString(c.Endpoint),
		Version: aws.ToString(c.Version), Status: string(c.Status)}
	if c.CertificateAuthority != nil && c.CertificateAuthority.Data != nil {
		pem, err := base64.StdEncoding.DecodeString(*c.CertificateAuthority.Data)
		if err != nil {
			return nil, fmt.Errorf("cloud: the cluster's certificate authority is not base64: %w", err)
		}
		d.CAPEM = string(pem)
	}
	if c.AccessConfig != nil {
		d.AuthenticationMode = string(c.AccessConfig.AuthenticationMode)
	}
	return d, nil
}

// ListClusters names the region's clusters, for guided enrolment.
func (e *EKS) ListClusters(ctx context.Context) ([]string, error) {
	var out []string
	in := &eks.ListClustersInput{}
	for {
		page, err := e.eks.ListClusters(ctx, in)
		if err != nil {
			return nil, wrapAWS(err)
		}
		out = append(out, page.Clusters...)
		if page.NextToken == nil || *page.NextToken == "" {
			return out, nil
		}
		in.NextToken = page.NextToken
	}
}

// Check is the access test (ADR 0023's, for a cluster): the role is assumed
// (GetCallerIdentity forces it), then the cluster described. Each failure
// names its stage, since the administrator's first failure is always the
// trust policy and a bare error does not say so.
func (e *EKS) Check(ctx context.Context) *EKSCheck {
	id, err := e.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return &EKSCheck{Stage: "assume", Error: clipProviderError(err.Error())}
	}
	out := &EKSCheck{AssumedARN: aws.ToString(id.Arn)}
	c, err := e.Describe(ctx)
	if err != nil {
		out.Stage, out.Error = "describe", clipProviderError(err.Error())
		return out
	}
	out.OK, out.Cluster = true, c
	return out
}

// EKSUsername is the Kubernetes user the cluster maps Zanskar's role to
// (the access entry's --username), which the printed RBAC binds.
const EKSUsername = "zanskar"

// EKSTrustPolicy is the role's trust policy for the gateway principal, or
// "" while the principal is unknown: a policy with a placeholder looks
// finished and is not (ADR 0023).
func EKSTrustPolicy(gatewayPrincipal, externalID string) string {
	if gatewayPrincipal == "" {
		return ""
	}
	return RenderPolicy(map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{{
			"Effect":    "Allow",
			"Principal": map[string]any{"AWS": gatewayPrincipal},
			"Action":    "sts:AssumeRole",
			"Condition": map[string]any{"StringEquals": map[string]any{"sts:ExternalId": externalID}},
		}},
	})
}

// EKSPermissionsPolicy is the least the role needs from AWS: to describe
// the one cluster and to list the region's. What it may do inside the
// cluster is the access entry's and the RBAC's to say, not IAM's.
func EKSPermissionsPolicy(region, cluster string) string {
	return RenderPolicy(map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{
			{"Sid": "ZanskarDescribe", "Effect": "Allow", "Action": "eks:DescribeCluster",
				"Resource": "arn:" + Partition(region) + ":eks:" + region + ":*:cluster/" + cluster},
			{"Sid": "ZanskarList", "Effect": "Allow", "Action": "eks:ListClusters", "Resource": "*"},
		},
	})
}

// EKSAccessEntry is the step that maps the role to the user the RBAC
// binds, for a cluster whose authentication mode includes API.
func EKSAccessEntry(region, cluster, roleARN string) string {
	return "aws eks create-access-entry --region " + region + " --cluster-name " + cluster +
		" --principal-arn " + roleARN + " --type STANDARD --username " + EKSUsername
}

// EKSAwsAuth is the same mapping for a cluster still on the aws-auth
// ConfigMap (authentication mode CONFIG_MAP): an entry under mapRoles.
func EKSAwsAuth(roleARN string) string {
	return "- rolearn: " + roleARN + "\n  username: " + EKSUsername
}

// Partition is the AWS partition a region belongs to, which every ARN in it
// names: GovCloud and China are their own.
func Partition(region string) string {
	switch {
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov"
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn"
	}
	return "aws"
}
