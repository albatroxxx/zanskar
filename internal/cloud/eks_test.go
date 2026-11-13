// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// staticEKS is a client over static credentials: presigning is a local
// signature, so no test here reaches AWS.
func staticEKS(cluster string) *EKS {
	cfg := aws.Config{Region: "eu-west-2", Credentials: credentials.NewStaticCredentialsProvider("AKIATEST", "secret", "")}
	return newEKS(cfg, cluster)
}

// The token is what aws-iam-authenticator defined (2026-11-13, F1-D): the
// prefix, an unpadded URL-safe base64 of a presigned GetCallerIdentity at
// the regional STS endpoint, with the cluster's name in a signed header and
// X-Amz-Expires=60.
func TestEKSTokenShape(t *testing.T) {
	e := staticEKS("prod")
	tok, err := e.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, "k8s-aws-v1.") || strings.ContainsAny(tok, "=+/") {
		t.Fatalf("token: %q", tok)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(tok, "k8s-aws-v1."))
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme != "https" || u.Host != "sts.eu-west-2.amazonaws.com" || q.Get("Action") != "GetCallerIdentity" || q.Get("Version") != "2011-06-15" {
		t.Fatalf("presigned url: %s", raw)
	}
	if q.Get("X-Amz-Expires") != "60" || !strings.Contains(q.Get("X-Amz-SignedHeaders"), "x-k8s-aws-id") || q.Get("X-Amz-Signature") == "" {
		t.Fatalf("presign parameters: %v", q)
	}
	if q.Get("X-Amz-Credential") == "" || !strings.HasPrefix(q.Get("X-Amz-Credential"), "AKIATEST/") {
		t.Fatalf("credential: %v", q.Get("X-Amz-Credential"))
	}
}

// countingPresigner counts the signatures made; the signature itself is
// dated by the real clock, so two made in one second read the same.
type countingPresigner struct {
	stsPresigner
	n int
}

func (c *countingPresigner) PresignGetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput, fns ...func(*sts.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
	c.n++
	return c.stsPresigner.PresignGetCallerIdentity(ctx, in, fns...)
}

// The token is reused while the cluster will still accept it, with a margin
// for clocks that disagree, and minted anew after.
func TestEKSTokenCached(t *testing.T) {
	e := staticEKS("prod")
	cp := &countingPresigner{stsPresigner: e.presign}
	e.presign = cp
	now := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	e.now = func() time.Time { return now }
	first, _ := e.Token(context.Background())
	now = now.Add(11 * time.Minute)
	again, _ := e.Token(context.Background())
	if again != first || cp.n != 1 {
		t.Fatalf("a token with time left was minted anew (%d signatures)", cp.n)
	}
	now = now.Add(2 * time.Minute) // 13 min: past the 12 the token is handed out for
	if _, err := e.Token(context.Background()); err != nil || cp.n != 2 {
		t.Fatalf("a token near the end of its life was handed out (%d signatures, %v)", cp.n, err)
	}
}

type fakeEKSAPI struct {
	cluster *ekstypes.Cluster
	err     error
	pages   [][]string
	calls   int
}

func (f *fakeEKSAPI) DescribeCluster(_ context.Context, in *eks.DescribeClusterInput, _ ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.cluster == nil || aws.ToString(in.Name) != aws.ToString(f.cluster.Name) {
		return nil, &smithy.GenericAPIError{Code: "ResourceNotFoundException", Message: "No cluster found for name: " + aws.ToString(in.Name)}
	}
	return &eks.DescribeClusterOutput{Cluster: f.cluster}, nil
}

func (f *fakeEKSAPI) ListClusters(_ context.Context, in *eks.ListClustersInput, _ ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
	i := f.calls
	f.calls++
	out := &eks.ListClustersOutput{Clusters: f.pages[i]}
	if i+1 < len(f.pages) {
		out.NextToken = aws.String("p")
	}
	if in.NextToken == nil && i > 0 {
		return nil, errors.New("page asked without the token")
	}
	return out, nil
}

type fakeSTS struct{ err error }

func (f fakeSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &sts.GetCallerIdentityOutput{Arn: aws.String("arn:aws:sts::123456789012:assumed-role/zanskar-eks/zanskar-gateway")}, nil
}

func prodCluster() *ekstypes.Cluster {
	ca := base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"))
	return &ekstypes.Cluster{Name: aws.String("prod"), Arn: aws.String("arn:aws:eks:eu-west-2:123456789012:cluster/prod"),
		Endpoint: aws.String("https://ABC.gr7.eu-west-2.eks.amazonaws.com"), Version: aws.String("1.31"), Status: ekstypes.ClusterStatusActive,
		CertificateAuthority: &ekstypes.Certificate{Data: aws.String(ca)},
		AccessConfig:         &ekstypes.AccessConfigResponse{AuthenticationMode: ekstypes.AuthenticationModeApiAndConfigMap}}
}

// Describe decodes the CA and says how the cluster maps principals; the
// check names the stage that failed.
func TestEKSDescribeAndCheck(t *testing.T) {
	e := &EKS{cluster: "prod", eks: &fakeEKSAPI{cluster: prodCluster()}, sts: fakeSTS{}}
	c, err := e.Describe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c.Endpoint != "https://ABC.gr7.eu-west-2.eks.amazonaws.com" || !strings.HasPrefix(c.CAPEM, "-----BEGIN CERTIFICATE-----") || c.AuthenticationMode != "API_AND_CONFIG_MAP" || c.Status != "ACTIVE" {
		t.Fatalf("described: %+v", c)
	}
	chk := e.Check(context.Background())
	if !chk.OK || chk.Stage != "" || chk.Cluster == nil || !strings.Contains(chk.AssumedARN, "zanskar-eks") {
		t.Fatalf("check: %+v", chk)
	}
	// The trust policy wrong: the role is never assumed.
	e.sts = fakeSTS{err: errors.New("AccessDenied: User is not authorized to perform: sts:AssumeRole")}
	if chk := e.Check(context.Background()); chk.OK || chk.Stage != "assume" || !strings.Contains(chk.Error, "AssumeRole") {
		t.Fatalf("assume stage: %+v", chk)
	}
	// The role assumed, the cluster missing or the permissions policy short.
	e.sts = fakeSTS{}
	e.eks = &fakeEKSAPI{}
	if chk := e.Check(context.Background()); chk.OK || chk.Stage != "describe" || !strings.Contains(chk.Error, "no EKS cluster") {
		t.Fatalf("describe stage: %+v", chk)
	}
	e.eks = &fakeEKSAPI{err: &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized to perform: eks:DescribeCluster"}}
	if chk := e.Check(context.Background()); chk.OK || chk.Stage != "describe" || !errors.Is(wrapAWS(&smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized"}), ErrAccessDenied) {
		t.Fatalf("denied stage: %+v", chk)
	}
}

func TestEKSListClustersPages(t *testing.T) {
	e := &EKS{cluster: "prod", eks: &fakeEKSAPI{pages: [][]string{{"a", "b"}, {"c"}}}}
	got, err := e.ListClusters(context.Background())
	if err != nil || strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("%v %v", got, err)
	}
}

// The documents the administrator pastes: the trust policy only once the
// gateway's principal is known, the permissions on the one cluster, and the
// mapping step in both of the cluster's forms.
func TestEKSDocuments(t *testing.T) {
	if EKSTrustPolicy("", "zanskar-0") != "" {
		t.Fatal("a trust policy with no principal")
	}
	tp := EKSTrustPolicy("arn:aws:iam::111111111111:role/gw", "zanskar-00000000000000000000000000000000")
	if !strings.Contains(tp, `"sts:ExternalId": "zanskar-0000`) || !strings.Contains(tp, `"AWS": "arn:aws:iam::111111111111:role/gw"`) {
		t.Fatalf("trust policy:\n%s", tp)
	}
	pp := EKSPermissionsPolicy("us-gov-west-1", "prod")
	if !strings.Contains(pp, `"arn:aws-us-gov:eks:us-gov-west-1:*:cluster/prod"`) || !strings.Contains(pp, "eks:ListClusters") {
		t.Fatalf("permissions policy:\n%s", pp)
	}
	ae := EKSAccessEntry("eu-west-2", "prod", "arn:aws:iam::123456789012:role/zanskar-eks")
	if !strings.Contains(ae, "--cluster-name prod") || !strings.HasSuffix(ae, "--username zanskar") {
		t.Fatalf("access entry: %s", ae)
	}
	if aa := EKSAwsAuth("arn:aws:iam::123456789012:role/zanskar-eks"); !strings.Contains(aa, "username: zanskar") {
		t.Fatalf("aws-auth: %s", aa)
	}
	for s, ok := range map[string]bool{"eu-west-2": true, "us-gov-west-1": true, "ap-southeast-1": true, "EU-WEST-2": false, "eu-west": false, "eu west 2": false} {
		if ValidRegion(s) != ok {
			t.Fatalf("region %q: %v", s, !ok)
		}
	}
}
