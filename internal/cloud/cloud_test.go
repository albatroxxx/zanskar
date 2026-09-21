// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	astypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2instanceconnect"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

func TestParseConsoleHostKeys(t *testing.T) {
	console := `Amazon Linux 2023
ec2: #############################################################
ec2: -----BEGIN SSH HOST KEY FINGERPRINTS-----
ec2: 256 SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefg root@ip (ED25519)
ec2: 3072 SHA256:ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210zyxwvut root@ip (RSA)
ec2: -----END SSH HOST KEY FINGERPRINTS-----
login: SHA256:PLANTEDPLANTEDPLANTEDPLANTEDPLANTEDPLANTED0 not in block`
	fps := ParseConsoleHostKeys(console)
	if len(fps) != 2 || fps[0] != "SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefg" {
		t.Fatalf("got %v", fps)
	}
	if ParseConsoleHostKeys("no markers SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefg") != nil {
		t.Fatal("fingerprints outside the block must be ignored")
	}
}

func TestHealthyRule(t *testing.T) {
	cases := []struct {
		in   Instance
		want bool
	}{
		{Instance{LifecycleState: "InService"}, true},
		{Instance{LifecycleState: "InService", LBHealth: "healthy"}, true},
		{Instance{LifecycleState: "InService", LBHealth: "unhealthy"}, false},
		{Instance{LifecycleState: "InService", LBHealth: "draining"}, false},
		{Instance{LifecycleState: "Terminating", LBHealth: "healthy"}, false},
		{Instance{LifecycleState: "Pending"}, false},
	}
	for i, c := range cases {
		if got := Healthy(c.in); got != c.want {
			t.Errorf("case %d: got %v want %v", i, got, c.want)
		}
	}
}

type fakeASG struct {
	out *autoscaling.DescribeAutoScalingGroupsOutput
}

func (f fakeASG) DescribeAutoScalingGroups(context.Context, *autoscaling.DescribeAutoScalingGroupsInput, ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error) {
	return f.out, nil
}

type fakeEC2 struct {
	desc    *ec2.DescribeInstancesOutput
	console string
}

func (f fakeEC2) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return f.desc, nil
}
func (f fakeEC2) GetConsoleOutput(context.Context, *ec2.GetConsoleOutputInput, ...func(*ec2.Options)) (*ec2.GetConsoleOutputOutput, error) {
	enc := base64.StdEncoding.EncodeToString([]byte(f.console))
	return &ec2.GetConsoleOutputOutput{Output: &enc}, nil
}

type fakeELB struct {
	out *elbv2.DescribeTargetHealthOutput
}

func (f fakeELB) DescribeTargetHealth(context.Context, *elbv2.DescribeTargetHealthInput, ...func(*elbv2.Options)) (*elbv2.DescribeTargetHealthOutput, error) {
	return f.out, nil
}

type fakeEIC struct{ calls int }

func (f *fakeEIC) SendSSHPublicKey(context.Context, *ec2instanceconnect.SendSSHPublicKeyInput, ...func(*ec2instanceconnect.Options)) (*ec2instanceconnect.SendSSHPublicKeyOutput, error) {
	f.calls++
	return &ec2instanceconnect.SendSSHPublicKeyOutput{Success: true}, nil
}

func TestAWSDescribeGroupMerges(t *testing.T) {
	p := &AWS{
		asg: fakeASG{out: &autoscaling.DescribeAutoScalingGroupsOutput{AutoScalingGroups: []astypes.AutoScalingGroup{{
			DesiredCapacity: aws.Int32(2),
			TargetGroupARNs: []string{"arn:tg"},
			Instances: []astypes.Instance{
				{InstanceId: aws.String("i-1"), LifecycleState: astypes.LifecycleStateInService, AvailabilityZone: aws.String("ap-south-1a")},
				{InstanceId: aws.String("i-2"), LifecycleState: astypes.LifecycleStateTerminating, AvailabilityZone: aws.String("ap-south-1b")},
			},
		}}}},
		ec2: fakeEC2{desc: &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{
			{InstanceId: aws.String("i-1"), PrivateIpAddress: aws.String("10.0.1.5"), PublicIpAddress: aws.String("3.3.3.3")},
			{InstanceId: aws.String("i-2"), PrivateIpAddress: aws.String("10.0.2.5")},
		}}}}, console: "-----BEGIN SSH HOST KEY FINGERPRINTS-----\n256 SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefg (ED25519)\n-----END SSH HOST KEY FINGERPRINTS-----"},
		elb: fakeELB{out: &elbv2.DescribeTargetHealthOutput{TargetHealthDescriptions: []elbtypes.TargetHealthDescription{
			{Target: &elbtypes.TargetDescription{Id: aws.String("i-1")}, TargetHealth: &elbtypes.TargetHealth{State: elbtypes.TargetHealthStateEnumHealthy}},
			{Target: &elbtypes.TargetDescription{Id: aws.String("i-2")}, TargetHealth: &elbtypes.TargetHealth{State: elbtypes.TargetHealthStateEnumDraining}},
		}}},
		eic: &fakeEIC{},
	}
	snap, err := p.DescribeGroup(context.Background(), "web")
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Instances) != 2 || snap.DesiredCapacity != 2 {
		t.Fatalf("snapshot: %+v", snap)
	}
	i1, i2 := snap.Instances[0], snap.Instances[1]
	if i1.PrivateIP != "10.0.1.5" || i1.PublicIP != "3.3.3.3" || i1.LBHealth != "healthy" || !Healthy(i1) {
		t.Fatalf("i-1: %+v", i1)
	}
	if i2.LBHealth != "draining" || Healthy(i2) {
		t.Fatalf("i-2: %+v", i2)
	}
	fps, err := p.ConsoleHostKeys(context.Background(), "i-1")
	if err != nil || len(fps) != 1 {
		t.Fatalf("console keys: %v %v", fps, err)
	}
	if err := p.SendSSHPublicKey(context.Background(), "i-1", "ap-south-1a", "ec2-user", []byte("ssh-ed25519 AAAA")); err != nil {
		t.Fatal(err)
	}
	if p.eic.(*fakeEIC).calls != 1 {
		t.Fatal("expected one SendSSHPublicKey call")
	}
}
