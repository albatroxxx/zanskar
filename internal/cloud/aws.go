// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2instanceconnect"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// AWSAccess names the cross-account role Zanskar assumes for one group.
// The gateway's own credentials (instance profile, environment, or a
// mounted profile) are the base identity; the role is assumed with the
// ExternalId the admin generated in Zanskar, which defeats the confused
// deputy problem.
type AWSAccess struct {
	Region     string
	RoleARN    string
	ExternalID string
}

// The SDK clients are used through these narrow interfaces so the mapping
// logic can be tested with fakes and no network.
type (
	asgAPI interface {
		DescribeAutoScalingGroups(context.Context, *autoscaling.DescribeAutoScalingGroupsInput, ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error)
	}
	ec2API interface {
		DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
		GetConsoleOutput(context.Context, *ec2.GetConsoleOutputInput, ...func(*ec2.Options)) (*ec2.GetConsoleOutputOutput, error)
	}
	elbAPI interface {
		DescribeTargetHealth(context.Context, *elbv2.DescribeTargetHealthInput, ...func(*elbv2.Options)) (*elbv2.DescribeTargetHealthOutput, error)
	}
	eicAPI interface {
		SendSSHPublicKey(context.Context, *ec2instanceconnect.SendSSHPublicKeyInput, ...func(*ec2instanceconnect.Options)) (*ec2instanceconnect.SendSSHPublicKeyOutput, error)
	}
)

// AWS implements Provider.
type AWS struct {
	asg asgAPI
	ec2 ec2API
	elb elbAPI
	eic eicAPI
}

// NewAWS builds a provider that assumes the role lazily and caches the
// temporary credentials until they expire.
func NewAWS(ctx context.Context, a AWSAccess) (*AWS, error) {
	if a.Region == "" || a.RoleARN == "" || a.ExternalID == "" {
		return nil, errors.New("cloud: region, role arn and external id are required")
	}
	base, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(a.Region))
	if err != nil {
		return nil, fmt.Errorf("cloud: aws base config: %w", err)
	}
	provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(base), a.RoleARN, func(o *stscreds.AssumeRoleOptions) {
		o.ExternalID = aws.String(a.ExternalID)
		o.RoleSessionName = "zanskar-gateway"
		o.Duration = 15 * time.Minute
	})
	cfg := base.Copy()
	cfg.Credentials = aws.NewCredentialsCache(provider)
	return &AWS{
		asg: autoscaling.NewFromConfig(cfg),
		ec2: ec2.NewFromConfig(cfg),
		elb: elbv2.NewFromConfig(cfg),
		eic: ec2instanceconnect.NewFromConfig(cfg),
	}, nil
}

// DescribeGroup implements Provider.
func (p *AWS) DescribeGroup(ctx context.Context, groupName string) (*GroupSnapshot, error) {
	out, err := p.asg.DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{AutoScalingGroupNames: []string{groupName}})
	if err != nil {
		return nil, wrapAWS(err)
	}
	if len(out.AutoScalingGroups) == 0 {
		return nil, ErrGroupNotFound
	}
	g := out.AutoScalingGroups[0]
	snap := &GroupSnapshot{Name: groupName, TargetGroupARNs: g.TargetGroupARNs}
	if g.DesiredCapacity != nil {
		snap.DesiredCapacity = int(*g.DesiredCapacity)
	}
	byID := map[string]*Instance{}
	var ids []string
	for _, in := range g.Instances {
		if in.InstanceId == nil {
			continue
		}
		inst := Instance{ID: *in.InstanceId, LifecycleState: string(in.LifecycleState), AvailabilityZone: aws.ToString(in.AvailabilityZone)}
		byID[inst.ID] = &inst
		ids = append(ids, inst.ID)
	}
	if len(ids) > 0 {
		desc, err := p.ec2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: ids})
		if err != nil {
			return nil, wrapAWS(err)
		}
		for _, r := range desc.Reservations {
			for _, in := range r.Instances {
				inst, ok := byID[aws.ToString(in.InstanceId)]
				if !ok {
					continue
				}
				inst.PrivateIP = aws.ToString(in.PrivateIpAddress)
				inst.PublicIP = aws.ToString(in.PublicIpAddress)
				if in.LaunchTime != nil {
					inst.LaunchedAt = *in.LaunchTime
				}
				if in.Placement != nil && inst.AvailabilityZone == "" {
					inst.AvailabilityZone = aws.ToString(in.Placement.AvailabilityZone)
				}
			}
		}
	}
	for _, arn := range g.TargetGroupARNs {
		th, err := p.elb.DescribeTargetHealth(ctx, &elbv2.DescribeTargetHealthInput{TargetGroupArn: aws.String(arn)})
		if err != nil {
			return nil, wrapAWS(err)
		}
		for _, d := range th.TargetHealthDescriptions {
			if d.Target == nil || d.TargetHealth == nil {
				continue
			}
			if inst, ok := byID[aws.ToString(d.Target.Id)]; ok {
				state := strings.ToLower(string(d.TargetHealth.State))
				// An instance that is unhealthy in any target group is unhealthy.
				if inst.LBHealth == "" || state != "healthy" {
					inst.LBHealth = state
				}
			}
		}
	}
	for _, id := range ids {
		snap.Instances = append(snap.Instances, *byID[id])
	}
	return snap, nil
}

// ConsoleHostKeys implements Provider.
func (p *AWS) ConsoleHostKeys(ctx context.Context, instanceID string) ([]string, error) {
	out, err := p.ec2.GetConsoleOutput(ctx, &ec2.GetConsoleOutputInput{InstanceId: aws.String(instanceID), Latest: aws.Bool(true)})
	if err != nil {
		return nil, wrapAWS(err)
	}
	if out.Output == nil {
		return nil, ErrNoConsoleKeys
	}
	raw, err := base64.StdEncoding.DecodeString(*out.Output)
	if err != nil {
		return nil, fmt.Errorf("cloud: console output: %w", err)
	}
	fps := ParseConsoleHostKeys(string(raw))
	if len(fps) == 0 {
		return nil, ErrNoConsoleKeys
	}
	return fps, nil
}

// SendSSHPublicKey implements Provider.
func (p *AWS) SendSSHPublicKey(ctx context.Context, instanceID, az, osUser string, publicKey []byte) error {
	_, err := p.eic.SendSSHPublicKey(ctx, &ec2instanceconnect.SendSSHPublicKeyInput{
		InstanceId:       aws.String(instanceID),
		InstanceOSUser:   aws.String(osUser),
		SSHPublicKey:     aws.String(strings.TrimSpace(string(publicKey))),
		AvailabilityZone: aws.String(az),
	})
	return wrapAWS(err)
}

func wrapAWS(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "AccessDenied") || strings.Contains(msg, "UnauthorizedOperation") || strings.Contains(msg, "not authorized") {
		return fmt.Errorf("%w: %s", ErrAccessDenied, redactARNs(msg))
	}
	return err
}

// redactARNs keeps error text useful without echoing full principal ARNs.
func redactARNs(s string) string {
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}
