// SPDX-License-Identifier: Apache-2.0

// Package cloud abstracts the cloud APIs Zanskar needs for autoscaling groups
// (ADR 0011): membership and lifecycle state, load balancer health, instance
// addresses, host key fingerprints published on the serial console, and
// EC2 Instance Connect. AWS is the first provider; the interface is what a
// GCP or Azure provider would implement later.
package cloud

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
)

// Instance is one member of a group as the cloud sees it.
type Instance struct {
	ID               string
	PrivateIP        string
	PublicIP         string
	AvailabilityZone string
	// LifecycleState is the group's view: InService, Pending, Terminating, ...
	LifecycleState string
	// LBHealth is the load balancer's view: healthy, unhealthy, draining,
	// initial, unused; empty when the group has no target group.
	LBHealth   string
	LaunchedAt time.Time
}

// GroupSnapshot is everything the sync loop needs from one poll.
type GroupSnapshot struct {
	Name            string
	Instances       []Instance
	TargetGroupARNs []string
	DesiredCapacity int
}

// Provider is implemented per cloud.
type Provider interface {
	// DescribeGroup returns the group's instances with lifecycle state,
	// addresses and (when the group is behind a load balancer) LB health.
	DescribeGroup(ctx context.Context, groupName string) (*GroupSnapshot, error)
	// ConsoleHostKeys returns the SSH host key fingerprints an instance
	// printed on its serial console at boot (cloud-init does this), in the
	// "SHA256:..." form, or ErrNoConsoleKeys when none were published.
	ConsoleHostKeys(ctx context.Context, instanceID string) ([]string, error)
	// SendSSHPublicKey pushes an ephemeral public key to an instance so the
	// gateway can log in with the matching private key for about a minute.
	SendSSHPublicKey(ctx context.Context, instanceID, availabilityZone, osUser string, publicKey []byte) error
}

// Errors.
var (
	ErrGroupNotFound = errors.New("cloud: autoscaling group not found")
	ErrNoConsoleKeys = errors.New("cloud: no host key fingerprints on the console")
	ErrNotSupported  = errors.New("cloud: operation not supported by this provider")
	ErrAccessDenied  = errors.New("cloud: access denied; check the role's permissions and ExternalId")
)

var fingerprintRe = regexp.MustCompile(`SHA256:[A-Za-z0-9+/=]{20,}`)

// ParseConsoleHostKeys extracts SHA256 host key fingerprints from serial
// console text. cloud-init prints them between
// "-----BEGIN SSH HOST KEY FINGERPRINTS-----" and the matching END marker;
// Amazon Linux prefixes each line with "ec2: ". Only that block is read so
// a fingerprint-looking string elsewhere in the log cannot be planted by a
// process on the instance after boot.
func ParseConsoleHostKeys(console string) []string {
	start := strings.Index(console, "BEGIN SSH HOST KEY FINGERPRINTS")
	if start < 0 {
		return nil
	}
	end := strings.Index(console[start:], "END SSH HOST KEY FINGERPRINTS")
	if end < 0 {
		return nil
	}
	block := console[start : start+end]
	seen := map[string]bool{}
	var out []string
	for _, fp := range fingerprintRe.FindAllString(block, -1) {
		if !seen[fp] {
			seen[fp] = true
			out = append(out, fp)
		}
	}
	return out
}

// Healthy applies the ADR 0011 rule to a cloud-side instance: the group must
// consider it InService, and the load balancer (if any) must not consider it
// unhealthy or draining. The gateway's own probe is applied by the caller.
func Healthy(in Instance) bool {
	if in.LifecycleState != "InService" {
		return false
	}
	switch strings.ToLower(in.LBHealth) {
	case "", "healthy":
		return true
	default:
		return false
	}
}
