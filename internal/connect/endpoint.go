// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/albatroxxx/zanskar/internal/asg"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/ticket"
)

// endpoint is a resolved connection target: a static target or one instance
// of an autoscaling group. Handlers work against this so the two kinds share
// the same policy, pinning and session code.
type endpoint struct {
	Name                string
	Address             string
	Ports               map[target.Protocol]int
	Tags                map[string]string
	Credentials         map[target.Protocol]string
	HostKeyFingerprint  string
	HostKeyTrusted      bool
	TLSFingerprint      string // RDP listener
	WinRMTLSFingerprint string
	Active              bool

	// Exactly one of TargetID or (ASGID, ASGInstanceID) is set.
	TargetID      string
	ASGID         string
	ASGInstanceID string
	// LiveKey is what the registry indexes live sessions by: the target id
	// or the instance id, so the sync loop can end sessions on a lost instance.
	LiveKey string
	// Cloud identity, for EC2 Instance Connect.
	CloudInstanceID  string
	AvailabilityZone string
	Group            *asg.Group
	Label            string // "i-0abc · ap-south-1a" for instances
}

// errNoHealthyInstances surfaces to the API as no_healthy_instances.
var errNoHealthyInstances = errors.New("no healthy instances")

func (e *endpoint) port(p target.Protocol) int {
	if n, ok := e.Ports[p]; ok && n > 0 {
		return n
	}
	return target.DefaultPorts[p]
}

func (e *endpoint) policyRef() (id, asgID string, tags map[string]string) {
	return e.TargetID, e.ASGID, e.Tags
}

func fromTarget(t *target.Target) *endpoint {
	e := &endpoint{Name: t.Name, Address: t.Address, Ports: t.Ports, Tags: t.Tags, Credentials: t.Credentials,
		HostKeyTrusted: t.HostKeyStatus == target.HostKeyTrusted, Active: t.Status == "active", TargetID: t.ID, LiveKey: t.ID}
	if t.HostKeyFingerprint != nil {
		e.HostKeyFingerprint = *t.HostKeyFingerprint
	}
	if t.TLSFingerprint != nil {
		e.TLSFingerprint = *t.TLSFingerprint
	}
	if t.WinRMTLSFingerprint != nil {
		e.WinRMTLSFingerprint = *t.WinRMTLSFingerprint
	}
	return e
}

func fromInstance(g *asg.Group, in *asg.Instance) *endpoint {
	return &endpoint{
		Name: g.Name, Address: g.Address(in), Ports: g.Ports, Tags: g.Tags, Credentials: g.Credentials,
		HostKeyFingerprint: in.HostKeyFingerprint, HostKeyTrusted: in.HostKeyFingerprint != "",
		Active: g.Status == "active" && in.Healthy,
		ASGID:  g.ID, ASGInstanceID: in.ID, LiveKey: in.ID,
		CloudInstanceID: in.InstanceID, AvailabilityZone: in.AvailabilityZone, Group: g,
		Label: in.InstanceID + " · " + in.AvailabilityZone,
	}
}

// resolveTarget loads a static target.
func (h *Handler) resolveTarget(ctx context.Context, id string) (*endpoint, error) {
	t, err := h.Targets.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return fromTarget(t), nil
}

// resolveInstance loads one autoscaling instance and its group.
func (h *Handler) resolveInstance(ctx context.Context, instanceID string) (*endpoint, error) {
	if h.ASGs == nil {
		return nil, asg.ErrNotFound
	}
	in, err := h.ASGs.GetInstance(ctx, instanceID)
	if err != nil {
		return nil, err
	}
	g, err := h.ASGs.Get(ctx, in.GroupID)
	if err != nil {
		return nil, err
	}
	return fromInstance(g, in), nil
}

// pickInstance chooses the newest healthy instance of a group.
func (h *Handler) pickInstance(ctx context.Context, groupID string) (*endpoint, error) {
	if h.ASGs == nil {
		return nil, asg.ErrNotFound
	}
	g, err := h.ASGs.Get(ctx, groupID)
	if err != nil {
		return nil, err
	}
	healthy, err := h.ASGs.Instances(ctx, g.ID, true)
	if err != nil {
		return nil, err
	}
	if len(healthy) == 0 {
		return nil, errNoHealthyInstances
	}
	return fromInstance(g, healthy[0]), nil
}

// resolveGrant re-resolves the endpoint a ticket was issued for, so a change
// between issue and redeem (instance retired, target disabled) is caught.
func (h *Handler) resolveGrant(ctx context.Context, g *ticket.Grant) (*endpoint, error) {
	if g.ASGInstanceID != "" {
		return h.resolveInstance(ctx, g.ASGInstanceID)
	}
	return h.resolveTarget(ctx, g.TargetID)
}

// ephemeralSSHKey returns a fresh ed25519 keypair for EC2 Instance Connect:
// the public half in authorized_keys form, the private half as OpenSSH PEM.
func ephemeralSSHKey() (pubLine string, privPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "zanskar instance connect")
	if err != nil {
		return "", nil, err
	}
	return string(ssh.MarshalAuthorizedKey(sshPub)), pem.EncodeToMemory(block), nil
}

func sessionLabel(e *endpoint) string {
	if e.Label != "" {
		return fmt.Sprintf("%s (%s)", e.Name, e.Label)
	}
	return e.Name
}
