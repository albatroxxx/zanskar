// SPDX-License-Identifier: Apache-2.0

package asg

import (
	"time"

	"github.com/albatroxxx/zanskar/internal/states"
	"github.com/albatroxxx/zanskar/internal/target"
)

// InstanceState is what holds of an autoscaling instance now (ADR 0047,
// ADR 0011): healthy, unhealthy, or terminated (no longer returned by the
// cloud, or marked so by the sync).
type InstanceState string

// Instance states.
const (
	InstanceHealthy    InstanceState = "healthy"
	InstanceUnhealthy  InstanceState = "unhealthy"
	InstanceTerminated InstanceState = "terminated"
)

// InstanceStateOf derives an instance's state from its derived health and
// its termination.
func InstanceStateOf(healthy bool, terminatedAt *time.Time) InstanceState {
	switch {
	case terminatedAt != nil:
		return InstanceTerminated
	case healthy:
		return InstanceHealthy
	}
	return InstanceUnhealthy
}

// InstanceLifecycle is the instance's declared lifecycle.
var InstanceLifecycle = states.New("autoscaling instance",
	[]string{string(InstanceHealthy), string(InstanceUnhealthy), string(InstanceTerminated)},
	states.Move{From: "healthy", To: "unhealthy", By: "a poll: the cloud, the load balancer or the probe says so, or a pinned key or certificate changed (asg.instance.unhealthy)"},
	states.Move{From: "unhealthy", To: "healthy", By: "a poll says so again (no event)"},
	states.Move{From: "healthy", To: "terminated", By: "the cloud no longer lists it (asg.instance.left)"},
	states.Move{From: "unhealthy", To: "terminated", By: "the cloud no longer lists it (asg.instance.left)"},
	states.Move{From: "terminated", To: "healthy", By: "the cloud lists it again (no event)"},
	states.Move{From: "terminated", To: "unhealthy", By: "the cloud lists it again (no event)"},
).Describe(states.Doc{
	Field:   "state",
	Schemas: []string{"AsgInstance"},
	Derivation: "`terminated` when `terminated_at` is set; else `healthy` when `healthy` holds (in service, load balancer healthy or absent, probe healthy); " +
		"else `unhealthy`. A first sighting lands in `healthy` or `unhealthy`.",
	Notes: []string{
		"Health has no time bound: a group that stops polling (disabled, or its sync failing) keeps each instance's last verdict.",
		"An instance whose pinned host key or certificate changed stays `unhealthy` while it presents the new one; no accept action exists.",
	},
})

// derive fills the computed fields from the stored ones (ADR 0047).
func (in *Instance) derive() {
	in.Healthy = derive(in)
	in.State = InstanceStateOf(in.Healthy, in.TerminatedAt)
}

// stateOf is the group's state: the target lifecycle's words (a group is
// active, disabled, or retired and never returned).
func stateOf(g *Group) target.State { return target.StateOf(g.Status, false) }
