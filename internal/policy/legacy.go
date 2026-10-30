// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"slices"
	"time"
)

// The policy model before ADR 0036, frozen. The data step converts stored
// policies from it, and the migration tests check the conversion against
// its evaluator. Nothing else reads it; it goes with the step once every
// supported upgrade path has run it.

// legacySelector named the targets a policy covered: a target matched when
// its id was listed, its group's id was listed, or every tag was present on
// it with the same value.
type legacySelector struct {
	Targets []string          `json:"targets,omitempty"`
	ASGs    []string          `json:"asgs,omitempty"`
	Tags    map[string]string `json:"tags,omitempty"`
}

func (s legacySelector) empty() bool {
	return len(s.Targets) == 0 && len(s.ASGs) == 0 && len(s.Tags) == 0
}

func (s legacySelector) matches(t TargetRef) bool {
	if t.ID != "" && slices.Contains(s.Targets, t.ID) {
		return true
	}
	if t.ASGID != "" && slices.Contains(s.ASGs, t.ASGID) {
		return true
	}
	if len(s.Tags) == 0 {
		return false
	}
	for k, v := range s.Tags {
		if got, ok := t.Tags[k]; !ok || got != v {
			return false
		}
	}
	return true
}

type legacyRule struct {
	Selector  legacySelector `json:"target_selector"`
	Protocols []string       `json:"protocols"`
}

// legacyPolicy is one stored row before ADR 0036: one subject, a selector
// with its protocols, extra rules, and one set of conditions.
type legacyPolicy struct {
	ID                 string
	Name               string
	Enabled            bool
	GroupID            string
	UserID             string
	Selector           legacySelector
	Protocols          []string
	Rules              []legacyRule
	TimeWindows        []TimeWindow
	MaxSessionMinutes  *int
	IdleTimeoutMinutes int
	RetentionDays      *int
	AllowClipboard     bool
	AllowFileTransfer  bool
	RequireMFA         bool
	RequireApproval    bool
}

func (p *legacyPolicy) covers(t TargetRef, protocol string) bool {
	if p.Selector.matches(t) && slices.Contains(p.Protocols, protocol) {
		return true
	}
	for _, r := range p.Rules {
		if r.Selector.matches(t) && slices.Contains(r.Protocols, protocol) {
			return true
		}
	}
	return false
}

func (p *legacyPolicy) matchesAnyRule(t TargetRef) bool {
	for _, r := range p.Rules {
		if r.Selector.matches(t) {
			return true
		}
	}
	return false
}

type legacyDecision struct {
	Allowed           bool
	Reason            string
	Policy            *legacyPolicy
	IdleTimeout       time.Duration
	MaxSession        time.Duration
	RetentionDays     int
	AllowClipboard    bool
	AllowFileTransfer bool
	RequireMFA        bool
	RequireApproval   bool
}

// legacyEvaluate is Evaluate before ADR 0036: standing policies decide when
// any applies, approval-gated ones otherwise, and of those the one with the
// shortest idle timeout sets every term but retention, which is the longest.
func legacyEvaluate(policies []*legacyPolicy, t TargetRef, protocol string, now time.Time) legacyDecision {
	var standing, gated legacyGrantSet
	reason := "no policy grants access to this target"
	for _, p := range policies {
		if !p.Enabled {
			continue
		}
		if !p.covers(t, protocol) {
			if p.Selector.matches(t) || p.matchesAnyRule(t) {
				reason = "protocol not allowed by policy"
			}
			continue
		}
		if len(p.TimeWindows) > 0 && !anyOpen(p.TimeWindows, now) {
			reason = "outside the policy's access window"
			continue
		}
		if p.RequireApproval {
			gated.add(p)
		} else {
			standing.add(p)
		}
	}
	set, requireApproval := standing, false
	if set.best == nil {
		set, requireApproval = gated, true
	}
	best := set.best
	if best == nil {
		return legacyDecision{Reason: reason}
	}
	d := legacyDecision{
		Allowed:           true,
		Policy:            best,
		IdleTimeout:       time.Duration(best.IdleTimeoutMinutes) * time.Minute,
		AllowClipboard:    best.AllowClipboard,
		AllowFileTransfer: best.AllowFileTransfer,
		RequireMFA:        best.RequireMFA,
		RequireApproval:   requireApproval,
		RetentionDays:     set.retention,
	}
	if best.MaxSessionMinutes != nil {
		d.MaxSession = time.Duration(*best.MaxSessionMinutes) * time.Minute
	}
	return d
}

type legacyGrantSet struct {
	best      *legacyPolicy
	retention int
}

func (g *legacyGrantSet) add(p *legacyPolicy) {
	if p.RetentionDays != nil && *p.RetentionDays > g.retention {
		g.retention = *p.RetentionDays
	}
	if g.best == nil || p.IdleTimeoutMinutes < g.best.IdleTimeoutMinutes {
		g.best = p
	}
}
