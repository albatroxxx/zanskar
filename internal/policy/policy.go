// SPDX-License-Identifier: Apache-2.0

// Package policy decides who may open which protocol to which target, and
// under what constraints. A policy binds one group to a selector of targets.
// Evaluation happens server-side on every connect and is re-checked while a
// session is open, so a revoked policy ends live sessions too.
package policy

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Protocols a policy may allow. "database" grants brokered access to a database
// target (ADR 0017); it is evaluated at connect time like any other protocol.
var validProtocols = map[string]bool{"ssh": true, "rdp": true, "vnc": true, "winrm": true, "database": true}

// Selector names the targets a policy covers. A target matches when its id is
// listed, its ASG id is listed, or every selector tag is present on it with
// the same value. An empty selector matches nothing.
type Selector struct {
	Targets []string          `json:"targets,omitempty"`
	ASGs    []string          `json:"asgs,omitempty"`
	Tags    map[string]string `json:"tags,omitempty"`
}

// Empty reports whether the selector can never match.
func (s Selector) Empty() bool {
	return len(s.Targets) == 0 && len(s.ASGs) == 0 && len(s.Tags) == 0
}

// Rule pairs a selector with the protocols it grants. A policy's own
// target_selector and protocols form its first rule; Rules adds more, so one
// policy can say "ssh to the Linux fleet, rdp to the two jump hosts" without
// a second policy for the same people and limits. Every rule shares the
// policy's windows, limits and flags.
type Rule struct {
	Selector  Selector `json:"target_selector"`
	Protocols []string `json:"protocols"`
}

// MaxRules bounds the extra rules on one policy.
const MaxRules = 32

// TimeWindow is a recurring weekly window in a named zone.
type TimeWindow struct {
	Days []string `json:"days"` // mon..sun
	From string   `json:"from"` // "09:00"
	To   string   `json:"to"`   // "18:00"; may be less than From for overnight windows
	TZ   string   `json:"tz"`   // IANA zone, default UTC
}

// Policy is one access rule.
type Policy struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	// Exactly one of GroupID and UserID is set: a policy applies to every
	// member of a group, or to one user directly (ADR 0013).
	GroupID   string   `json:"group_id,omitempty"`
	UserID    string   `json:"user_id,omitempty"`
	Selector  Selector `json:"target_selector"`
	Protocols []string `json:"protocols"`
	// Rules are further selector/protocol pairs granted by this policy, on
	// top of the base Selector and Protocols (which may be empty when Rules
	// carry everything).
	Rules              []Rule       `json:"rules"`
	TimeWindows        []TimeWindow `json:"time_windows"`
	MaxSessionMinutes  *int         `json:"max_session_minutes,omitempty"`
	IdleTimeoutMinutes int          `json:"idle_timeout_minutes"`
	AllowClipboard     bool         `json:"allow_clipboard"`
	AllowFileTransfer  bool         `json:"allow_file_transfer"`
	RequireMFA         bool         `json:"require_mfa"`
	// RequireApproval makes this policy grant eligibility, not standing access:
	// the user must request access and be approved before connect is permitted
	// (just-in-time / PIM, ADR 0018).
	RequireApproval bool      `json:"require_approval"`
	CreatedBy       string    `json:"created_by,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// Errors.
var (
	ErrNotFound     = errors.New("policy: not found")
	ErrDuplicate    = errors.New("policy: name already exists")
	ErrInvalidInput = errors.New("policy: invalid input")
)

var dayIndex = map[string]time.Weekday{"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday, "thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday}

// Validate checks a policy before it is stored.
func (p *Policy) Validate() error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || len(p.Name) > 64 {
		return fmt.Errorf("%w: name must be 1-64 characters", ErrInvalidInput)
	}
	if (p.GroupID == "") == (p.UserID == "") {
		return fmt.Errorf("%w: exactly one of group_id or user_id is required", ErrInvalidInput)
	}
	// The base selector and protocols may be empty only when rules carry the
	// grants; a policy that grants nothing anywhere is a mistake, not a policy.
	if p.Selector.Empty() != (len(p.Protocols) == 0) {
		return fmt.Errorf("%w: target_selector and protocols go together; give both or neither", ErrInvalidInput)
	}
	if p.Selector.Empty() && len(p.Rules) == 0 {
		return fmt.Errorf("%w: target_selector must name targets, asgs or tags", ErrInvalidInput)
	}
	if !p.Selector.Empty() {
		if err := validateSelector(p.Selector); err != nil {
			return err
		}
		if err := validateProtocols(p.Protocols); err != nil {
			return err
		}
	}
	if len(p.Rules) > MaxRules {
		return fmt.Errorf("%w: at most %d rules", ErrInvalidInput, MaxRules)
	}
	for i, rule := range p.Rules {
		if rule.Selector.Empty() {
			return fmt.Errorf("%w: rule %d must name targets, asgs or tags", ErrInvalidInput, i+1)
		}
		if err := validateSelector(rule.Selector); err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
		if len(rule.Protocols) == 0 {
			return fmt.Errorf("%w: rule %d needs at least one protocol", ErrInvalidInput, i+1)
		}
		if err := validateProtocols(rule.Protocols); err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	if p.Rules == nil {
		p.Rules = []Rule{}
	}
	if p.IdleTimeoutMinutes <= 0 || p.IdleTimeoutMinutes > 24*60 {
		return fmt.Errorf("%w: idle_timeout_minutes must be 1-1440", ErrInvalidInput)
	}
	if p.MaxSessionMinutes != nil && (*p.MaxSessionMinutes <= 0 || *p.MaxSessionMinutes > 7*24*60) {
		return fmt.Errorf("%w: max_session_minutes must be 1-10080", ErrInvalidInput)
	}
	for i := range p.TimeWindows {
		if err := p.TimeWindows[i].validate(); err != nil {
			return err
		}
	}
	if p.TimeWindows == nil {
		p.TimeWindows = []TimeWindow{}
	}
	return nil
}

func validateSelector(s Selector) error {
	if len(s.Tags) > 32 {
		return fmt.Errorf("%w: at most 32 selector tags", ErrInvalidInput)
	}
	for k, v := range s.Tags {
		if k == "" || len(k) > 64 || len(v) > 64 {
			return fmt.Errorf("%w: tag keys and values must be 1-64 characters", ErrInvalidInput)
		}
	}
	return nil
}

func validateProtocols(protocols []string) error {
	seen := map[string]bool{}
	for _, proto := range protocols {
		if !validProtocols[proto] {
			return fmt.Errorf("%w: unknown protocol %q", ErrInvalidInput, proto)
		}
		if seen[proto] {
			return fmt.Errorf("%w: duplicate protocol %q", ErrInvalidInput, proto)
		}
		seen[proto] = true
	}
	return nil
}

// Covers reports whether the policy grants protocol on the target: through
// its base selector and protocols, or through any of its rules. Every
// caller that decides access must use this and nothing looser, or a rule
// would grant in one place and be ignored in another.
func (p *Policy) Covers(t TargetRef, protocol string) bool {
	if p.Selector.Matches(t) && contains(p.Protocols, protocol) {
		return true
	}
	for _, r := range p.Rules {
		if r.Selector.Matches(t) && contains(r.Protocols, protocol) {
			return true
		}
	}
	return false
}

// References reports whether the policy names the target or the autoscaling
// group by id anywhere: the base selector or any rule. Tag selectors are not
// references.
func (p *Policy) References(targetID, asgID string) bool {
	sels := []Selector{p.Selector}
	for _, r := range p.Rules {
		sels = append(sels, r.Selector)
	}
	for _, s := range sels {
		if (targetID != "" && contains(s.Targets, targetID)) || (asgID != "" && contains(s.ASGs, asgID)) {
			return true
		}
	}
	return false
}

func (w *TimeWindow) validate() error {
	if len(w.Days) == 0 {
		return fmt.Errorf("%w: time window needs days", ErrInvalidInput)
	}
	for i, d := range w.Days {
		d = strings.ToLower(strings.TrimSpace(d))
		if _, ok := dayIndex[d]; !ok {
			return fmt.Errorf("%w: unknown day %q", ErrInvalidInput, d)
		}
		w.Days[i] = d
	}
	if _, err := parseClock(w.From); err != nil {
		return fmt.Errorf("%w: from: %w", ErrInvalidInput, err)
	}
	if _, err := parseClock(w.To); err != nil {
		return fmt.Errorf("%w: to: %w", ErrInvalidInput, err)
	}
	if w.TZ == "" {
		w.TZ = "UTC"
	}
	if _, err := time.LoadLocation(w.TZ); err != nil {
		return fmt.Errorf("%w: unknown time zone %q", ErrInvalidInput, w.TZ)
	}
	return nil
}

func parseClock(s string) (int, error) {
	var h, m int
	if _, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil || h < 0 || h > 23 || m < 0 || m > 59 || len(s) != 5 {
		return 0, fmt.Errorf("want HH:MM, got %q", s)
	}
	return h*60 + m, nil
}

// Open reports whether now falls inside the window.
func (w TimeWindow) Open(now time.Time) bool {
	loc, err := time.LoadLocation(w.TZ)
	if err != nil {
		return false
	}
	local := now.In(loc)
	from, _ := parseClock(w.From)
	to, _ := parseClock(w.To)
	minute := local.Hour()*60 + local.Minute()
	today := local.Weekday()
	yesterday := (today + 6) % 7
	if from <= to {
		return w.hasDay(today) && minute >= from && minute < to
	}
	// Overnight window, e.g. 22:00 to 06:00: either after From today, or
	// before To on the day after a listed day.
	return (w.hasDay(today) && minute >= from) || (w.hasDay(yesterday) && minute < to)
}

func (w TimeWindow) hasDay(d time.Weekday) bool {
	for _, name := range w.Days {
		if dayIndex[name] == d {
			return true
		}
	}
	return false
}

// TargetRef is what the engine needs to know about a connection target.
type TargetRef struct {
	ID    string            // static target id, or empty
	ASGID string            // autoscaling group id, or empty
	Tags  map[string]string // tags of the target or of its ASG
}

// Matches reports whether the selector covers the target.
func (s Selector) Matches(t TargetRef) bool {
	if t.ID != "" {
		for _, id := range s.Targets {
			if id == t.ID {
				return true
			}
		}
	}
	if t.ASGID != "" {
		for _, id := range s.ASGs {
			if id == t.ASGID {
				return true
			}
		}
	}
	if len(s.Tags) == 0 {
		return false
	}
	for k, v := range s.Tags {
		if t.Tags[k] != v {
			return false
		}
	}
	return true
}

// Decision is the outcome of an evaluation.
type Decision struct {
	Allowed bool    `json:"allowed"`
	Reason  string  `json:"reason,omitempty"` // when denied
	Policy  *Policy `json:"policy,omitempty"` // the policy that allowed it
	// Effective constraints, taken from the allowing policy.
	IdleTimeout       time.Duration `json:"-"`
	MaxSession        time.Duration `json:"-"`
	AllowClipboard    bool          `json:"allow_clipboard"`
	AllowFileTransfer bool          `json:"allow_file_transfer"`
	RequireMFA        bool          `json:"require_mfa"`
	// RequireApproval is true when every policy granting this access is
	// approval-gated, so the caller holds no standing access and needs an active
	// grant to connect (ADR 0018). False when any standing policy also grants it.
	RequireApproval bool `json:"require_approval"`
}

// Evaluate picks the first enabled policy among the caller's policies that
// covers the target, allows the protocol and is inside a time window (or has
// none). Policies are ordered most-restrictive-first by the caller? No:
// order is by name, and the first match wins; admins should keep policies
// non-overlapping. When several match, the one with the shortest idle
// timeout is chosen so overlap never widens access.
func Evaluate(policies []*Policy, t TargetRef, protocol string, now time.Time) Decision {
	var best *Policy
	sawStanding := false
	reason := "no policy grants access to this target"
	for _, p := range policies {
		if !p.Enabled {
			continue
		}
		if !p.Covers(t, protocol) {
			// Tell a protocol refusal from a target the policy never covers,
			// since the user sees the reason.
			if p.Selector.Matches(t) || p.matchesAnyRule(t) {
				reason = "protocol not allowed by policy"
			}
			continue
		}
		if len(p.TimeWindows) > 0 {
			open := false
			for _, w := range p.TimeWindows {
				if w.Open(now) {
					open = true
					break
				}
			}
			if !open {
				reason = "outside the policy's access window"
				continue
			}
		}
		// A qualifying standing policy means no approval is needed; access is the
		// union, so any standing grant wins over an approval-gated one.
		if !p.RequireApproval {
			sawStanding = true
		}
		if best == nil || p.IdleTimeoutMinutes < best.IdleTimeoutMinutes {
			best = p
		}
	}
	if best == nil {
		return Decision{Allowed: false, Reason: reason}
	}
	d := Decision{
		Allowed:           true,
		Policy:            best,
		IdleTimeout:       time.Duration(best.IdleTimeoutMinutes) * time.Minute,
		AllowClipboard:    best.AllowClipboard,
		AllowFileTransfer: best.AllowFileTransfer,
		RequireMFA:        best.RequireMFA,
		RequireApproval:   !sawStanding,
	}
	if best.MaxSessionMinutes != nil {
		d.MaxSession = time.Duration(*best.MaxSessionMinutes) * time.Minute
	}
	return d
}

func (p *Policy) matchesAnyRule(t TargetRef) bool {
	for _, r := range p.Rules {
		if r.Selector.Matches(t) {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
