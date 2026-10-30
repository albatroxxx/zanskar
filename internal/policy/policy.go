// SPDX-License-Identifier: Apache-2.0

// Package policy decides who may open which protocol to which target, and
// under what conditions (ADR 0036). A policy names its audience, any number
// of groups and users, and lists grants. Each grant is complete on its own:
// a kind of target, which targets of that kind (by name, with protocols per
// target, or by tag), and the conditions a session opens and runs under.
// Evaluation happens server-side on every connect. When several grants
// admit the same session, standing access wins over approval, and each term
// is the strictest among them. A live session is re-checked whenever the
// access that admitted it may have changed, and ends when a fresh connect
// would be refused or its clipboard or file transfer would now be off.
package policy

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/protocol"
)

// Subject kinds: a policy names groups and users.
const (
	SubjectGroup = "group"
	SubjectUser  = "user"
)

// Access: a standing grant admits at once; an approval grant makes the
// person eligible to request access (just-in-time, ADR 0018).
const (
	AccessStanding = "standing"
	AccessApproval = "approval"
)

// Sign-in: SignInTarget lets the target's slot decide (its vaulted
// credential, its SSH authority, or User supplied); SignInOwn asks for the
// person's own login whatever the slot holds.
const (
	SignInTarget = "target"
	SignInOwn    = "own"
)

// Bounds.
const (
	MaxSubjects     = 64
	MaxGrants       = 32
	MaxGrantTargets = 200
	MaxTagKeys      = 32
	MaxTagValues    = 16
	maxTagLen       = 64
)

// Subject is one group or user a policy applies to.
type Subject struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// GrantTarget is one named target (or autoscaling group) with the
// protocols granted on it.
type GrantTarget struct {
	ID        string   `json:"id"`
	Protocols []string `json:"protocols"`
}

// TagMatch selects every target of the grant's kind that carries every key
// with one of its values, now or later, with the protocols granted on them.
type TagMatch struct {
	Match     map[string][]string `json:"match"`
	Protocols []string            `json:"protocols"`
}

// Grant is one complete grant: what, and under which conditions.
type Grant struct {
	ID                 string        `json:"id"`
	Kind               string        `json:"kind"`
	Targets            []GrantTarget `json:"targets"`
	Tags               *TagMatch     `json:"tags,omitempty"`
	Access             string        `json:"access"`
	SignIn             string        `json:"sign_in"`
	RequireMFA         bool          `json:"require_mfa"`
	AllowClipboard     bool          `json:"allow_clipboard"`
	AllowFileTransfer  bool          `json:"allow_file_transfer"`
	IdleTimeoutMinutes int           `json:"idle_timeout_minutes"`
	MaxSessionMinutes  *int          `json:"max_session_minutes"`
	TimeWindows        []TimeWindow  `json:"time_windows"`
	RetentionDays      *int          `json:"retention_days"`
}

// TimeWindow is a recurring weekly window in a named zone.
type TimeWindow struct {
	Days []string `json:"days"` // mon..sun
	From string   `json:"from"` // "09:00"
	To   string   `json:"to"`   // "18:00"; less than From for overnight windows, equal for all day
	TZ   string   `json:"tz"`   // IANA zone, default UTC
}

// Policy is an audience and the grants it holds.
type Policy struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	Subjects    []Subject `json:"subjects"`
	Grants      []Grant   `json:"grants"`
	CreatedBy   string    `json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Errors.
var (
	ErrNotFound     = errors.New("policy: not found")
	ErrDuplicate    = errors.New("policy: name already exists")
	ErrInvalidInput = errors.New("policy: invalid input")
	// ErrProtocolNotForKind and ErrUnknownSubject are invalid input of a kind
	// the API names with codes of their own.
	ErrProtocolNotForKind = errors.New("protocol not served by the kind")
	ErrUnknownSubject     = errors.New("subject not found")
)

var dayIndex = map[string]time.Weekday{"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday, "thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday}

// Validate checks a policy before it is stored, filling the defaults a
// grant may leave out (access standing, sign-in target, idle 15 minutes).
func (p *Policy) Validate() error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || len(p.Name) > 64 {
		return fmt.Errorf("%w: name must be 1-64 characters", ErrInvalidInput)
	}
	// No subject is allowed: a policy whose last group or user was deleted
	// grants nobody and may still be edited or switched off. A new policy
	// needs someone (the handler asks).
	if len(p.Subjects) > MaxSubjects {
		return fmt.Errorf("%w: at most %d groups and users", ErrInvalidInput, MaxSubjects)
	}
	seen := map[Subject]bool{}
	for _, s := range p.Subjects {
		if (s.Kind != SubjectGroup && s.Kind != SubjectUser) || s.ID == "" {
			return fmt.Errorf("%w: a subject is a group or a user, by id", ErrInvalidInput)
		}
		if seen[s] {
			return fmt.Errorf("%w: %s %s is named twice", ErrInvalidInput, s.Kind, s.ID)
		}
		seen[s] = true
	}
	if len(p.Grants) == 0 {
		return fmt.Errorf("%w: a policy needs at least one grant", ErrInvalidInput)
	}
	if len(p.Grants) > MaxGrants {
		return fmt.Errorf("%w: at most %d grants", ErrInvalidInput, MaxGrants)
	}
	ids := map[string]bool{}
	for i := range p.Grants {
		g := &p.Grants[i]
		if err := g.validate(); err != nil {
			return fmt.Errorf("grant %d: %w", i+1, err)
		}
		if g.ID != "" {
			if ids[g.ID] {
				return fmt.Errorf("%w: grant %d repeats grant id %s", ErrInvalidInput, i+1, g.ID)
			}
			ids[g.ID] = true
		}
	}
	return nil
}

func (g *Grant) validate() error {
	if !protocol.ValidKind(g.Kind) {
		return fmt.Errorf("%w: kind must be one of %s", ErrInvalidInput, strings.Join(protocol.Kinds, ", "))
	}
	if len(g.Targets) == 0 && g.Tags == nil {
		return fmt.Errorf("%w: name targets or match tags", ErrInvalidInput)
	}
	if len(g.Targets) > MaxGrantTargets {
		return fmt.Errorf("%w: at most %d targets", ErrInvalidInput, MaxGrantTargets)
	}
	named := map[string]bool{}
	for _, t := range g.Targets {
		if t.ID == "" {
			return fmt.Errorf("%w: a target needs its id", ErrInvalidInput)
		}
		if named[t.ID] {
			return fmt.Errorf("%w: target %s is named twice", ErrInvalidInput, t.ID)
		}
		named[t.ID] = true
		if err := g.validProtocols(t.Protocols); err != nil {
			return fmt.Errorf("target %s: %w", t.ID, err)
		}
	}
	if g.Tags != nil {
		if err := g.Tags.validate(); err != nil {
			return err
		}
		if err := g.validProtocols(g.Tags.Protocols); err != nil {
			return fmt.Errorf("tags: %w", err)
		}
	}
	if g.Targets == nil {
		g.Targets = []GrantTarget{}
	}
	switch g.Access {
	case "":
		g.Access = AccessStanding
	case AccessStanding, AccessApproval:
	default:
		return fmt.Errorf("%w: access must be standing or approval", ErrInvalidInput)
	}
	switch g.SignIn {
	case "":
		g.SignIn = SignInTarget
	case SignInTarget, SignInOwn:
	default:
		return fmt.Errorf("%w: sign_in must be target or own", ErrInvalidInput)
	}
	if g.SignIn == SignInOwn && g.Kind == protocol.KindApplication {
		return fmt.Errorf("%w: an application has no login of its own; sign_in must be target", ErrInvalidInput)
	}
	if g.IdleTimeoutMinutes == 0 {
		g.IdleTimeoutMinutes = 15
	}
	if g.IdleTimeoutMinutes < 1 || g.IdleTimeoutMinutes > 24*60 {
		return fmt.Errorf("%w: idle_timeout_minutes must be 1-1440", ErrInvalidInput)
	}
	if g.MaxSessionMinutes != nil && (*g.MaxSessionMinutes < 1 || *g.MaxSessionMinutes > 7*24*60) {
		return fmt.Errorf("%w: max_session_minutes must be 1-10080", ErrInvalidInput)
	}
	if g.RetentionDays != nil && (*g.RetentionDays < 1 || *g.RetentionDays > 3650) {
		return fmt.Errorf("%w: retention_days must be 1-3650", ErrInvalidInput)
	}
	for i := range g.TimeWindows {
		if err := g.TimeWindows[i].validate(); err != nil {
			return err
		}
	}
	if g.TimeWindows == nil {
		g.TimeWindows = []TimeWindow{}
	}
	return nil
}

// validProtocols checks a protocol list against what the grant's kind serves.
func (g *Grant) validProtocols(protos []string) error {
	if len(protos) == 0 {
		return fmt.Errorf("%w: choose at least one protocol", ErrInvalidInput)
	}
	seen := map[string]bool{}
	for _, p := range protos {
		if !protocol.KindServes(g.Kind, p) {
			return fmt.Errorf("%w: %w: a %s does not serve %q (it serves %s)", ErrInvalidInput, ErrProtocolNotForKind, g.Kind, p, strings.Join(protocol.KindProtocols(g.Kind), ", "))
		}
		if seen[p] {
			return fmt.Errorf("%w: %s is given twice", ErrInvalidInput, p)
		}
		seen[p] = true
	}
	return nil
}

func (m *TagMatch) validate() error {
	if len(m.Match) == 0 {
		return fmt.Errorf("%w: a tag match needs at least one key", ErrInvalidInput)
	}
	if len(m.Match) > MaxTagKeys {
		return fmt.Errorf("%w: at most %d tag keys", ErrInvalidInput, MaxTagKeys)
	}
	for k, vs := range m.Match {
		if k == "" || len(k) > maxTagLen {
			return fmt.Errorf("%w: tag keys are 1-%d characters", ErrInvalidInput, maxTagLen)
		}
		if len(vs) == 0 || len(vs) > MaxTagValues {
			return fmt.Errorf("%w: tag %s needs 1-%d values", ErrInvalidInput, k, MaxTagValues)
		}
		seen := map[string]bool{}
		for _, v := range vs {
			if v == "" || len(v) > maxTagLen {
				return fmt.Errorf("%w: tag %s: values are 1-%d characters", ErrInvalidInput, k, maxTagLen)
			}
			if seen[v] {
				return fmt.Errorf("%w: tag %s: value %s is given twice", ErrInvalidInput, k, v)
			}
			seen[v] = true
		}
	}
	return nil
}

// TargetRef is what the evaluator needs to know about a connection target.
type TargetRef struct {
	Kind  string            // protocol.Kind*: host, database, application, autoscaling
	ID    string            // static target id, or empty
	ASGID string            // autoscaling group id, or empty
	Tags  map[string]string // tags of the target or of its group
}

// id is the id a grant's named targets are matched against: the group's for
// an autoscaling grant, the target's otherwise.
func (t TargetRef) id() string {
	if t.Kind == protocol.KindAutoscaling {
		return t.ASGID
	}
	return t.ID
}

// Covers reports whether the grant admits protocol on the target, windows
// aside: same kind, and the target named with the protocol, or matched by
// the tag rule with it.
func (g *Grant) Covers(t TargetRef, proto string) bool {
	if g.Kind != t.Kind || !protocol.KindServes(g.Kind, proto) {
		return false
	}
	if id := t.id(); id != "" {
		for _, gt := range g.Targets {
			if gt.ID == id && slices.Contains(gt.Protocols, proto) {
				return true
			}
		}
	}
	return g.Tags != nil && slices.Contains(g.Tags.Protocols, proto) && g.Tags.matches(t.Tags)
}

// selects reports whether the grant points at the target at all, whatever
// the protocol: for telling a protocol refusal from no access.
func (g *Grant) selects(t TargetRef) bool {
	if g.Kind != t.Kind {
		return false
	}
	if id := t.id(); id != "" {
		for _, gt := range g.Targets {
			if gt.ID == id {
				return true
			}
		}
	}
	return g.Tags != nil && g.Tags.matches(t.Tags)
}

// matches: every key present with one of its values.
func (m *TagMatch) matches(tags map[string]string) bool {
	if len(m.Match) == 0 {
		return false
	}
	for k, vs := range m.Match {
		got, ok := tags[k]
		if !ok || !slices.Contains(vs, got) {
			return false
		}
	}
	return true
}

// References reports whether the policy names the target or the autoscaling
// group by id in any grant. Tag rules are not references.
func (p *Policy) References(targetID, asgID string) bool {
	for _, g := range p.Grants {
		want := targetID
		if g.Kind == protocol.KindAutoscaling {
			want = asgID
		}
		if want == "" {
			continue
		}
		for _, gt := range g.Targets {
			if gt.ID == want {
				return true
			}
		}
	}
	return false
}

// HasSubject reports whether the policy names the subject.
func (p *Policy) HasSubject(kind, id string) bool {
	return slices.Contains(p.Subjects, Subject{Kind: kind, ID: id})
}

// GrantRef names one grant that decided an evaluation.
type GrantRef struct {
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	GrantID    string `json:"grant_id"`
}

// Decision is the outcome of an evaluation.
type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"` // when denied
	// Policy and GrantID name the deciding grant with the shortest idle
	// timeout (ties: the policy first by name, then the grant first in it).
	// They label the session; revocation does not key on them.
	Policy  *Policy `json:"policy,omitempty"`
	GrantID string  `json:"grant_id,omitempty"`
	// Grants lists every grant that decided, for the audit trail.
	Grants []GrantRef `json:"grants,omitempty"`
	// The session's terms: each the strictest among the deciding grants.
	IdleTimeout time.Duration `json:"-"`
	MaxSession  time.Duration `json:"-"`
	// RetentionDays is the longest among the deciding grants; 0 leaves the
	// global retention policy in charge.
	RetentionDays     int  `json:"-"`
	AllowClipboard    bool `json:"allow_clipboard"`
	AllowFileTransfer bool `json:"allow_file_transfer"`
	RequireMFA        bool `json:"require_mfa"`
	// RequireApproval is true when only approval grants admit, so the
	// person needs an active grant to connect (ADR 0018).
	RequireApproval bool `json:"require_approval"`
	// SignInTarget: a deciding grant lets the target's slot decide.
	// SignInOwn: a deciding grant allows the person's own login. When only
	// SignInOwn is set, the person's own login is asked for.
	SignInTarget bool `json:"sign_in_target"`
	SignInOwn    bool `json:"sign_in_own"`
}

// Evaluate decides access from the caller's policies, given in name order.
// It collects the grants of enabled policies that cover the target and
// protocol and have a window open now (or none). If any is standing, the
// standing ones decide and no approval is needed; otherwise the approval
// ones decide. Of the deciding grants, the idle timeout and maximum are the
// shortest, clipboard and file transfer are allowed only if every grant
// allows them, an authenticator is required if any grant requires one, and
// retention is the longest. Adding a grant can add access; it never loosens
// a term of access that already exists.
func Evaluate(policies []*Policy, t TargetRef, proto string, now time.Time) Decision {
	return evaluate(policies, t, proto, now, true)
}

// EvaluateLive is Evaluate for a session already running: every time window
// counts as open. A window that shuts, or one narrowed by an edit, does not
// pull a running session (ADR 0036); its maximum bounds it instead.
func EvaluateLive(policies []*Policy, t TargetRef, proto string, now time.Time) Decision {
	return evaluate(policies, t, proto, now, false)
}

func evaluate(policies []*Policy, t TargetRef, proto string, now time.Time, windows bool) Decision {
	reason := "no policy grants access to this target"
	var standing, approval []decider
	for _, p := range policies {
		if !p.Enabled {
			continue
		}
		for i := range p.Grants {
			g := &p.Grants[i]
			if !g.Covers(t, proto) {
				if g.selects(t) {
					reason = "protocol not allowed by policy"
				}
				continue
			}
			if windows && len(g.TimeWindows) > 0 && !anyOpen(g.TimeWindows, now) {
				reason = "outside the policy's access window"
				continue
			}
			if g.Access == AccessApproval {
				approval = append(approval, decider{p, g})
			} else {
				standing = append(standing, decider{p, g})
			}
		}
	}
	set, requireApproval := standing, false
	if len(set) == 0 {
		set, requireApproval = approval, true
	}
	if len(set) == 0 {
		return Decision{Reason: reason}
	}
	d := Decision{Allowed: true, RequireApproval: requireApproval, AllowClipboard: true, AllowFileTransfer: true}
	var best *decider
	maxSet := false
	for i := range set {
		c := &set[i]
		g := c.g
		d.Grants = append(d.Grants, GrantRef{PolicyID: c.p.ID, PolicyName: c.p.Name, GrantID: g.ID})
		if best == nil || g.IdleTimeoutMinutes < best.g.IdleTimeoutMinutes {
			best = c
		}
		d.AllowClipboard = d.AllowClipboard && g.AllowClipboard
		d.AllowFileTransfer = d.AllowFileTransfer && g.AllowFileTransfer
		d.RequireMFA = d.RequireMFA || g.RequireMFA
		if g.MaxSessionMinutes != nil {
			m := time.Duration(*g.MaxSessionMinutes) * time.Minute
			if !maxSet || m < d.MaxSession {
				d.MaxSession, maxSet = m, true
			}
		}
		if g.RetentionDays != nil && *g.RetentionDays > d.RetentionDays {
			d.RetentionDays = *g.RetentionDays
		}
		if g.SignIn == SignInOwn {
			d.SignInOwn = true
		} else {
			d.SignInTarget = true
		}
	}
	d.Policy, d.GrantID = best.p, best.g.ID
	d.IdleTimeout = time.Duration(best.g.IdleTimeoutMinutes) * time.Minute
	return d
}

type decider struct {
	p *Policy
	g *Grant
}

func anyOpen(windows []TimeWindow, now time.Time) bool {
	for _, w := range windows {
		if w.Open(now) {
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
	if from == to {
		// Equal ends are the whole day, as 00:00 to 00:00 is written to say;
		// read as an empty span, such a window never opened (B18).
		return w.hasDay(today)
	}
	if from < to {
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
