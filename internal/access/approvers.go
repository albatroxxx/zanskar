// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/asg"
	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/group"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/protocol"
	"github.com/albatroxxx/zanskar/internal/target"
	"github.com/albatroxxx/zanskar/internal/user"
)

// Who decides a request (ADR 0049). A grant that makes people eligible may
// name approvers, groups or users; a request's approvers are the union over
// the approval grants that cover its target and protocol, resolved to
// people when the queue is listed and again when a decision is made, from
// the policies as they stand then (as eligibility is, ADR 0018 SEC-2).
// Nobody named: any administrator decides, as before. Someone named: the
// named decide, never their own request; an administrator sees the request
// and may revoke the grant, and does not approve or deny it.

// ApproverRef is one named approver as the queue shows it: the designation
// on the grant, with its name resolved when read.
type ApproverRef struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// deciders is a request's approvers: the designation for display, the
// people it resolves to who hold the role, and the policies that named
// them, for a refusal to say.
type deciders struct {
	named    []ApproverRef
	users    map[string]bool
	policies []string
}

func (d deciders) isNamed() bool { return len(d.named) > 0 }

// others counts the deciders other than userID.
func (d deciders) others(userID string) int {
	n := 0
	for id := range d.users {
		if id != userID {
			n++
		}
	}
	return n
}

// names caches what one listing resolves, so a group fifty requests name is
// read once: users and groups by id, a group's members, and a requester's
// policies (the queue is read every half minute, on SQLite's one connection).
type names struct {
	users    map[string]*user.User
	groups   map[string]*group.Group
	members  map[string][]group.Member
	policies map[string][]*policy.Policy
}

func newNames() *names {
	return &names{users: map[string]*user.User{}, groups: map[string]*group.Group{}, members: map[string][]group.Member{}, policies: map[string][]*policy.Policy{}}
}

// userByID reads a user once per listing; nil for one that is gone.
func (h *Handler) userByID(ctx context.Context, n *names, id string) (*user.User, error) {
	if u, ok := n.users[id]; ok {
		return u, nil
	}
	u, err := h.Users.GetByID(ctx, id)
	if errors.Is(err, user.ErrNotFound) {
		u, err = nil, nil
	}
	if err != nil {
		return nil, err
	}
	n.users[id] = u
	return u, nil
}

// groupByID reads a group once per listing; nil for one that is gone.
func (h *Handler) groupByID(ctx context.Context, n *names, id string) (*group.Group, error) {
	if g, ok := n.groups[id]; ok {
		return g, nil
	}
	g, err := h.Groups.Get(ctx, id)
	if errors.Is(err, group.ErrNotFound) {
		g, err = nil, nil
	}
	if err != nil {
		return nil, err
	}
	n.groups[id] = g
	return g, nil
}

// membersOf reads a group's members once per listing.
func (h *Handler) membersOf(ctx context.Context, n *names, id string) ([]group.Member, error) {
	if m, ok := n.members[id]; ok {
		return m, nil
	}
	m, err := h.Groups.Members(ctx, id)
	if err != nil {
		return nil, err
	}
	n.members[id] = m
	return m, nil
}

// policiesFor reads a requester's policies once per listing.
func (h *Handler) policiesFor(ctx context.Context, n *names, userID string) ([]*policy.Policy, error) {
	if p, ok := n.policies[userID]; ok {
		return p, nil
	}
	p, err := h.Policies.ForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	n.policies[userID] = p
	return p, nil
}

// decidesFor reports whether u may be counted among a request's deciders:
// named is not enough, the role is needed too (ADR 0049, 3), and the
// account must be active; a disabled one decides nothing and is not written
// to.
func decidesFor(u *user.User) bool {
	return u != nil && u.Status == user.StatusActive && (u.HasRole(user.RoleApprover) || u.HasRole(user.RoleAdmin))
}

// decidableBy answers whether u may approve or deny req now (ADR 0049, 4):
// a pending request nobody is named for, for an administrator; a pending
// request u is named for, unless it is u's own.
func (d deciders) decidableBy(u *user.User, req *Request) bool {
	if req.Status != StatusPending {
		return false
	}
	if d.isNamed() {
		return d.users[u.ID] && req.UserID != u.ID
	}
	return u.HasRole(user.RoleAdmin)
}

// resolve finds who decides a request for ref and proto under pols. Without
// a Users or Groups repository nobody is named, so any administrator
// decides.
func (h *Handler) resolve(ctx context.Context, n *names, pols []*policy.Policy, ref policy.TargetRef, proto string) (deciders, error) {
	d := deciders{users: map[string]bool{}}
	if h.Users == nil || h.Groups == nil {
		return d, nil
	}
	subs := policy.ApproversOf(pols, ref, proto)
	if len(subs) == 0 {
		return d, nil
	}
	for _, p := range pols {
		if !p.Enabled {
			continue
		}
		for i := range p.Grants {
			g := &p.Grants[i]
			if g.Access == policy.AccessApproval && len(g.Approvers) > 0 && g.Covers(ref, proto) && !slices.Contains(d.policies, p.Name) {
				d.policies = append(d.policies, p.Name)
			}
		}
	}
	for _, s := range subs {
		a := ApproverRef{Kind: s.Kind, ID: s.ID}
		switch s.Kind {
		case policy.SubjectUser:
			u, err := h.userByID(ctx, n, s.ID)
			if err != nil {
				return d, err
			}
			if u != nil {
				a.Name = u.Username
				if decidesFor(u) {
					d.users[u.ID] = true
				}
			}
		case policy.SubjectGroup:
			g, err := h.groupByID(ctx, n, s.ID)
			if err != nil {
				return d, err
			}
			if g != nil {
				a.Name = g.Name
				members, err := h.membersOf(ctx, n, s.ID)
				if err != nil {
					return d, err
				}
				for _, m := range members {
					u, err := h.userByID(ctx, n, m.UserID)
					if err != nil {
						return d, err
					}
					if decidesFor(u) {
						d.users[u.ID] = true
					}
				}
			}
		}
		d.named = append(d.named, a)
	}
	return d, nil
}

// ref is the target or group a request names, as eligibility is judged on
// it; errGone when it no longer exists.
var errGone = errors.New("access: the target or group is gone")

func (h *Handler) ref(ctx context.Context, targetID, asgID string) (policy.TargetRef, error) {
	if targetID != "" {
		tgt, err := h.Targets.Get(ctx, targetID)
		if errors.Is(err, target.ErrNotFound) {
			return policy.TargetRef{}, errGone
		}
		if err != nil {
			return policy.TargetRef{}, err
		}
		return policy.TargetRef{Kind: tgt.Kind(), ID: tgt.ID, Tags: tgt.Tags}, nil
	}
	if h.ASGs == nil {
		return policy.TargetRef{}, errGone
	}
	g, err := h.ASGs.Get(ctx, asgID)
	if errors.Is(err, asg.ErrNotFound) {
		return policy.TargetRef{}, errGone
	}
	if err != nil {
		return policy.TargetRef{}, err
	}
	return policy.TargetRef{Kind: protocol.KindAutoscaling, ASGID: g.ID, Tags: g.Tags}, nil
}

// decidersOf resolves a request's deciders from the requester's policies as
// they stand now. A request whose target is gone has none.
func (h *Handler) decidersOf(ctx context.Context, n *names, req *Request) (deciders, error) {
	ref, err := h.ref(ctx, req.TargetID, req.ASGID)
	if errors.Is(err, errGone) {
		return deciders{users: map[string]bool{}}, nil
	}
	if err != nil {
		return deciders{}, err
	}
	pols, err := h.policiesFor(ctx, n, req.UserID)
	if err != nil {
		return deciders{}, err
	}
	return h.resolve(ctx, n, pols, ref, req.Protocol)
}

// decorate fills Approvers, Named and MayDecide (for the caller, pr) on the
// requests: every pending one, and every one when all is set (a single
// request read on its own).
func (h *Handler) decorate(ctx context.Context, n *names, pr *auth.Principal, reqs []*Request, all bool) (map[string]deciders, error) {
	out := map[string]deciders{}
	for _, req := range reqs {
		if !all && req.Status != StatusPending {
			continue
		}
		d, err := h.decidersOf(ctx, n, req)
		if err != nil {
			return nil, err
		}
		req.Approvers, req.Named, req.MayDecide = append([]ApproverRef{}, d.named...), d.isNamed(), d.decidableBy(pr.User, req)
		out[req.ID] = d
	}
	return out, nil
}

// decidersFor is decidersOf for a handler that has answered on failure.
func (h *Handler) decidersFor(w http.ResponseWriter, r *http.Request, req *Request) (deciders, bool) {
	d, err := h.decidersOf(r.Context(), newNames(), req)
	if err != nil {
		h.fail(w, r, err)
		return d, false
	}
	return d, true
}

// mayDecide answers whether the caller may approve or deny cur (ADR 0049,
// 4), writing the refusal when not.
func (h *Handler) mayDecide(w http.ResponseWriter, r *http.Request, pr *auth.Principal, cur *Request, d deciders) bool {
	admin := pr.User.HasRole(user.RoleAdmin)
	if d.isNamed() {
		if !d.users[pr.User.ID] {
			if admin {
				httpx.WriteError(w, r, http.StatusForbidden, "approvers_named", "this request has named approvers ("+strings.Join(approverNames(d), ", ")+"); they decide it")
			} else {
				httpx.WriteError(w, r, http.StatusForbidden, "forbidden", "you are not named to decide this request")
			}
			return false
		}
		if cur.UserID == pr.User.ID {
			httpx.WriteError(w, r, http.StatusForbidden, "own_request", "nobody decides their own request")
			return false
		}
		return true
	}
	if !admin {
		httpx.WriteError(w, r, http.StatusForbidden, "forbidden", "this request names no approvers; an administrator decides it")
		return false
	}
	return true
}

// mayRevoke answers whether the caller may revoke cur's grant: an
// administrator always, a named approver for the grants in their scope and
// never their own.
func (h *Handler) mayRevoke(w http.ResponseWriter, r *http.Request, pr *auth.Principal, cur *Request, d deciders) bool {
	if pr.User.HasRole(user.RoleAdmin) {
		return true
	}
	if !d.users[pr.User.ID] {
		httpx.WriteError(w, r, http.StatusForbidden, "forbidden", "you are not named to decide this request")
		return false
	}
	if cur.UserID == pr.User.ID {
		httpx.WriteError(w, r, http.StatusForbidden, "own_request", "nobody decides their own request")
		return false
	}
	return true
}

func approverNames(d deciders) []string {
	out := make([]string, 0, len(d.named))
	for _, a := range d.named {
		if a.Name != "" {
			out = append(out, a.Name)
		} else {
			out = append(out, a.ID)
		}
	}
	return out
}

// requireOthers refuses a new request nobody but its author could decide
// (ADR 0049, 4; TEAM blocks the same case), writing the refusal.
func (h *Handler) requireOthers(w http.ResponseWriter, r *http.Request, pr *auth.Principal, d deciders) bool {
	if !d.isNamed() || d.others(pr.User.ID) > 0 {
		return true
	}
	httpx.WriteError(w, r, http.StatusUnprocessableEntity, "no_approver",
		"nobody else is named to approve this request (policy "+strings.Join(d.policies, ", ")+")")
	return false
}

// mailApprovers tells the request's deciders other than the requester, each
// with an address, by mail (ADR 0049, 6). In the background: a slow mail
// server must not hold the request's answer. Nothing is logged but a
// failure.
func (h *Handler) mailApprovers(ctx context.Context, d deciders, requester *user.User, req *Request) {
	if h.Mail == nil || h.Users == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var to []string
	for id := range d.users {
		if id == requester.ID {
			continue
		}
		u, err := h.Users.GetByID(ctx, id)
		if err != nil || u.Email == "" {
			continue
		}
		to = append(to, u.Email)
	}
	if len(to) == 0 {
		return
	}
	slices.Sort(to)
	name := req.TargetName
	if name == "" {
		name = req.ASGName
	}
	if err := h.Mail.AccessRequested(ctx, to, requester.Username, req.Protocol, name, req.ID); err != nil && !errors.Is(err, notifyNoServer) {
		h.Log.Warn("access: mail the approvers", "request", req.ID, "err", err)
	}
}

// list is the approval queue and its history. An administrator without
// scope sees every request; scope=mine, the approver's view (and an
// administrator's when asked), is the pending requests the caller is named
// for, the active grants whose deciders they are now (the ones they may
// revoke, ADR 0049, 5) and the requests they decided that no longer run. An
// approver gets scope=mine whether or not they ask.
func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	pr, _ := auth.FromContext(r.Context())
	status := Status(r.URL.Query().Get("status"))
	switch status {
	case "", StatusPending, StatusApproved, StatusDenied, StatusExpired, StatusRevoked, StatusCancelled:
	default:
		httpx.BadRequest(w, r, "unknown status filter")
		return
	}
	scope := r.URL.Query().Get("scope")
	admin := pr.User.HasRole(user.RoleAdmin)
	if scope == "" && !admin {
		scope = "mine"
	}
	if scope != "" && scope != "mine" {
		httpx.BadRequest(w, r, "scope must be mine or left out")
		return
	}
	n := newNames()
	if scope == "" {
		items, err := h.Requests.List(r.Context(), status)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		if _, err := h.decorate(r.Context(), n, pr, items, false); err != nil {
			h.fail(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, httpx.Page[*Request]{Items: items})
		return
	}
	out, seen := []*Request{}, map[string]bool{}
	add := func(req *Request) {
		if !seen[req.ID] {
			seen[req.ID] = true
			out = append(out, req)
		}
	}
	now := time.Now().UTC()
	if status == "" || status == StatusPending {
		pending, err := h.Requests.List(r.Context(), StatusPending)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		ds, err := h.decorate(r.Context(), n, pr, pending, false)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		for _, req := range pending {
			if ds[req.ID].users[pr.User.ID] {
				add(req)
			}
		}
	}
	if status == "" || status == StatusApproved {
		// The grants the caller may revoke: active, with the caller among
		// their deciders as the policies stand now, whoever approved them.
		approved, err := h.Requests.List(r.Context(), StatusApproved)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		for _, req := range approved {
			if !req.Active(now) {
				continue
			}
			d, err := h.decidersOf(r.Context(), n, req)
			if err != nil {
				h.fail(w, r, err)
				return
			}
			if d.users[pr.User.ID] {
				add(req)
			}
		}
	}
	if status != StatusPending && status != StatusApproved {
		// The history: what the caller decided, once it no longer runs.
		decided, err := h.Requests.ListDecidedBy(r.Context(), pr.User.ID, status)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		for _, req := range decided {
			if !req.Active(now) {
				add(req)
			}
		}
	}
	slices.SortFunc(out, func(a, b *Request) int { return b.CreatedAt.Compare(a.CreatedAt) })
	httpx.WriteJSON(w, http.StatusOK, httpx.Page[*Request]{Items: out})
}

// one is a single request, for the link a notification carries: it opens
// the request whether it still waits or was decided meanwhile. An approver
// sees the requests they are named for or decided; another is not found, as
// own answers for another person's, so the id tells nothing.
func (h *Handler) one(w http.ResponseWriter, r *http.Request) {
	pr, _ := auth.FromContext(r.Context())
	req, err := h.Requests.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	ds, err := h.decorate(r.Context(), newNames(), pr, []*Request{req}, true)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if !pr.User.HasRole(user.RoleAdmin) && !ds[req.ID].users[pr.User.ID] && req.ApproverUserID != pr.User.ID {
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "access request not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, req)
}

// own reads the caller's own request; another person's is not found, as
// it is not theirs to see.
func (h *Handler) own(w http.ResponseWriter, r *http.Request, pr *auth.Principal) (*Request, bool) {
	cur, err := h.Requests.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, ErrNotFound) || (err == nil && cur.UserID != pr.User.ID) {
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "access request not found")
		return nil, false
	}
	if err != nil {
		h.fail(w, r, err)
		return nil, false
	}
	return cur, true
}

// cancel withdraws the caller's own pending request (ADR 0049, 8).
func (h *Handler) cancel(w http.ResponseWriter, r *http.Request) {
	pr, _ := auth.FromContext(r.Context())
	cur, ok := h.own(w, r, pr)
	if !ok {
		return
	}
	req, err := h.Requests.Cancel(r.Context(), cur.ID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.record(r, audit.AccessRequestCancel, req, nil)
	httpx.WriteJSON(w, http.StatusOK, req)
}

// end is the caller ending their own active grant (ADR 0049, 8): a revoke
// by the requester, ending the sessions it admitted as an administrator's
// revoke does, with the approver's note kept.
func (h *Handler) end(w http.ResponseWriter, r *http.Request) {
	pr, _ := auth.FromContext(r.Context())
	cur, ok := h.own(w, r, pr)
	if !ok {
		return
	}
	req, err := h.Requests.Revoke(r.Context(), cur.ID, cur.DecisionNote)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	more := map[string]any{"by": "requester"}
	if h.Revoker != nil {
		more["live_sessions_ended"] = h.Revoker.GrantRevoked(r.Context(), req.UserID, req.TargetID, req.ASGID, req.Protocol)
	}
	h.record(r, audit.AccessRequestRevoke, req, more)
	httpx.WriteJSON(w, http.StatusOK, req)
}
