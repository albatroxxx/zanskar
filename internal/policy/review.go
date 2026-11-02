// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
)

// ReviewDue is how long a policy's access review stands before the console
// calls it due (ADR 0040): a quarter, the common rhythm of SOC 2 and ISO
// 27001 user-access reviews.
const ReviewDue = 90 * 24 * time.Hour

// Person is someone a policy covers, named.
type Person struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
}

// Directory names the people behind a policy's subjects for a review.
type Directory interface {
	// UserName is a user's username, or "" when gone.
	UserName(ctx context.Context, id string) (string, error)
	// Group is a group's name and its members.
	Group(ctx context.Context, id string) (string, []Person, error)
}

// reviewPerson is one person in a review, with their last session under
// the policy.
type reviewPerson struct {
	Person
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// reviewSubject is one subject of the policy as a review shows it: who it
// is, the people it brings, and the last time any of them used the policy.
type reviewSubject struct {
	Subject
	Name       string         `json:"name"`
	People     []reviewPerson `json:"people"`
	LastUsedAt *time.Time     `json:"last_used_at,omitempty"`
}

type reviewView struct {
	Policy   *Policy         `json:"policy"`
	Subjects []reviewSubject `json:"subjects"`
	// ReviewerName names who last reviewed it.
	ReviewerName string `json:"reviewer_name,omitempty"`
	// Due says the review is older than ReviewDue, or was never made.
	Due bool `json:"due"`
}

// review answers GET /api/v1/access-policies/{id}/review: who the policy
// covers, person by person, and when each last used it (ADR 0040).
func (h *AdminHandler) review(w http.ResponseWriter, r *http.Request) {
	v, err := h.reviewOf(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (h *AdminHandler) reviewOf(ctx context.Context, id string) (*reviewView, error) {
	p, err := h.Repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	used, err := h.Repo.LastUse(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	at := func(uid string) *time.Time {
		if t, ok := used[uid]; ok {
			return &t
		}
		return nil
	}
	v := &reviewView{Policy: p, Subjects: []reviewSubject{}, Due: p.ReviewedAt == nil || time.Since(*p.ReviewedAt) > ReviewDue}
	for _, s := range p.Subjects {
		rs := reviewSubject{Subject: s, People: []reviewPerson{}}
		var people []Person
		if h.Directory != nil {
			switch s.Kind {
			case SubjectUser:
				name, err := h.Directory.UserName(ctx, s.ID)
				if err != nil {
					return nil, err
				}
				rs.Name, people = name, []Person{{UserID: s.ID, Username: name}}
			case SubjectGroup:
				name, members, err := h.Directory.Group(ctx, s.ID)
				if err != nil {
					return nil, err
				}
				rs.Name, people = name, members
			}
		}
		for _, person := range people {
			rp := reviewPerson{Person: person, LastUsedAt: at(person.UserID)}
			if rp.LastUsedAt != nil && (rs.LastUsedAt == nil || rp.LastUsedAt.After(*rs.LastUsedAt)) {
				rs.LastUsedAt = rp.LastUsedAt
			}
			rs.People = append(rs.People, rp)
		}
		v.Subjects = append(v.Subjects, rs)
	}
	if p.ReviewedBy != "" && h.Directory != nil {
		v.ReviewerName, _ = h.Directory.UserName(ctx, p.ReviewedBy)
	}
	return v, nil
}

type reviewInput struct {
	// Remove are the subjects that no longer need the policy; every other
	// subject is kept.
	Remove []Subject `json:"remove"`
	Note   string    `json:"note"`
}

// completeReview answers POST /api/v1/access-policies/{id}/review: the
// administrator's decisions. Subjects to remove leave the policy, and the
// live sessions they no longer have a grant for end, as an edit's would;
// the policy is stamped reviewed; and one policy.review event says who was
// kept, who removed, and why (ADR 0040).
func (h *AdminHandler) completeReview(w http.ResponseWriter, r *http.Request) {
	var in reviewInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.BadRequest(w, r, err.Error())
		return
	}
	in.Note = strings.TrimSpace(in.Note)
	if len(in.Note) > 2000 {
		httpx.BadRequest(w, r, "note: at most 2000 characters")
		return
	}
	old, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	for _, s := range in.Remove {
		if !slices.Contains(old.Subjects, s) {
			httpx.WriteError(w, r, http.StatusUnprocessableEntity, "unknown_subject", "remove: "+s.Kind+" "+s.ID+" is not a subject of this policy")
			return
		}
	}
	kept := slices.DeleteFunc(slices.Clone(old.Subjects), func(s Subject) bool { return slices.Contains(in.Remove, s) })
	more := map[string]any{"kept": kept, "removed": in.Remove, "note": in.Note, "name": old.Name}
	p := old
	if len(in.Remove) > 0 {
		p = &Policy{ID: old.ID, Name: old.Name, Description: old.Description, Enabled: old.Enabled, Subjects: kept, Grants: old.Grants,
			CreatedBy: old.CreatedBy, CreatedAt: old.CreatedAt}
		if err := h.Repo.Update(r.Context(), p); err != nil {
			h.fail(w, r, err)
			return
		}
		if n, ok := h.recheck(r.Context(), old.Subjects); ok {
			more["live_sessions_ended"] = n
		}
	}
	reviewer, _ := auth.FromContext(r.Context())
	if err := h.Repo.Reviewed(r.Context(), p.ID, reviewer.User.ID, time.Now().UTC()); err != nil {
		h.fail(w, r, err)
		return
	}
	auth.Recorder{Audit: h.Audit, Log: h.Log}.Record(r, auth.ActorFor(r).Event(audit.PolicyReview, "access_policy", p.ID, audit.Success, more))
	v, err := h.reviewOf(r.Context(), p.ID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}
