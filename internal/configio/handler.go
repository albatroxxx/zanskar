// SPDX-License-Identifier: Apache-2.0

package configio

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/user"
)

// maxFile bounds an imported file.
const maxFile = 2 << 20

// Handler serves /api/v1/admin/config (ADR 0043).
type Handler struct {
	// API is the gateway's own routes, which every read and change goes
	// through; set by the server once they are all registered (UseMux).
	API   http.Handler
	Audit *audit.Log
	Log   *slog.Logger
}

// UseMux gives the handler the routes it calls.
func (h *Handler) UseMux(m http.Handler) { h.API = m }

// Register mounts the routes.
func (h *Handler) Register(mux *http.ServeMux) {
	admin := auth.RequireRole(user.RoleAdmin)
	mux.Handle("GET /api/v1/admin/config/export", admin(http.HandlerFunc(h.export)))
	mux.Handle("POST /api/v1/admin/config/import", admin(http.HandlerFunc(h.importConfig)))
}

func (h *Handler) record(r *http.Request, action string, details map[string]any) {
	auth.Recorder{Audit: h.Audit, Log: h.Log}.Record(r, auth.ActorFor(r).Event(action, "gateway", "", audit.Success, details))
}

// export answers GET /api/v1/admin/config/export: the configuration as a
// YAML file, references by name, no secrets.
func (h *Handler) export(w http.ResponseWriter, r *http.Request) {
	s, err := read(api{h.API, r.Context(), r.RemoteAddr})
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	d := s.export()
	d.ExportedAt = time.Now().UTC().Format(time.RFC3339)
	var b bytes.Buffer
	b.WriteString("# Zanskar configuration (ADR 0043): groups, hosts, databases, applications and access\n")
	b.WriteString("# policies, by name. Secrets are not here; credentials are named and must exist where\n")
	b.WriteString("# this is imported. Import it from Settings, or POST it to /api/v1/admin/config/import.\n")
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(d); err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	_ = enc.Close()
	h.record(r, audit.ConfigExport, map[string]any{"groups": len(d.Groups), "targets": len(d.Targets), "policies": len(d.Policies)})
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="zanskar-config-%s.yaml"`, time.Now().UTC().Format("2006-01-02")))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b.Bytes())
}

// importResult is what an import answers: every change and whether it ran.
type importResult struct {
	Applied bool     `json:"applied"`
	Changes []Change `json:"changes"`
}

// importConfig answers POST /api/v1/admin/config/import: the plan of what
// the file would change (the default), or with ?apply=true the changes
// made, in order: groups, then targets, then policies. Any problem in the
// plan (a name that does not exist, a malformed subject) stops it before it
// changes anything; a change the API then refuses stops the rest, and the
// answer says which ran.
func (h *Handler) importConfig(w http.ResponseWriter, r *http.Request) {
	apply := r.URL.Query().Get("apply") == "true"
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxFile+1))
	if err != nil || len(raw) > maxFile {
		httpx.BadRequest(w, r, "the file must be YAML of at most 2 MiB")
		return
	}
	var d Document
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		httpx.BadRequest(w, r, "not a Zanskar configuration file: "+err.Error())
		return
	}
	if d.Zanskar != Version {
		httpx.BadRequest(w, r, fmt.Sprintf("zanskar: this gateway reads version %d files", Version))
		return
	}
	a := api{h.API, r.Context(), r.RemoteAddr}
	s, err := read(a)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	changes := plan(s, d)
	res := importResult{Changes: changes}
	problems := 0
	for _, c := range changes {
		if c.Problem != "" {
			problems++
		}
	}
	if !apply {
		httpx.WriteJSON(w, http.StatusOK, res)
		return
	}
	if problems > 0 {
		httpx.WriteJSON(w, http.StatusUnprocessableEntity, res)
		return
	}
	res.Applied = true
	res.Changes = h.run(a, s, d, changes)
	n := map[string]int{}
	for _, c := range res.Changes {
		if c.Applied {
			n[c.Kind+"s"]++
		}
	}
	h.record(r, audit.ConfigImport, map[string]any{"changed": n, "failed": failed(res.Changes)})
	status := http.StatusOK
	if failed(res.Changes) != "" {
		status = http.StatusConflict
	}
	httpx.WriteJSON(w, status, res)
}

func failed(cs []Change) string {
	for _, c := range cs {
		if c.Error != "" {
			return c.Kind + " " + c.Name
		}
	}
	return ""
}

// yamlOf is a value's YAML, the form two views of a thing are compared in.
func yamlOf(v any) string {
	b, _ := yaml.Marshal(v)
	return string(b)
}

// plan says what d would change against s, and what stops it.
func plan(s *state, d Document) []Change {
	var out []Change
	seen := map[string]bool{}
	// Names this file creates count as existing for what it names later.
	future := &state{users: s.users, credentials: s.credentials, asgs: s.asgs, groups: map[string]apiGroup{}, targets: map[string]apiTarget{},
		members: s.members, byID: s.byID, policies: s.policies}
	for k, v := range s.groups {
		future.groups[k] = v
	}
	for k, v := range s.targets {
		future.targets[k] = v
	}
	for _, g := range d.Groups {
		c := Change{Kind: "group", Name: g.Name}
		key := "group:" + g.Name
		if seen[key] || strings.TrimSpace(g.Name) == "" {
			c.Problem = "a group needs a name, once"
		}
		seen[key] = true
		for _, m := range g.Members {
			if _, ok := s.users[m]; !ok && c.Problem == "" {
				c.Problem = fmt.Sprintf("member %q does not exist on this gateway", m)
			}
		}
		old, exists := s.groups[g.Name]
		switch {
		case !exists:
			c.Action = "create"
			future.groups[g.Name] = apiGroup{ID: "(new)", Name: g.Name}
		case old.Description == g.Description && yamlOf(s.members[old.ID]) == yamlOf(sorted(g.Members)):
			c.Action = "unchanged"
		default:
			c.Action = "update"
		}
		out = append(out, c)
	}
	for _, t := range d.Targets {
		c := Change{Kind: "target", Name: t.Name}
		key := "target:" + t.Name
		if seen[key] || strings.TrimSpace(t.Name) == "" {
			c.Problem = "a target needs a name, once"
		}
		seen[key] = true
		if _, p := s.writeTarget(t); p != "" && c.Problem == "" {
			c.Problem = p
		}
		old, exists := s.targets[t.Name]
		switch {
		case !exists:
			c.Action = "create"
			future.targets[t.Name] = apiTarget{ID: "(new)", Name: t.Name}
		case yamlOf(s.targetDoc(old)) == yamlOf(withDefaults(t)):
			c.Action = "unchanged"
		default:
			c.Action = "update"
		}
		out = append(out, c)
	}
	for _, p := range d.Policies {
		c := Change{Kind: "policy", Name: p.Name}
		key := "policy:" + p.Name
		if seen[key] || strings.TrimSpace(p.Name) == "" {
			c.Problem = "a policy needs a name, once"
		}
		seen[key] = true
		old, exists := s.policies[p.Name]
		var oldp *apiPolicy
		if exists {
			oldp = &old
		}
		if _, prob := future.writePolicy(p, oldp); prob != "" && c.Problem == "" {
			c.Problem = prob
		}
		switch {
		case !exists:
			c.Action = "create"
		case yamlOf(s.policyDoc(old)) == yamlOf(p):
			c.Action = "unchanged"
		default:
			c.Action = "update"
		}
		out = append(out, c)
	}
	return out
}

func sorted(xs []string) []string {
	out := append([]string{}, xs...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// withDefaults fills what a file may leave out and an export writes.
func withDefaults(t Target) Target {
	if t.Status == "" {
		t.Status = "active"
	}
	if t.KubeAPIServer != "" {
		// A cluster's row says which way its sessions act and how its
		// token is minted (target.Target); a file may leave the defaults out.
		if t.KubePlatform == "" {
			t.KubePlatform = "vanilla"
		}
		if t.KubeImpersonate == nil {
			on := true
			t.KubeImpersonate = &on
		}
	}
	return t
}

// run applies the planned changes through the API, in order, stopping at
// the first the API refuses. Targets are read again before the policies,
// which name the ones this import created.
func (h *Handler) run(a api, s *state, d Document, plan []Change) []Change {
	out := append([]Change{}, plan...)
	at := func(kind, name string) int {
		for i, c := range out {
			if c.Kind == kind && c.Name == name {
				return i
			}
		}
		return -1
	}
	do := func(i int, method, path string, body any) bool {
		code, resp, err := a.call(method, path, body)
		if err != nil || code < 200 || code > 299 {
			var e struct {
				Message string `json:"message"`
			}
			_ = json.Unmarshal(resp, &e)
			if e.Message == "" {
				e.Message = fmt.Sprintf("%d", code)
			}
			out[i].Error = e.Message
			return false
		}
		out[i].Applied = true
		return true
	}
	userIDs := func(names []string) []string {
		ids := []string{}
		for _, n := range names {
			ids = append(ids, s.users[n])
		}
		return ids
	}
	for _, g := range d.Groups {
		i := at("group", g.Name)
		switch out[i].Action {
		case "create":
			if !do(i, http.MethodPost, "/api/v1/groups", map[string]any{"name": g.Name, "description": g.Description, "user_ids": userIDs(g.Members)}) {
				return out
			}
		case "update":
			id := url.PathEscape(s.groups[g.Name].ID)
			if !do(i, http.MethodPut, "/api/v1/groups/"+id, map[string]any{"name": g.Name, "description": g.Description}) ||
				!do(i, http.MethodPut, "/api/v1/groups/"+id+"/members", map[string]any{"user_ids": userIDs(g.Members)}) {
				return out
			}
		}
	}
	for _, t := range d.Targets {
		i := at("target", t.Name)
		body, _ := s.writeTarget(t)
		switch out[i].Action {
		case "create":
			if !do(i, http.MethodPost, "/api/v1/targets", body) {
				return out
			}
		case "update":
			if !do(i, http.MethodPut, "/api/v1/targets/"+url.PathEscape(s.targets[t.Name].ID), body) {
				return out
			}
		}
	}
	// What this import created has ids now.
	fresh, err := read(a)
	if err != nil {
		for _, p := range d.Policies {
			out[at("policy", p.Name)].Error = "the configuration could not be read again: " + err.Error()
		}
		return out
	}
	for _, p := range d.Policies {
		i := at("policy", p.Name)
		if out[i].Action == "unchanged" {
			continue
		}
		old, exists := fresh.policies[p.Name]
		var oldp *apiPolicy
		if exists {
			oldp = &old
		}
		body, prob := fresh.writePolicy(p, oldp)
		if prob != "" {
			out[i].Error = prob
			return out
		}
		if exists {
			if !do(i, http.MethodPut, "/api/v1/access-policies/"+url.PathEscape(old.ID), body) {
				return out
			}
		} else if !do(i, http.MethodPost, "/api/v1/access-policies", body) {
			return out
		}
	}
	return out
}
