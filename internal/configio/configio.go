// SPDX-License-Identifier: Apache-2.0

package configio

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sort"
	"strings"
)

// api is the gateway's API, called in process with a request's context:
// the importing administrator's sign-in, roles and step-up.
type api struct {
	h   http.Handler
	ctx context.Context
	// remote is the importing administrator's address, which every change's
	// audit event names (the context's own, set by RealIP, comes first).
	remote string
}

// call sends one request and returns its status and body.
func (a api) call(method, path string, body any) (int, []byte, error) {
	var rd *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequestWithContext(a.ctx, method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	if a.remote != "" {
		req.RemoteAddr = a.remote
	}
	rr := httptest.NewRecorder()
	a.h.ServeHTTP(rr, req)
	return rr.Code, rr.Body.Bytes(), nil
}

// all reads every page of a list route into items.
func all[T any](a api, path string) ([]T, error) {
	var out []T
	cursor := ""
	for {
		q := url.Values{"limit": {"500"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		code, body, err := a.call(http.MethodGet, path+sep+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		if code != http.StatusOK {
			return nil, fmt.Errorf("reading %s: %d %s", path, code, strings.TrimSpace(string(body)))
		}
		var page struct {
			Items []T    `json:"items"`
			Next  string `json:"next_cursor"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		out = append(out, page.Items...)
		if page.Next == "" || page.Next == cursor {
			return out, nil
		}
		cursor = page.Next
	}
}

// The API's shapes, as much of them as this package reads.
type (
	apiNamed struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Username string `json:"username"`
	}
	apiGroup struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	apiTarget struct {
		ID              string            `json:"id"`
		Name            string            `json:"name"`
		Address         string            `json:"address"`
		OSFamily        string            `json:"os_family"`
		Engine          string            `json:"engine"`
		EngineVersion   string            `json:"engine_version"`
		DatabaseName    string            `json:"database_name"`
		TLSMode         string            `json:"tls_mode"`
		TLSCA           string            `json:"tls_ca"`
		AppUpstream     string            `json:"app_upstream"`
		AppEndpoints    []Endpoint        `json:"app_endpoints"`
		AppDependencies string            `json:"app_dependencies"`
		Ports           map[string]int    `json:"ports"`
		Capabilities    []string          `json:"capabilities"`
		Tags            map[string]string `json:"tags"`
		Status          string            `json:"status"`
		Notes           string            `json:"notes"`
		RetentionDays   *int              `json:"retention_days"`
		Credentials     map[string]string `json:"credentials"`
	}
	apiSubject struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	}
	apiGrantTarget struct {
		ID        string   `json:"id"`
		Protocols []string `json:"protocols"`
	}
	apiGrant struct {
		ID                 string           `json:"id,omitempty"`
		Kind               string           `json:"kind"`
		Targets            []apiGrantTarget `json:"targets"`
		Tags               *TagMatch        `json:"tags,omitempty"`
		Access             string           `json:"access"`
		SignIn             string           `json:"sign_in"`
		RequireMFA         bool             `json:"require_mfa"`
		AllowClipboard     bool             `json:"allow_clipboard"`
		AllowFileTransfer  bool             `json:"allow_file_transfer"`
		AllowDevTools      bool             `json:"allow_devtools"`
		IdleTimeoutMinutes int              `json:"idle_timeout_minutes"`
		MaxSessionMinutes  *int             `json:"max_session_minutes"`
		TimeWindows        []TimeWindow     `json:"time_windows"`
		RetentionDays      *int             `json:"retention_days"`
	}
	apiPolicy struct {
		ID          string       `json:"id,omitempty"`
		Name        string       `json:"name"`
		Description string       `json:"description"`
		Enabled     bool         `json:"enabled"`
		Subjects    []apiSubject `json:"subjects"`
		Grants      []apiGrant   `json:"grants"`
	}
)

// state is the gateway's configuration as the API gives it, with the maps
// that turn names into ids and back.
type state struct {
	users, credentials, asgs map[string]string // name -> id
	groups                   map[string]apiGroup
	members                  map[string][]string // group id -> usernames, sorted
	targets                  map[string]apiTarget
	policies                 map[string]apiPolicy
	byID                     map[string]string // any id -> its name
}

func read(a api) (*state, error) {
	s := &state{users: map[string]string{}, credentials: map[string]string{}, asgs: map[string]string{}, groups: map[string]apiGroup{},
		members: map[string][]string{}, targets: map[string]apiTarget{}, policies: map[string]apiPolicy{}, byID: map[string]string{}}
	users, err := all[apiNamed](a, "/api/v1/users")
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		s.users[u.Username], s.byID[u.ID] = u.ID, u.Username
	}
	for _, path := range []string{"/api/v1/credentials", "/api/v1/autoscaling-groups"} {
		items, err := all[apiNamed](a, path)
		if err != nil {
			return nil, err
		}
		for _, it := range items {
			if path == "/api/v1/credentials" {
				s.credentials[it.Name] = it.ID
			} else {
				s.asgs[it.Name] = it.ID
			}
			s.byID[it.ID] = it.Name
		}
	}
	groups, err := all[apiGroup](a, "/api/v1/groups")
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		s.groups[g.Name], s.byID[g.ID] = g, g.Name
		ms, err := all[apiNamed](a, "/api/v1/groups/"+url.PathEscape(g.ID)+"/members")
		if err != nil {
			return nil, err
		}
		names := []string{}
		for _, m := range ms {
			names = append(names, m.Username)
		}
		sort.Strings(names)
		s.members[g.ID] = names
	}
	targets, err := all[apiTarget](a, "/api/v1/targets")
	if err != nil {
		return nil, err
	}
	for _, t := range targets {
		s.targets[t.Name], s.byID[t.ID] = t, t.Name
	}
	policies, err := all[apiPolicy](a, "/api/v1/access-policies")
	if err != nil {
		return nil, err
	}
	for _, p := range policies {
		s.policies[p.Name] = p
	}
	return s, nil
}

// export is the state as a Document, every list by name.
func (s *state) export() Document {
	d := Document{Zanskar: Version}
	for _, name := range slices.Sorted(maps.Keys(s.groups)) {
		g := s.groups[name]
		d.Groups = append(d.Groups, Group{Name: g.Name, Description: g.Description, Members: s.members[g.ID]})
	}
	for _, name := range slices.Sorted(maps.Keys(s.targets)) {
		d.Targets = append(d.Targets, s.targetDoc(s.targets[name]))
	}
	for _, name := range slices.Sorted(maps.Keys(s.policies)) {
		d.Policies = append(d.Policies, s.policyDoc(s.policies[name]))
	}
	return d
}

func emptyNil[M ~map[K]V, K comparable, V any](m M) M {
	if len(m) == 0 {
		return nil
	}
	return m
}

func (s *state) targetDoc(t apiTarget) Target {
	creds := map[string]string{}
	for proto, id := range t.Credentials {
		creds[proto] = s.byID[id]
	}
	return Target{Name: t.Name, Address: t.Address, OSFamily: t.OSFamily, Engine: t.Engine, EngineVersion: t.EngineVersion, DatabaseName: t.DatabaseName,
		TLSMode: t.TLSMode, TLSCA: t.TLSCA, AppUpstream: t.AppUpstream, AppEndpoints: t.AppEndpoints, AppDependencies: t.AppDependencies, Ports: emptyNil(t.Ports), Tags: emptyNil(t.Tags),
		Status: t.Status, Notes: t.Notes, RetentionDays: t.RetentionDays, Credentials: emptyNil(creds)}
}

func (s *state) policyDoc(p apiPolicy) Policy {
	out := Policy{Name: p.Name, Description: p.Description, Enabled: p.Enabled}
	for _, sub := range p.Subjects {
		if sub.Kind == "group" {
			out.Subjects = append(out.Subjects, Subject{Group: s.byID[sub.ID]})
		} else {
			out.Subjects = append(out.Subjects, Subject{User: s.byID[sub.ID]})
		}
	}
	for _, g := range p.Grants {
		dg := Grant{Kind: g.Kind, Tags: g.Tags, Access: g.Access, SignIn: g.SignIn, RequireMFA: g.RequireMFA, AllowClipboard: g.AllowClipboard,
			AllowFileTransfer: g.AllowFileTransfer, AllowDevTools: g.AllowDevTools, IdleTimeoutMinutes: g.IdleTimeoutMinutes,
			MaxSessionMinutes: g.MaxSessionMinutes, TimeWindows: g.TimeWindows, RetentionDays: g.RetentionDays}
		for _, gt := range g.Targets {
			dg.Targets = append(dg.Targets, GrantTarget{Name: s.byID[gt.ID], Protocols: gt.Protocols})
		}
		out.Grants = append(out.Grants, dg)
	}
	return out
}

// Change is one thing an import does, or would.
type Change struct {
	Kind   string `json:"kind"` // group, target, policy
	Name   string `json:"name"`
	Action string `json:"action"` // create, update, unchanged
	// Problem says why the change cannot be made; any problem stops an
	// import before it changes anything.
	Problem string `json:"problem,omitempty"`
	// Error is the API's refusal of a change being applied.
	Error   string `json:"error,omitempty"`
	Applied bool   `json:"applied,omitempty"`
}

// writeTarget is a Target as the target API takes it, credentials by id.
func (s *state) writeTarget(t Target) (map[string]any, string) {
	creds := map[string]string{}
	for proto, name := range t.Credentials {
		id, ok := s.credentials[name]
		if !ok {
			return nil, fmt.Sprintf("credential %q does not exist on this gateway; add it first", name)
		}
		creds[proto] = id
	}
	status := t.Status
	if status == "" {
		status = "active"
	}
	return map[string]any{"name": t.Name, "address": t.Address, "os_family": t.OSFamily, "engine": t.Engine, "engine_version": t.EngineVersion,
		"database_name": t.DatabaseName, "tls_mode": t.TLSMode, "tls_ca": t.TLSCA, "app_upstream": t.AppUpstream, "app_endpoints": t.AppEndpoints, "app_dependencies": t.AppDependencies,
		"ports": t.Ports, "tags": t.Tags, "status": status, "notes": t.Notes, "retention_days": t.RetentionDays, "credentials": creds}, ""
}

// writePolicy is a Policy as the policy API takes it, every name an id;
// grants of an existing policy keep their ids where the kind matches by
// position, so the access requests that point at them stay valid.
func (s *state) writePolicy(p Policy, old *apiPolicy) (apiPolicy, string) {
	out := apiPolicy{Name: p.Name, Description: p.Description, Enabled: p.Enabled, Subjects: []apiSubject{}, Grants: []apiGrant{}}
	for _, sub := range p.Subjects {
		switch {
		case sub.Group != "" && sub.User == "":
			g, ok := s.groups[sub.Group]
			if !ok {
				return out, fmt.Sprintf("group %q does not exist", sub.Group)
			}
			out.Subjects = append(out.Subjects, apiSubject{Kind: "group", ID: g.ID})
		case sub.User != "" && sub.Group == "":
			id, ok := s.users[sub.User]
			if !ok {
				return out, fmt.Sprintf("user %q does not exist on this gateway", sub.User)
			}
			out.Subjects = append(out.Subjects, apiSubject{Kind: "user", ID: id})
		default:
			return out, "a subject names exactly one of group or user"
		}
	}
	for i, g := range p.Grants {
		// A file from 1.15.0 may ask for four eyes, which 1.16.0 removed: said,
		// not dropped in silence.
		if g.RequireWatcher {
			return out, fmt.Sprintf("grant %d asks for a second person watching (four eyes), which was removed in 1.16.0; take require_watcher out", i+1)
		}
		ag := apiGrant{Kind: g.Kind, Targets: []apiGrantTarget{}, Tags: g.Tags, Access: g.Access, SignIn: g.SignIn, RequireMFA: g.RequireMFA,
			AllowClipboard: g.AllowClipboard, AllowFileTransfer: g.AllowFileTransfer, AllowDevTools: g.AllowDevTools,
			IdleTimeoutMinutes: g.IdleTimeoutMinutes, MaxSessionMinutes: g.MaxSessionMinutes, TimeWindows: g.TimeWindows, RetentionDays: g.RetentionDays}
		if ag.TimeWindows == nil {
			ag.TimeWindows = []TimeWindow{}
		}
		if old != nil && i < len(old.Grants) && old.Grants[i].Kind == g.Kind {
			ag.ID = old.Grants[i].ID
		}
		for _, gt := range g.Targets {
			var id string
			var ok bool
			if g.Kind == "autoscaling" {
				id, ok = s.asgs[gt.Name]
			} else {
				var t apiTarget
				t, ok = s.targets[gt.Name]
				id = t.ID
			}
			if !ok {
				return out, fmt.Sprintf("grant %d names %q, which does not exist", i+1, gt.Name)
			}
			ag.Targets = append(ag.Targets, apiGrantTarget{ID: id, Protocols: gt.Protocols})
		}
		out.Grants = append(out.Grants, ag)
	}
	return out, ""
}
