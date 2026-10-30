// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/policy"
	"github.com/albatroxxx/zanskar/internal/protocol"
)

// command is one row of the command table. Every command maps to existing
// API routes; the command line never grows a feature of its own (ADR 0027).
type command struct {
	name    string   // "user show"
	group   string   // section in help and the reference
	args    []string // positional placeholders, e.g. "<name>"
	rest    string   // optional trailing free text, e.g. "[note]"
	flags   []flag
	summary string
	example string
	// plan, when set, makes the command destructive: it describes what will
	// happen and names the word the administrator must type to go ahead.
	plan func(x *run) (prompt, expect string, err error)
	exec func(x *run) error
}

type flag struct {
	name  string
	value string // placeholder; empty for a switch
	help  string
}

func (c *command) flagNamed(name string) *flag {
	for i := range c.flags {
		if c.flags[i].name == name {
			return &c.flags[i]
		}
	}
	return nil
}

func (c *command) usage() string {
	parts := []string{c.name}
	parts = append(parts, c.args...)
	if c.rest != "" {
		parts = append(parts, c.rest)
	}
	for _, f := range c.flags {
		if f.value == "" {
			parts = append(parts, "[--"+f.name+"]")
		} else {
			parts = append(parts, "[--"+f.name+" "+f.value+"]")
		}
	}
	return strings.Join(parts, " ")
}

// run is one execution of a command.
type run struct {
	parsed
	api *caller
	out *out
	now time.Time
	// ids resolved by plan, reused by exec so both act on the same object.
	resolved map[string]string
	// cmds is the whole table, for help.
	cmds []*command
}

// usageError marks an error in what was typed, as opposed to one from the API.
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usagef(format string, a ...any) error { return usageError{fmt.Sprintf(format, a...)} }

// ---- the table

func commands() []*command {
	return []*command{
		{name: "help", group: "General", rest: "[command]", summary: "List the commands, or show how to use one.", example: "help user disable", exec: cmdHelp},
		{name: "status", group: "General", summary: "Gateway health, audit chain, live sessions and waiting requests.", example: "status", exec: cmdStatus},
		{name: "version", group: "General", summary: "The gateway's version.", example: "version", exec: cmdVersion},

		{name: "sessions", group: "Sessions", flags: []flag{{"live", "", "only sessions still open"}, {"user", "<username>", "one user's sessions"}, {"target", "<name>", "sessions to one target"}, {"last", "<n>", "how many, newest first (default 20)"}},
			summary: "Sessions through the gateway, newest first.", example: "sessions --live", exec: cmdSessions},
		{name: "session show", group: "Sessions", args: []string{"<id>"}, summary: "One session in full. The id can be the first 8 characters shown by sessions.", example: "session show 3f9a1c20", exec: cmdSessionShow},
		{name: "session terminate", group: "Sessions", args: []string{"<id>"}, summary: "End a live session now. Its recording stops at that moment.", example: "session terminate 3f9a1c20", plan: planSessionTerminate, exec: cmdSessionTerminate},

		{name: "users", group: "Users", flags: []flag{{"role", "<role>", "admin, auditor or user"}}, summary: "People who can sign in.", example: "users --role admin", exec: cmdUsers},
		{name: "user show", group: "Users", args: []string{"<username>"}, summary: "One user in full.", example: "user show alice", exec: cmdUserShow},
		{name: "user disable", group: "Users", args: []string{"<username>"}, summary: "Stop a user signing in, and sign them out everywhere.", example: "user disable alice", plan: planUser("disable"), exec: cmdUserStatus("disabled")},
		{name: "user enable", group: "Users", args: []string{"<username>"}, summary: "Let a disabled user sign in again.", example: "user enable alice", exec: cmdUserStatus("active")},
		{name: "user reset-mfa", group: "Users", args: []string{"<username>"}, summary: "Remove a user's authenticator; they enrol a new one at next sign-in.", example: "user reset-mfa alice", plan: planUser("reset-mfa"), exec: cmdUserResetMFA},
		{name: "user signout", group: "Users", args: []string{"<username>"}, summary: "End all of a user's console sign-ins.", example: "user signout alice", plan: planUser("signout"), exec: cmdUserSignout},

		{name: "targets", group: "Targets", flags: []flag{{"tag", "<key=value>", "only targets with this tag"}, {"search", "<text>", "name or address contains"}}, summary: "Hosts and databases the gateway can reach.", example: "targets --tag env=prod", exec: cmdTargets},
		{name: "target show", group: "Targets", args: []string{"<name>"}, summary: "One target in full.", example: "target show web-01", exec: cmdTargetShow},
		{name: "target probe", group: "Targets", args: []string{"<name>"}, summary: "Connect to a target to learn what it offers. Trust is not changed.", example: "target probe web-01", exec: cmdTargetProbe},

		{name: "policies", group: "Access", summary: "Access policies.", example: "policies", exec: cmdPolicies},
		{name: "policy show", group: "Access", args: []string{"<name>"}, summary: "One policy in full.", example: "policy show prod-db-jit", exec: cmdPolicyShow},
		{name: "requests", group: "Access", flags: []flag{{"pending", "", "only requests waiting for a decision"}}, summary: "Access requests, newest first.", example: "requests --pending", exec: cmdRequests},
		{name: "request approve", group: "Access", args: []string{"<id>"}, rest: "[note]", summary: "Approve a request; the note is shown to the requester.", example: "request approve 9c1d2e3f ok for the incident", exec: cmdDecide("approve")},
		{name: "request deny", group: "Access", args: []string{"<id>"}, rest: "[note]", summary: "Deny a request; the note is shown to the requester.", example: "request deny 9c1d2e3f use the staging copy", exec: cmdDecide("deny")},
		{name: "request revoke", group: "Access", args: []string{"<id>"}, summary: "Withdraw an approved request before it expires.", example: "request revoke 9c1d2e3f", plan: planRevoke, exec: cmdDecide("revoke")},

		{name: "events", group: "Audit", flags: []flag{{"user", "<username>", "events by one person"}, {"action", "<action>", "one kind of event, e.g. session.start"}, {"last", "<n>", "how many, newest first (default 20)"}}, summary: "The audit log, newest first.", example: "events --user alice --last 10", exec: cmdEvents},
		{name: "audit verify", group: "Audit", summary: "Walk the hash chain and check that no event was altered or removed.", example: "audit verify", exec: cmdAuditVerify},

		{name: "logs", group: "Gateway", flags: []flag{{"last", "<n>", "how many lines (default 30)"}, {"level", "<level>", "debug, info, warn or error and above"}, {"search", "<text>", "lines containing this"}}, summary: "The gateway's recent log.", example: "logs --level warn", exec: cmdLogs},
		{name: "tls", group: "Gateway", summary: "How the gateway serves HTTPS and the certificate in use.", example: "tls", exec: cmdTLS},
		{name: "storage", group: "Gateway", summary: "Where recordings are kept.", example: "storage", exec: cmdStorage},
		{name: "storage test", group: "Gateway", summary: "Write and read back a test object in the recordings store.", example: "storage test", exec: cmdStorageTest},
		{name: "settings", group: "Gateway", summary: "Runtime settings and where each value comes from.", example: "settings", exec: cmdSettings},
		{name: "setting get", group: "Gateway", args: []string{"<key>"}, summary: "One setting in full.", example: "setting get log.level", exec: cmdSettingGet},
		{name: "setting set", group: "Gateway", args: []string{"<key>"}, rest: "<value>", summary: "Change a runtime setting. Secrets are never set here.", example: "setting set log.level debug", plan: planSettingSet, exec: cmdSettingSet},
		{name: "restart", group: "Gateway", flags: []flag{{"wait", "<minutes>", "how long live sessions may finish first; 0 ends them now (default 15)"}}, summary: "Restart the gateway once live sessions end, as the console does.", example: "restart --wait 5", plan: planRestart, exec: cmdRestart},
		{name: "restart cancel", group: "Gateway", summary: "Cancel a restart that is waiting for sessions to end.", example: "restart cancel", exec: cmdRestartCancel},

		{name: "asgs", group: "Autoscaling", summary: "Autoscaling groups the gateway follows.", example: "asgs", exec: cmdASGs},
		{name: "asg sync", group: "Autoscaling", args: []string{"<name>"}, summary: "Read the group's instances from the cloud now.", example: "asg sync web-fleet", exec: cmdASGSync},
	}
}

// find returns the command named by the first one or two words.
func find(cmds []*command, words []string) (*command, []string) {
	if len(words) >= 2 {
		two := words[0] + " " + words[1]
		for _, c := range cmds {
			if c.name == two {
				return c, words[2:]
			}
		}
	}
	for _, c := range cmds {
		if c.name == words[0] {
			return c, words[1:]
		}
	}
	return nil, nil
}

// ---- resolving names and ids

// listAll pages through a list route.
func (x *run) listAll(path string, maxItems int) ([]obj, error) {
	var items []obj
	cursor := ""
	for len(items) < maxItems {
		u := path
		sep := "?"
		if strings.Contains(u, "?") {
			sep = "&"
		}
		u += sep + "limit=200"
		if cursor != "" {
			u += "&cursor=" + url.QueryEscape(cursor)
		}
		var page struct {
			Items      []obj  `json:"items"`
			NextCursor string `json:"next_cursor"`
		}
		if err := x.api.get(u, &page); err != nil {
			return nil, err
		}
		items = append(items, page.Items...)
		if page.NextCursor == "" || len(page.Items) == 0 {
			break
		}
		cursor = page.NextCursor
	}
	return items, nil
}

// byName finds the item whose nameKey matches (case-insensitively) or whose id
// is exactly s.
func (x *run) byName(kind, path, nameKey, s string) (obj, error) {
	if err := checkName(kind, s); err != nil {
		return nil, usagef("%s", err.Error())
	}
	items, err := x.listAll(path, 5000)
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		if strings.EqualFold(str(it, nameKey), s) || str(it, "id") == s {
			return it, nil
		}
	}
	return nil, usagef("no %s named %q", kind, s)
}

// byIDPrefix finds the item whose id starts with s (at least six characters).
func (x *run) byIDPrefix(kind, path, s string) (obj, error) {
	if err := checkName(kind+" id", s); err != nil {
		return nil, usagef("%s", err.Error())
	}
	if len(s) < 6 {
		return nil, usagef("give at least the first 6 characters of the %s id", kind)
	}
	items, err := x.listAll(path, 5000)
	if err != nil {
		return nil, err
	}
	var hit obj
	for _, it := range items {
		if strings.HasPrefix(str(it, "id"), strings.ToLower(s)) {
			if hit != nil {
				return nil, usagef("%q matches more than one %s; give more of the id", s, kind)
			}
			hit = it
		}
	}
	if hit == nil {
		return nil, usagef("no %s with id %q", kind, s)
	}
	return hit, nil
}

// once resolves a name once per run: plan and exec share the answer.
func (x *run) once(key string, resolve func() (obj, error)) (string, error) {
	if id, ok := x.resolved[key]; ok {
		return id, nil
	}
	it, err := resolve()
	if err != nil {
		return "", err
	}
	x.resolved[key] = str(it, "id")
	x.resolved[key+".label"] = str(it, "username") + str(it, "name")
	return x.resolved[key], nil
}

func (x *run) userID() (string, error) {
	return x.once("user", func() (obj, error) { return x.byName("user", "/users", "username", x.args[0]) })
}

func (x *run) last(def, ceiling int) (int, error) {
	if !x.has("last") {
		return def, nil
	}
	n, err := strconv.Atoi(x.flag("last"))
	if err != nil || n < 1 || n > ceiling {
		return 0, usagef("--last takes a number from 1 to %d", ceiling)
	}
	return n, nil
}

// ---- General

func cmdHelp(x *run) error {
	if x.rest != "" {
		c, _ := find(x.cmds, strings.Fields(x.rest))
		if c == nil {
			return usagef("no command %q; type help to list them", x.rest)
		}
		x.out.addf(styleHead, "%s", c.usage())
		x.out.textf("%s", c.summary)
		for _, f := range c.flags {
			name := "--" + f.name
			if f.value != "" {
				name += " " + f.value
			}
			x.out.textf("  %-22s %s", name, f.help)
		}
		if c.plan != nil {
			x.out.addf(styleMuted, "Asks you to confirm before it runs.")
		}
		x.out.addf(styleMuted, "Example: %s", c.example)
		return nil
	}
	group := ""
	for _, c := range x.cmds {
		if c.group != group {
			if group != "" {
				x.out.textf("")
			}
			group = c.group
			x.out.addf(styleHead, "%s", group)
		}
		x.out.textf("  %-26s %s", c.name+" "+strings.Join(c.args, " "), c.summary)
	}
	x.out.textf("")
	x.out.addf(styleMuted, "Also: clear, history. Type help <command> for its options. This is not a shell: only these commands run.")
	return nil
}

func cmdStatus(x *run) error {
	var st obj
	if err := x.api.get("/admin/system/status", &st); err != nil {
		return err
	}
	line := fmt.Sprintf("healthy · %s · up %s", str(st, "version"), span(time.Duration(num(st, "uptime_seconds"))*time.Second))
	switch {
	case st["draining"] == true:
		line += " · restarting once live sessions end"
	case st["restart_required"] == true:
		line += " · restart needed to apply changed settings"
	}
	var v obj
	if err := x.api.get("/audit/verify", &v); err != nil {
		return err
	}
	auditLine, auditStyle := fmt.Sprintf("chain verified · %d events", num(v, "checked")), styleOK
	if v["intact"] != true {
		auditLine, auditStyle = fmt.Sprintf("CHAIN BROKEN at event %s: run audit verify", str(sub(v, "broken"), "ID")), styleError
		if len(sub(v, "broken")) == 0 {
			auditLine = "PROBLEMS FOUND: run audit verify"
		}
	}
	pending, err := x.listAll("/access-requests?status=pending", 1000)
	if err != nil {
		return err
	}
	x.out.addf("", "%-9s %s", "gateway", line)
	x.out.addf(auditStyle, "%-9s %s", "audit", auditLine)
	x.out.addf("", "%-9s %d live · %d access requests waiting", "sessions", num(st, "live_sessions"), len(pending))
	return nil
}

func cmdVersion(x *run) error {
	var v obj
	if err := x.api.get("/version", &v); err != nil {
		return err
	}
	x.out.textf("Zanskar %s", str(v, "version"))
	return nil
}

// ---- Sessions

func cmdSessions(x *run) error {
	n, err := x.last(20, 500)
	if err != nil {
		return err
	}
	q := url.Values{"limit": {strconv.Itoa(n)}}
	if x.has("live") {
		q.Set("open", "true")
	}
	if u := x.flag("user"); u != "" {
		q.Set("username", u)
	}
	if t := x.flag("target"); t != "" {
		it, err := x.byName("target", "/targets", "name", t)
		if err != nil {
			return err
		}
		q.Set("target_id", str(it, "id"))
	}
	var page struct {
		Items []obj `json:"items"`
	}
	if err := x.api.get("/sessions?"+q.Encode(), &page); err != nil {
		return err
	}
	rows := make([][]string, 0, len(page.Items))
	for _, s := range page.Items {
		state := "live"
		if str(s, "ended_at") != "" {
			state = "ended " + when(s, "ended_at")
		}
		rows = append(rows, []string{short(str(s, "id")), str(s, "username"), str(s, "target_name") + str(s, "asg_name"), protocol.Name(str(s, "protocol")), when(s, "started_at"), state})
	}
	x.out.table([]string{"ID", "USER", "TARGET", "PROTOCOL", "STARTED", "STATE"}, rows)
	return nil
}

func (x *run) session() (obj, error) {
	return x.byIDPrefix("session", "/sessions", x.args[0])
}

func cmdSessionShow(x *run) error {
	s, err := x.session()
	if err != nil {
		return err
	}
	x.out.pairs([][2]string{
		{"id", str(s, "id")}, {"user", str(s, "username")}, {"target", str(s, "target_name") + str(s, "asg_name")},
		{"protocol", protocol.Name(str(s, "protocol"))}, {"from", str(s, "client_ip")}, {"started", when(s, "started_at")},
		{"ended", when(s, "ended_at")}, {"end reason", str(s, "end_reason")}, {"recording", str(s, "recording_id")},
	})
	return nil
}

func planSessionTerminate(x *run) (string, string, error) {
	s, err := x.session()
	if err != nil {
		return "", "", err
	}
	if str(s, "ended_at") != "" {
		return "", "", usagef("session %s has already ended", short(str(s, "id")))
	}
	x.resolved["session"] = str(s, "id")
	return fmt.Sprintf("This ends %s's %s session to %s now. The recording stops at this moment.",
		str(s, "username"), protocol.Name(str(s, "protocol")), str(s, "target_name")+str(s, "asg_name")), str(s, "username"), nil
}

func cmdSessionTerminate(x *run) error {
	id := x.resolved["session"]
	if err := x.api.do(http.MethodPost, pathf("/sessions/%s/terminate", id), map[string]string{"reason": "terminated from the command line"}, nil); err != nil {
		return err
	}
	x.out.addf(styleOK, "✓ Terminated.")
	return nil
}

// ---- Users

func cmdUsers(x *run) error {
	items, err := x.listAll("/users", 5000)
	if err != nil {
		return err
	}
	role := x.flag("role")
	var rows [][]string
	for _, u := range items {
		if role != "" && !strings.Contains(","+strings.ReplaceAll(str(u, "roles"), " ", "")+",", ","+role+",") {
			continue
		}
		rows = append(rows, []string{str(u, "username"), str(u, "display_name"), str(u, "roles"), str(u, "status"), when(u, "last_login_at")})
	}
	x.out.table([]string{"USERNAME", "NAME", "ROLES", "STATUS", "LAST SIGN-IN"}, rows)
	return nil
}

func cmdUserShow(x *run) error {
	id, err := x.userID()
	if err != nil {
		return err
	}
	var u obj
	if err := x.api.get(pathf("/users/%s", id), &u); err != nil {
		return err
	}
	x.out.pairs([][2]string{
		{"username", str(u, "username")}, {"name", str(u, "display_name")}, {"email", str(u, "email")},
		{"roles", str(u, "roles")}, {"status", str(u, "status")}, {"last sign-in", when(u, "last_login_at")},
		{"created", when(u, "created_at")}, {"id", str(u, "id")},
	})
	return nil
}

func planUser(action string) func(x *run) (string, string, error) {
	return func(x *run) (string, string, error) {
		if _, err := x.userID(); err != nil {
			return "", "", err
		}
		name := x.resolved["user.label"]
		switch action {
		case "disable":
			return fmt.Sprintf("This stops %s signing in and ends all of their console sign-ins.", name), name, nil
		case "reset-mfa":
			return fmt.Sprintf("This removes %s's authenticator and recovery codes and signs them out; they enrol a new one at their next sign-in.", name), name, nil
		default:
			return fmt.Sprintf("This ends every console sign-in %s has.", name), name, nil
		}
	}
}

func cmdUserStatus(status string) func(x *run) error {
	return func(x *run) error {
		id, err := x.userID()
		if err != nil {
			return err
		}
		var u obj
		if err := x.api.get(pathf("/users/%s", id), &u); err != nil {
			return err
		}
		// PUT replaces the whole record; carry the current name and email
		// through so changing the status changes nothing else.
		body := map[string]string{"display_name": str(u, "display_name"), "email": str(u, "email"), "status": status}
		if err := x.api.do(http.MethodPut, pathf("/users/%s", id), body, nil); err != nil {
			return err
		}
		x.out.addf(styleOK, "✓ %s is now %s.", str(u, "username"), status)
		return nil
	}
}

func cmdUserResetMFA(x *run) error {
	id, err := x.userID()
	if err != nil {
		return err
	}
	if err := x.api.do(http.MethodDelete, pathf("/users/%s/mfa", id), nil, nil); err != nil {
		return err
	}
	x.out.addf(styleOK, "✓ Authenticator removed for %s.", x.resolved["user.label"])
	return nil
}

func cmdUserSignout(x *run) error {
	id, err := x.userID()
	if err != nil {
		return err
	}
	if err := x.api.do(http.MethodDelete, pathf("/users/%s/sessions", id), nil, nil); err != nil {
		return err
	}
	x.out.addf(styleOK, "✓ %s is signed out everywhere.", x.resolved["user.label"])
	return nil
}

// ---- Targets

func cmdTargets(x *run) error {
	path := "/targets"
	if s := x.flag("search"); s != "" {
		path += "?q=" + url.QueryEscape(s)
	}
	items, err := x.listAll(path, 5000)
	if err != nil {
		return err
	}
	tagK, tagV, wantTag := strings.Cut(x.flag("tag"), "=")
	if x.has("tag") && !wantTag {
		return usagef("--tag takes key=value, for example --tag env=prod")
	}
	var rows [][]string
	for _, t := range items {
		if wantTag && str(sub(t, "tags"), tagK) != tagV {
			continue
		}
		kind := str(t, "os_family")
		if e := str(t, "engine"); e != "" {
			kind = e
		} else if str(t, "app_upstream") != "" {
			kind = "application"
		}
		rows = append(rows, []string{str(t, "name"), str(t, "address"), kind, str(t, "host_key_status"), str(t, "tags")})
	}
	x.out.table([]string{"NAME", "ADDRESS", "KIND", "HOST KEY", "TAGS"}, rows)
	return nil
}

func (x *run) targetID() (string, error) {
	return x.once("target", func() (obj, error) { return x.byName("target", "/targets", "name", x.args[0]) })
}

func cmdTargetShow(x *run) error {
	id, err := x.targetID()
	if err != nil {
		return err
	}
	var t obj
	if err := x.api.get(pathf("/targets/%s", id), &t); err != nil {
		return err
	}
	x.out.pairs([][2]string{
		{"name", str(t, "name")}, {"address", str(t, "address")}, {"os", str(t, "os_family")}, {"engine", str(t, "engine")},
		{"ports", str(t, "ports")}, {"offers", str(t, "capabilities")}, {"host key", str(t, "host_key_status")},
		{"fingerprint", str(t, "host_key_fingerprint")}, {"tags", str(t, "tags")}, {"status", str(t, "status")},
		{"last probed", when(t, "last_probed_at")}, {"notes", str(t, "notes")}, {"id", str(t, "id")},
	})
	return nil
}

func cmdTargetProbe(x *run) error {
	id, err := x.targetID()
	if err != nil {
		return err
	}
	var res obj
	if err := x.api.do(http.MethodPost, pathf("/targets/%s/probe", id), nil, &res); err != nil {
		return err
	}
	x.out.addf(styleOK, "✓ Probed %s.", x.resolved["target.label"])
	keys := make([]string, 0, len(res))
	for k := range res {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	kv := make([][2]string, 0, len(keys))
	for _, k := range keys {
		kv = append(kv, [2]string{strings.ReplaceAll(k, "_", " "), str(res, k)})
	}
	x.out.pairs(kv)
	x.out.addf(styleMuted, "Trust is unchanged; trust a new key or certificate from the console.")
	return nil
}

// ---- Access

// A policy is an audience and a list of grants, each complete with its own
// conditions (ADR 0036). The nested parts are read into the policy package's
// own types, so the command line reads exactly the shape the API sends.

func cmdPolicies(x *run) error {
	items, err := x.listAll("/access-policies", 5000)
	if err != nil {
		return err
	}
	pols := make([]policy.Policy, 0, len(items))
	for _, it := range items {
		p, err := asPolicy(it)
		if err != nil {
			return err
		}
		pols = append(pols, p)
	}
	groups, users, err := x.audience(pols...)
	if err != nil {
		return err
	}
	rows := make([][]string, 0, len(pols))
	for _, p := range pols {
		lines := make([]string, 0, len(p.Grants))
		for _, g := range p.Grants {
			lines = append(lines, grantLine(g))
		}
		state := "on"
		if !p.Enabled {
			state = "off"
		}
		rows = append(rows, []string{p.Name, who(p, groups, users), strings.Join(lines, " · "), accessOf(p), state})
	}
	x.out.table([]string{"NAME", "WHO", "GRANTS", "ACCESS", "ENABLED"}, rows)
	return nil
}

func cmdPolicyShow(x *run) error {
	it, err := x.byName("policy", "/access-policies", "name", x.args[0])
	if err != nil {
		return err
	}
	p, err := asPolicy(it)
	if err != nil {
		return err
	}
	groups, users, err := x.audience(p)
	if err != nil {
		return err
	}
	targets, asgs, err := x.inventory(p)
	if err != nil {
		return err
	}
	gs, us := subjectNames(p, groups, users)
	x.out.pairs([][2]string{
		{"name", str(it, "name")}, {"description", str(it, "description")}, {"enabled", str(it, "enabled")},
		{"groups", strings.Join(gs, ", ")}, {"users", strings.Join(us, ", ")},
		{"created", when(it, "created_at")}, {"updated", when(it, "updated_at")}, {"id", str(it, "id")},
	})
	if len(p.Subjects) == 0 {
		// A group deleted leaves its policies (ADR 0036); one it was the
		// only audience of grants no one until someone is added.
		x.out.addf(styleMuted, "Applies to no one: add a group or user from the console.")
	}
	for i, g := range p.Grants {
		x.out.textf("")
		x.out.addf(styleHead, "Grant %d · %s", i+1, g.Kind)
		x.out.pairs(grantPairs(g, targets, asgs))
	}
	return nil
}

// asPolicy reads a policy from a list item.
func asPolicy(it obj) (policy.Policy, error) {
	var p policy.Policy
	b, err := json.Marshal(it)
	if err != nil {
		return p, err
	}
	err = json.Unmarshal(b, &p)
	return p, err
}

// names maps the ids a list route returns to the value of key; label falls
// back to the id for one it does not hold, such as a target retired since.
func (x *run) names(path, key string) (map[string]string, error) {
	items, err := x.listAll(path, 5000)
	if err != nil {
		return nil, err
	}
	m := make(map[string]string, len(items))
	for _, it := range items {
		m[str(it, "id")] = str(it, key)
	}
	return m, nil
}

func label(names map[string]string, id string) string {
	if n := names[id]; n != "" {
		return n
	}
	return id
}

// audience names the groups and users the policies apply to, asking for
// each list only when some policy names one of its kind.
func (x *run) audience(pols ...policy.Policy) (groups, users map[string]string, err error) {
	var wantGroups, wantUsers bool
	for _, p := range pols {
		for _, s := range p.Subjects {
			wantGroups = wantGroups || s.Kind == policy.SubjectGroup
			wantUsers = wantUsers || s.Kind == policy.SubjectUser
		}
	}
	if wantGroups {
		if groups, err = x.names("/groups", "name"); err != nil {
			return nil, nil, err
		}
	}
	if wantUsers {
		if users, err = x.names("/users", "username"); err != nil {
			return nil, nil, err
		}
	}
	return groups, users, nil
}

// inventory names the targets and autoscaling groups the policy's grants
// name, asking for each list only when a grant names one of its kind.
func (x *run) inventory(p policy.Policy) (targets, asgs map[string]string, err error) {
	var wantTargets, wantASGs bool
	for _, g := range p.Grants {
		if len(g.Targets) == 0 {
			continue
		}
		if g.Kind == protocol.KindAutoscaling {
			wantASGs = true
		} else {
			wantTargets = true
		}
	}
	if wantTargets {
		if targets, err = x.names("/targets", "name"); err != nil {
			return nil, nil, err
		}
	}
	if wantASGs {
		if asgs, err = x.names("/autoscaling-groups", "name"); err != nil {
			return nil, nil, err
		}
	}
	return targets, asgs, nil
}

// who is a policy's audience in a few words: its groups by name, then its
// users, counted beside groups and named when they are all there is.
func who(p policy.Policy, groups, users map[string]string) string {
	gs, us := subjectNames(p, groups, users)
	switch {
	case len(gs) == 0 && len(us) == 0:
		return "no one"
	case len(gs) == 0:
		return strings.Join(us, ", ")
	case len(us) == 0:
		return strings.Join(gs, ", ")
	}
	return strings.Join(gs, ", ") + " +" + count(len(us), "user")
}

// subjectNames splits a policy's audience into its groups' and its users'
// names, in the policy's order.
func subjectNames(p policy.Policy, groups, users map[string]string) (gs, us []string) {
	for _, s := range p.Subjects {
		if s.Kind == policy.SubjectGroup {
			gs = append(gs, label(groups, s.ID))
		} else {
			us = append(us, label(users, s.ID))
		}
	}
	return gs, us
}

// accessOf says whether a policy's grants admit at once, after approval, or
// some of each.
func accessOf(p policy.Policy) string {
	var standing, approval bool
	for _, g := range p.Grants {
		if g.Access == policy.AccessApproval {
			approval = true
		} else {
			standing = true
		}
	}
	switch {
	case standing && approval:
		return "standing, approval"
	case approval:
		return "approval"
	case standing:
		return "standing"
	}
	return ""
}

// grantLine is one grant in a few words: its kind, the protocols it gives
// where the kind has a choice, then how many it names and the tags it
// matches, as in "host SSH (2 targets, env=prod)".
func grantLine(g policy.Grant) string {
	s := g.Kind
	if protos := grantProtocols(g); len(protos) > 0 {
		s += " " + strings.Join(protos, ", ")
	}
	var what []string
	if n := len(g.Targets); n > 0 {
		noun := "target"
		if g.Kind == protocol.KindAutoscaling {
			noun = "group"
		}
		what = append(what, count(n, noun))
	}
	if g.Tags != nil {
		what = append(what, tagText(g.Tags.Match))
	}
	if len(what) > 0 {
		s += " (" + strings.Join(what, ", ") + ")"
	}
	return s
}

// grantPairs is one grant in full, for policy show.
func grantPairs(g policy.Grant, targets, asgs map[string]string) [][2]string {
	names := targets
	if g.Kind == protocol.KindAutoscaling {
		names = asgs
	}
	named := make([]string, 0, len(g.Targets))
	for _, t := range g.Targets {
		named = append(named, label(names, t.ID)+protoSuffix(g.Kind, t.Protocols))
	}
	tags := ""
	if g.Tags != nil {
		tags = tagText(g.Tags.Match) + protoSuffix(g.Kind, g.Tags.Protocols)
	}
	signIn := "as the target sets it"
	if g.SignIn == policy.SignInOwn {
		signIn = "their own login"
	}
	most := "none"
	if g.MaxSessionMinutes != nil {
		most = fmt.Sprintf("%d min", *g.MaxSessionMinutes)
	}
	keep := "the global setting"
	if g.RetentionDays != nil {
		keep = fmt.Sprintf("%d days", *g.RetentionDays)
	}
	return [][2]string{
		{"targets", strings.Join(named, ", ")}, {"tags", tags}, {"access", g.Access}, {"sign-in", signIn},
		{"needs MFA", yesNo(g.RequireMFA)}, {"clipboard", yesNo(g.AllowClipboard)}, {"file transfer", yesNo(g.AllowFileTransfer)},
		{"idle timeout", fmt.Sprintf("%d min", g.IdleTimeoutMinutes)}, {"max session", most},
		{"windows", windowsText(g.TimeWindows)}, {"retention", keep}, {"id", g.ID},
	}
}

// grantProtocols lists, by name and in the kind's own order, the protocols
// a grant gives on anything, for a kind with more than one to give: a
// database grant gives database and an application grant http, always.
func grantProtocols(g policy.Grant) []string {
	if len(protocol.KindProtocols(g.Kind)) < 2 {
		return nil
	}
	given := map[string]bool{}
	for _, t := range g.Targets {
		for _, p := range t.Protocols {
			given[p] = true
		}
	}
	if g.Tags != nil {
		for _, p := range g.Tags.Protocols {
			given[p] = true
		}
	}
	var out []string
	for _, p := range protocol.KindProtocols(g.Kind) {
		if given[p] {
			out = append(out, protocol.Name(p))
		}
	}
	return out
}

// protoSuffix is " (SSH, RDP)" after a target or a tag match, for a kind
// with a choice of protocols; nothing for one without.
func protoSuffix(kind string, protos []string) string {
	if len(protocol.KindProtocols(kind)) < 2 {
		return ""
	}
	labels := make([]string, 0, len(protos))
	for _, p := range protos {
		labels = append(labels, protocol.Name(p))
	}
	return " (" + strings.Join(labels, ", ") + ")"
}

// tagText renders a tag match as "env=prod tier=web|api", keys in order:
// every key must be present, with one of its values.
func tagText(match map[string][]string) string {
	parts := make([]string, 0, len(match))
	for _, k := range slices.Sorted(maps.Keys(match)) {
		parts = append(parts, k+"="+strings.Join(match[k], "|"))
	}
	return strings.Join(parts, " ")
}

// windowsText renders time windows as "mon,tue 09:00-18:00 Europe/Berlin";
// none means at any time.
func windowsText(ws []policy.TimeWindow) string {
	if len(ws) == 0 {
		return "any time"
	}
	parts := make([]string, 0, len(ws))
	for _, w := range ws {
		hours := w.From + "-" + w.To
		if w.From == w.To {
			hours = "all day"
		}
		parts = append(parts, strings.Join(w.Days, ",")+" "+hours+" "+w.TZ)
	}
	return strings.Join(parts, "; ")
}

func count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func cmdRequests(x *run) error {
	path := "/access-requests"
	if x.has("pending") {
		path += "?status=pending"
	}
	items, err := x.listAll(path, 200)
	if err != nil {
		return err
	}
	rows := make([][]string, 0, len(items))
	for _, r := range items {
		rows = append(rows, []string{short(str(r, "id")), str(r, "username"), str(r, "target_name"), protocol.Name(str(r, "protocol")), str(r, "requested_minutes") + "m", str(r, "status"), str(r, "reason")})
	}
	x.out.table([]string{"ID", "USER", "TARGET", "PROTOCOL", "FOR", "STATUS", "REASON"}, rows)
	return nil
}

func (x *run) requestID() (string, error) {
	return x.once("request", func() (obj, error) { return x.byIDPrefix("request", "/access-requests", x.args[0]) })
}

func planRevoke(x *run) (string, string, error) {
	r, err := x.byIDPrefix("request", "/access-requests", x.args[0])
	if err != nil {
		return "", "", err
	}
	x.resolved["request"] = str(r, "id")
	return fmt.Sprintf("This withdraws %s's access to %s now; any session it opened is ended.", str(r, "username"), str(r, "target_name")), str(r, "username"), nil
}

func cmdDecide(verb string) func(x *run) error {
	return func(x *run) error {
		id, err := x.requestID()
		if err != nil {
			return err
		}
		var body any
		if x.rest != "" {
			body = map[string]string{"note": x.rest}
		}
		if err := x.api.do(http.MethodPost, pathf("/access-requests/%s/"+verb, id), body, nil); err != nil {
			return err
		}
		past := map[string]string{"approve": "Approved", "deny": "Denied", "revoke": "Revoked"}[verb]
		x.out.addf(styleOK, "✓ %s.", past)
		return nil
	}
}

// ---- Audit

func cmdEvents(x *run) error {
	n, err := x.last(20, 500)
	if err != nil {
		return err
	}
	q := url.Values{"limit": {strconv.Itoa(n)}}
	if u := x.flag("user"); u != "" {
		q.Set("actor", u)
	}
	if a := x.flag("action"); a != "" {
		q.Set("action", a)
	}
	var page struct {
		Items []obj `json:"items"`
	}
	if err := x.api.get("/audit/events?"+q.Encode(), &page); err != nil {
		return err
	}
	rows := make([][]string, 0, len(page.Items))
	for _, e := range page.Items {
		object := str(e, "object_name")
		if object == "" {
			object = str(e, "object_type")
		}
		who := str(e, "actor_username")
		if who == "" {
			who = "system"
		}
		rows = append(rows, []string{str(e, "id"), when(e, "ts"), who, str(e, "action"), object, str(e, "outcome")})
	}
	x.out.table([]string{"ID", "TIME", "WHO", "ACTION", "OBJECT", "OUTCOME"}, rows)
	return nil
}

func cmdAuditVerify(x *run) error {
	var v obj
	if err := x.api.get("/audit/verify", &v); err != nil {
		return err
	}
	problems, _ := v["problems"].([]any)
	if v["intact"] == true {
		x.out.addf(styleOK, "✓ Chain intact: %d events checked, head %s.", num(v, "checked"), short(str(v, "last_hash")))
		if warnings, _ := v["warnings"].([]any); len(warnings) > 0 {
			x.out.addf(styleMuted, "Warning: %s", str(v, "warnings"))
		}
		return nil
	}
	if b := sub(v, "broken"); len(b) > 0 || len(problems) == 0 {
		// The API sends the broken event as audit.VerifyError, whose fields
		// carry no JSON tags: ID and Reason, as the spec documents them.
		x.out.addf(styleError, "✗ Chain broken at event %s: %s", str(b, "ID"), str(b, "Reason"))
		x.out.addf(styleMuted, "Events from there on cannot be shown to be unaltered. Repair is a host-only operation (zanskar audit), on purpose.")
	}
	// The chain can link and still have lost its newest events: the signed
	// anchors and the id sequence say so (ADR 0008).
	for _, p := range problems {
		x.out.addf(styleError, "✗ %v", p)
	}
	return nil
}

// ---- Gateway

func cmdLogs(x *run) error {
	n, err := x.last(30, 1000)
	if err != nil {
		return err
	}
	q := url.Values{"limit": {strconv.Itoa(n)}}
	if l := x.flag("level"); l != "" {
		q.Set("level", l)
	}
	if s := x.flag("search"); s != "" {
		q.Set("q", s)
	}
	var page struct {
		Items []obj `json:"items"`
	}
	if err := x.api.get("/admin/logs?"+q.Encode(), &page); err != nil {
		return err
	}
	if len(page.Items) == 0 {
		x.out.addf(styleMuted, "(no lines)")
	}
	for _, l := range page.Items {
		style := ""
		switch str(l, "level") {
		case "WARN":
			style = styleWarn
		case "ERROR":
			style = styleError
		case "DEBUG":
			style = styleMuted
		}
		text := fmt.Sprintf("%s %-5s %s", when(l, "time"), str(l, "level"), str(l, "msg"))
		if a := str(l, "attrs"); a != "" {
			text += "  " + a
		}
		x.out.addf(style, "%s", text)
	}
	return nil
}

func cmdTLS(x *run) error {
	var t obj
	if err := x.api.get("/admin/tls", &t); err != nil {
		return err
	}
	kv := [][2]string{{"mode", str(t, "mode")}}
	for _, k := range []string{"subject", "issuer", "hosts", "not_after", "fingerprint", "source"} {
		if v := str(t, k); v != "" {
			kv = append(kv, [2]string{strings.ReplaceAll(k, "_", " "), v})
		}
	}
	x.out.pairs(kv)
	return nil
}

func cmdStorage(x *run) error {
	var s obj
	if err := x.api.get("/admin/storage", &s); err != nil {
		return err
	}
	move := sub(s, "move")
	kv := [][2]string{{"stored in", str(s, "source")}, {"recordings", str(s, "counts")}}
	if move["running"] == true {
		kv = append(kv, [2]string{"move", fmt.Sprintf("running: %d of %d moved, %d failed", num(move, "moved"), num(move, "total"), num(move, "failed"))})
	}
	x.out.pairs(kv)
	return nil
}

func cmdStorageTest(x *run) error {
	var res obj
	if err := x.api.do(http.MethodPost, "/admin/storage/test", nil, &res); err != nil {
		return err
	}
	x.out.addf(styleOK, "✓ The recordings store accepted a test object and returned it.")
	return nil
}

func cmdSettings(x *run) error {
	var s struct {
		Runtime []obj `json:"runtime"`
	}
	if err := x.api.get("/admin/settings", &s); err != nil {
		return err
	}
	rows := make([][]string, 0, len(s.Runtime))
	for _, r := range s.Runtime {
		rows = append(rows, []string{str(r, "key"), str(r, "value"), str(r, "source"), str(r, "title")})
	}
	x.out.table([]string{"KEY", "VALUE", "FROM", "WHAT"}, rows)
	return nil
}

// setting finds the key among the runtime settings. A key that is set at
// install comes back as boot, so get can show it and set can say where it
// is changed instead of claiming no such setting exists.
func (x *run) setting() (r obj, boot bool, err error) {
	key := x.args[0]
	var s struct {
		Runtime []obj `json:"runtime"`
		Boot    []obj `json:"boot"`
	}
	if err := x.api.get("/admin/settings", &s); err != nil {
		return nil, false, err
	}
	for _, r := range s.Runtime {
		if str(r, "key") == key {
			return r, false, nil
		}
	}
	for _, r := range s.Boot {
		if str(r, "key") == key {
			return r, true, nil
		}
	}
	return nil, false, usagef("no setting %q; type settings to list them", key)
}

// bootRefusal says where an install-time setting is changed.
func bootRefusal(r obj) error {
	return usagef("%s (%s) is set at install: edit %s in the service's environment file and restart the gateway",
		str(r, "title"), str(r, "key"), str(r, "env_var"))
}

func cmdSettingGet(x *run) error {
	r, boot, err := x.setting()
	if err != nil {
		return err
	}
	if boot {
		x.out.pairs([][2]string{
			{"key", str(r, "key")}, {"title", str(r, "title")}, {"value", str(r, "value")},
			{"from", "install (" + str(r, "env_var") + ")"}, {"about", str(r, "description")},
		})
		return nil
	}
	x.out.pairs([][2]string{
		{"key", str(r, "key")}, {"title", str(r, "title")}, {"value", str(r, "value")}, {"from", str(r, "source")},
		{"default", str(r, "default")}, {"type", str(r, "type")}, {"about", str(r, "description")},
	})
	return nil
}

func planSettingSet(x *run) (string, string, error) {
	if x.rest == "" {
		return "", "", usagef("usage: setting set <key> <value>")
	}
	r, boot, err := x.setting()
	if err != nil {
		return "", "", err
	}
	if boot {
		return "", "", bootRefusal(r)
	}
	// Only plain value types are set here. A setting of any other type, a
	// secret one day, is refused, so that "no secrets on the command line"
	// stays true without anyone remembering to keep it so (ADR 0027).
	if !plainSettingTypes[str(r, "type")] {
		return "", "", usagef("%s is set from the console's Settings page, not here", str(r, "key"))
	}
	return fmt.Sprintf("This changes %s (%s) from %q to %q for everyone.", str(r, "title"), str(r, "key"), str(r, "value"), x.rest), str(r, "key"), nil
}

// plainSettingTypes are the runtime setting types the command line may set.
var plainSettingTypes = map[string]bool{"string": true, "text": true, "bool": true, "enum": true, "hostport": true}

func cmdSettingSet(x *run) error {
	if err := x.api.do(http.MethodPut, pathf("/admin/settings/%s", x.args[0]), map[string]string{"value": x.rest}, nil); err != nil {
		return err
	}
	x.out.addf(styleOK, "✓ %s is now %q.", x.args[0], x.rest)
	return nil
}

// defaultWait matches the API's and the console's default.
const defaultWait = 15

func (x *run) waitMinutes() (int, error) {
	if !x.has("wait") {
		return defaultWait, nil
	}
	n, err := strconv.Atoi(x.flag("wait"))
	if err != nil || n < 0 || n > 240 {
		return 0, usagef("--wait takes minutes from 0 to 240")
	}
	return n, nil
}

func planRestart(x *run) (string, string, error) {
	wait, err := x.waitMinutes()
	if err != nil {
		return "", "", err
	}
	var st obj
	if err := x.api.get("/admin/system/status", &st); err != nil {
		return "", "", err
	}
	live := num(st, "live_sessions")
	if wait == 0 {
		return fmt.Sprintf("This restarts the gateway now. %d live sessions end, and the console is unavailable for a few seconds.", live), "restart", nil
	}
	return fmt.Sprintf("This restarts the gateway once the %d live sessions end, or after %d minutes, whichever is first. New sessions are refused meanwhile.", live, wait), "restart", nil
}

func cmdRestart(x *run) error {
	wait, err := x.waitMinutes()
	if err != nil {
		return err
	}
	if err := x.api.do(http.MethodPost, "/admin/system/restart", map[string]int{"wait_minutes": wait}, nil); err != nil {
		return err
	}
	x.out.addf(styleOK, "✓ Restart started.")
	return nil
}

func cmdRestartCancel(x *run) error {
	if err := x.api.do(http.MethodDelete, "/admin/system/restart", nil, nil); err != nil {
		var ae *apiError
		if errors.As(err, &ae) && ae.Status == http.StatusConflict {
			return usagef("no restart is waiting")
		}
		return err
	}
	x.out.addf(styleOK, "✓ Restart cancelled.")
	return nil
}

// ---- Autoscaling

func cmdASGs(x *run) error {
	items, err := x.listAll("/autoscaling-groups", 1000)
	if err != nil {
		return err
	}
	rows := make([][]string, 0, len(items))
	for _, g := range items {
		rows = append(rows, []string{str(g, "name"), str(g, "provider") + " " + str(g, "region"), str(g, "external_name"), str(g, "os_family"), str(g, "status"), when(g, "last_synced_at")})
	}
	x.out.table([]string{"NAME", "CLOUD", "GROUP", "OS", "STATUS", "LAST SYNC"}, rows)
	return nil
}

func cmdASGSync(x *run) error {
	g, err := x.byName("autoscaling group", "/autoscaling-groups", "name", x.args[0])
	if err != nil {
		return err
	}
	if err := x.api.do(http.MethodPost, pathf("/autoscaling-groups/%s/sync", str(g, "id")), nil, nil); err != nil {
		return err
	}
	x.out.addf(styleOK, "✓ Synced %s.", str(g, "name"))
	return nil
}
