// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/albatroxxx/zanskar/internal/session"
	"github.com/albatroxxx/zanskar/internal/states"
	"github.com/albatroxxx/zanskar/internal/states/catalog"
)

// The guard tests of ADR 0047: a lifecycle is declared once, in Go, and the
// console's labels, the OpenAPI enums and docs/lifecycles.md follow it. A
// copy that drifts fails here and names what to change.

// consoleLabels reads web/src/api/states.ts: lifecycle key -> its states.
// It reads the file's shape (one lifecycle per two-space key, one state per
// four-space key), not the module, so a change there is a change here.
func consoleLabels(t *testing.T) map[string][]string {
	t.Helper()
	src, err := os.ReadFile("../../web/src/api/states.ts")
	if err != nil {
		t.Fatal(err)
	}
	_, body, ok := strings.Cut(string(src), "export const stateLabels = {")
	if !ok {
		t.Fatal("states.ts has no stateLabels table")
	}
	body, _, ok = strings.Cut(body, "\n} as const")
	if !ok {
		t.Fatal("states.ts: stateLabels has no end")
	}
	out := map[string][]string{}
	var current string
	lifecycle := regexp.MustCompile(`^  ([a-z_]+): \{$`)
	state := regexp.MustCompile(`^    ([a-z_]+): \{ label: `)
	for _, line := range strings.Split(body, "\n") {
		if m := lifecycle.FindStringSubmatch(line); m != nil {
			current = m[1]
			out[current] = nil
			continue
		}
		if m := state.FindStringSubmatch(line); m != nil {
			if current == "" {
				t.Fatalf("states.ts: state %q outside a lifecycle", m[1])
			}
			out[current] = append(out[current], m[1])
		}
	}
	return out
}

// TestLifecyclesHaveConsoleLabels: every state the gateway can send has the
// words the console shows for it, and the console names no state the
// gateway never sends.
func TestLifecyclesHaveConsoleLabels(t *testing.T) {
	labels := consoleLabels(t)
	seen := map[string]bool{}
	for _, l := range catalog.Exposed() {
		seen[l.Key()] = true
		got, ok := labels[l.Key()]
		if !ok {
			t.Errorf("web/src/api/states.ts: no labels for %q (states %v)", l.Key(), l.States())
			continue
		}
		if want := states.Sorted(l.States()); !slices.Equal(states.Sorted(got), want) {
			t.Errorf("web/src/api/states.ts: %s labels %v, the gateway declares %v", l.Key(), got, want)
		}
	}
	for key := range labels {
		if !seen[key] {
			t.Errorf("web/src/api/states.ts: labels for %q, which no exposed lifecycle declares", key)
		}
	}
}

// openAPISchemas reads components.schemas of docs/api/openapi.yaml.
func openAPISchemas(t *testing.T) map[string]map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../docs/api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]map[string]any `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Components.Schemas
}

// enumOf finds the enum of schema.field, through allOf and a $ref.
func enumOf(schemas map[string]map[string]any, schema, field string) ([]string, bool) {
	s, ok := schemas[schema]
	if !ok {
		return nil, false
	}
	var prop map[string]any
	if props, ok := s["properties"].(map[string]any); ok {
		prop, _ = props[field].(map[string]any)
	}
	if prop == nil {
		// A composed schema: the field may sit on a part, or on the schema a
		// part refers to (AccessSession extends OwnSession).
		if all, ok := s["allOf"].([]any); ok {
			for _, part := range all {
				m, _ := part.(map[string]any)
				if ref, ok := m["$ref"].(string); ok {
					m = schemas[strings.TrimPrefix(ref, "#/components/schemas/")]
				}
				if props, ok := m["properties"].(map[string]any); ok {
					if p, ok := props[field].(map[string]any); ok {
						prop = p
					}
				}
			}
		}
	}
	if prop == nil {
		return nil, false
	}
	if ref, ok := prop["$ref"].(string); ok {
		name := strings.TrimPrefix(ref, "#/components/schemas/")
		if target, ok := schemas[name]; ok {
			prop = target
		}
	}
	raw, ok := prop["enum"].([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		out = append(out, v.(string))
	}
	return out, true
}

// TestLifecyclesMatchOpenAPI: the enum of every state field in the API
// document is the set of states the code declares, on every schema that
// carries the field; and the end reasons are the twelve the gateway writes.
func TestLifecyclesMatchOpenAPI(t *testing.T) {
	schemas := openAPISchemas(t)
	for _, l := range catalog.Exposed() {
		want := states.Sorted(l.States())
		for _, schema := range l.Schemas {
			got, ok := enumOf(schemas, schema, l.Field)
			if !ok {
				t.Errorf("openapi.yaml: %s.%s has no enum (lifecycle %q)", schema, l.Field, l.Name)
				continue
			}
			if !slices.Equal(states.Sorted(got), want) {
				t.Errorf("openapi.yaml: %s.%s enum %v, the gateway declares %v", schema, l.Field, got, want)
			}
		}
	}
	got, ok := enumOf(map[string]map[string]any{"x": {"properties": map[string]any{"end_reason": map[string]any{"$ref": "#/components/schemas/EndReason"}}}, "EndReason": schemas["EndReason"]}, "x", "end_reason")
	if !ok {
		t.Fatal("openapi.yaml: EndReason has no enum")
	}
	if want := states.Sorted(session.EndReasons); !slices.Equal(states.Sorted(got), want) {
		t.Errorf("openapi.yaml: EndReason %v, the gateway writes %v", got, want)
	}
}

// TestLifecyclesDocIsCurrent: docs/lifecycles.md is what the declarations
// render. Regenerate it with `go run ./hack/gen-lifecycles > docs/lifecycles.md`.
func TestLifecyclesDocIsCurrent(t *testing.T) {
	have, err := os.ReadFile("../../docs/lifecycles.md")
	if err != nil {
		t.Fatal(err)
	}
	if want := catalog.Document(); string(have) != want {
		t.Errorf("docs/lifecycles.md is stale; run: go run ./hack/gen-lifecycles > docs/lifecycles.md")
	}
}

// TestLifecycleKeysAreDistinct: two lifecycles cannot share a key, or the
// label table and the document would fold them into one.
func TestLifecycleKeysAreDistinct(t *testing.T) {
	seen := map[string]string{}
	for _, l := range catalog.All() {
		if prev, dup := seen[l.Key()]; dup {
			t.Errorf("lifecycles %q and %q share the key %q", prev, l.Name, l.Key())
		}
		seen[l.Key()] = l.Name
		if l.Exposed() && len(l.Schemas) == 0 {
			t.Errorf("lifecycle %q names a field and no schema", l.Name)
		}
	}
}
