// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestOpenAPIParses: docs/api/openapi.yaml must stay well-formed YAML with
// the top-level shape the console and the docs rely on. Nothing else in CI
// reads the file, and a misplaced block or an unquoted description that
// contains ": " breaks it silently.
func TestOpenAPIParses(t *testing.T) {
	raw, err := os.ReadFile("../../docs/api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		OpenAPI    string                    `yaml:"openapi"`
		Paths      map[string]map[string]any `yaml:"paths"`
		Components struct {
			Schemas map[string]map[string]any `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("openapi.yaml: %v", err)
	}
	if doc.OpenAPI == "" || len(doc.Paths) == 0 || len(doc.Components.Schemas) == 0 {
		t.Fatalf("openapi.yaml: missing top-level shape: version %q, %d paths, %d schemas", doc.OpenAPI, len(doc.Paths), len(doc.Components.Schemas))
	}
	for _, p := range []string{"/admin/tls", "/admin/storage", "/admin/logs", "/admin/settings", "/targets"} {
		if _, ok := doc.Paths[p]; !ok {
			t.Errorf("openapi.yaml: path %s missing", p)
		}
	}
	for _, s := range []string{"Target", "AccessPolicy", "TLSStatus", "StorageStatus", "ConnectTicket"} {
		props, ok := doc.Components.Schemas[s]["properties"].(map[string]any)
		if !ok || len(props) == 0 {
			t.Errorf("openapi.yaml: schema %s has no properties", s)
		}
	}
}

// TestOpenAPIMatchesRoutes: every operation in docs/api/openapi.yaml must reach
// a route the server registers, with the same method, and every route must be
// documented. The spec once listed PATCH for six updates the server serves as
// PUT, and four operations that never existed.
func TestOpenAPIMatchesRoutes(t *testing.T) {
	raw, err := os.ReadFile("../../docs/api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	type server struct {
		URL string `yaml:"url"`
	}
	var doc struct {
		Servers []server                  `yaml:"servers"`
		Paths   map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("openapi.yaml: %v", err)
	}
	base := func(srv []server) string {
		if len(srv) == 0 {
			return ""
		}
		return strings.TrimSuffix(srv[0].URL, "/")
	}
	spec := map[string]bool{} // "METHOD /full/path"
	for p, item := range doc.Paths {
		prefix := base(doc.Servers)
		if s, ok := item["servers"]; ok {
			b, _ := yaml.Marshal(s)
			var ss []server
			if err := yaml.Unmarshal(b, &ss); err != nil {
				t.Fatalf("openapi.yaml: %s servers: %v", p, err)
			}
			prefix = base(ss)
		}
		for m := range item {
			switch m {
			case "get", "post", "put", "patch", "delete":
				spec[strings.ToUpper(m)+" "+prefix+p] = true
			}
		}
	}

	route := regexp.MustCompile(`"((?:GET|POST|PUT|PATCH|DELETE) /(?:api/v1|healthz|readyz|ws)\b[^"]*)"`)
	code := map[string]bool{}
	mux := http.NewServeMux()
	for _, root := range []string{"../../internal", "."} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			src, err := os.ReadFile(path) // #nosec G304 -- walking the repo's own source tree
			if err != nil {
				return err
			}
			for _, m := range route.FindAllStringSubmatch(string(src), -1) {
				if !code[m[1]] {
					code[m[1]] = true
					mux.Handle(m[1], http.NotFoundHandler())
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(code) < 50 {
		t.Fatalf("found only %d routes in the source; is the pattern still right?", len(code))
	}

	// Each documented operation must be served. The mux decides, so a
	// documented literal such as /admin/settings/login-banner may reach a
	// {key} route, exactly as a client's request would.
	param := regexp.MustCompile(`\{[^}]+\}`)
	for op := range spec {
		method, path, _ := strings.Cut(op, " ")
		req := httptest.NewRequest(method, param.ReplaceAllString(path, "x"), nil)
		if _, pattern := mux.Handler(req); pattern == "" {
			t.Errorf("openapi.yaml documents %s, but the server has no such route", op)
		}
	}

	// Every route the server registers must be documented, spelled exactly as
	// registered (same method, same path parameter names).
	for op := range code {
		if !spec[op] {
			t.Errorf("the server registers %s, but openapi.yaml does not document it", op)
		}
	}
}
