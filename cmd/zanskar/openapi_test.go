// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
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
