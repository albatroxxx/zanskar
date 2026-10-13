// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// actionConstants reads the action names declared in actions.go.
func actionConstants(t *testing.T) map[string]string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "actions.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	byValue := map[string]string{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, name := range vs.Names {
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Fatalf("%s is not a string literal", name.Name)
				}
				v, _ := strconv.Unquote(lit.Value)
				if prev, dup := byValue[v]; dup {
					t.Errorf("%s and %s are both %q", prev, name.Name, v)
				}
				byValue[v] = name.Name
			}
		}
	}
	return byValue
}

// TestActionsMatchConsoleLabels: the console names every action the gateway
// records, and labels nothing the gateway never records (M25). A new action
// without a label shows its words as a guess; a label without an action is a
// filter that finds nothing.
func TestActionsMatchConsoleLabels(t *testing.T) {
	actions := actionConstants(t)
	src, err := os.ReadFile("../../web/src/pages/audit/eventText.ts")
	if err != nil {
		t.Fatal(err)
	}
	block := string(src)
	start := strings.Index(block, "const actionLabels")
	if start < 0 {
		t.Fatal("eventText.ts has no actionLabels table")
	}
	block, _, ok := strings.Cut(block[start:], "\n}\n")
	if !ok {
		t.Fatal("eventText.ts: actionLabels has no end")
	}
	labels := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s*'([^']+)':`).FindAllStringSubmatch(block, -1) {
		labels[m[1]] = true
	}
	var missing, stale []string
	for v := range actions {
		if !labels[v] {
			missing = append(missing, v)
		}
	}
	for v := range labels {
		if _, ok := actions[v]; !ok {
			stale = append(stale, v)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("actions with no label in eventText.ts: %v", missing)
	}
	if len(stale) > 0 {
		t.Errorf("labels in eventText.ts for actions the gateway never records: %v", stale)
	}
}

// TestNoLiteralActions: events are recorded with the constants, so a
// misspelt action fails to build rather than reaching the log. A string equal
// to an action anywhere else in the gateway's code is reported.
func TestNoLiteralActions(t *testing.T) {
	actions := actionConstants(t)
	fset := token.NewFileSet()
	for _, root := range []string{"../../internal", "../../cmd"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") ||
				filepath.Clean(path) == filepath.Clean("../../internal/audit/actions.go") {
				return err
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				if v, err := strconv.Unquote(lit.Value); err == nil {
					if name, ok := actions[v]; ok {
						t.Errorf("%s: %s is written as a literal; use audit.%s", fset.Position(lit.Pos()), lit.Value, name)
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
