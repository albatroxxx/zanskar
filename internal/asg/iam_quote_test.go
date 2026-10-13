// SPDX-License-Identifier: Apache-2.0

package asg

import (
	"errors"
	"os/exec"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// hostileNames are cloud-side group names that try to leave the quoted
// description in the CLI script or add keys to the CloudFormation template.
var hostileNames = []string{
	"web'; echo PWNED #",
	`web" $(echo PWNED) ` + "`echo PWNED`",
	"web'\necho PWNED\n'",
	"web\nTransform: AWS::Include",
	`web\'`,
}

// TestRoleCLIQuotesTheGroupName: whatever the cloud-side name holds, the
// shell reads the description as one argument holding exactly that text.
func TestRoleCLIQuotesTheGroupName(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	for _, name := range hostileNames {
		g := &Group{ExternalName: name}
		cli := g.RoleCLI("zanskar-web", "{}")
		start := strings.Index(cli, "--description ")
		end := strings.Index(cli, "\naws iam put-role-policy")
		if start < 0 || end < 0 {
			t.Fatalf("%q: description line not found in:\n%s", name, cli)
		}
		word := cli[start+len("--description ") : end]
		out, err := exec.Command("sh", "-c", "printf '%s\\n' "+word+"; printf END").Output() // #nosec G204 -- the point of the test
		if err != nil {
			t.Fatalf("%q: sh: %v", name, err)
		}
		want := "Zanskar gateway: read autoscaling group " + name + "\nEND"
		if string(out) != want {
			t.Errorf("%q: the shell read the description as\n%q\nwant\n%q", name, out, want)
		}
	}
}

// TestRoleCloudFormationQuotesTheGroupName: the template keeps exactly its
// four top-level keys and the description holds the name verbatim.
func TestRoleCloudFormationQuotesTheGroupName(t *testing.T) {
	for _, name := range hostileNames {
		g := &Group{ExternalName: name}
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(g.RoleCloudFormation("zanskar-web", "{}")), &doc); err != nil {
			t.Errorf("%q: template does not parse: %v", name, err)
			continue
		}
		if len(doc) != 4 || doc["AWSTemplateFormatVersion"] == nil || doc["Resources"] == nil || doc["Outputs"] == nil {
			t.Errorf("%q: top-level keys changed: %v", name, keys(doc))
		}
		if got := doc["Description"]; got != "Zanskar gateway access to autoscaling group "+name {
			t.Errorf("%q: description %q", name, got)
		}
	}
}

// TestValidateRefusesControlCharacters: no real autoscaling group name holds
// a line break or a control character, so one is refused at the door.
func TestValidateRefusesControlCharacters(t *testing.T) {
	for _, name := range []string{"web\nTransform: x", "web\tx", "web\x00", "web\x7f"} {
		g := &Group{Name: "g", Region: "eu-west-2", ExternalName: name, RoleARN: "arn:aws:iam::1:role/r", OSFamily: "linux"}
		if err := g.Validate(); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%q: Validate = %v, want ErrInvalidInput", name, err)
		}
	}
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
