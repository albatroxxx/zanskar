// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestPolicyModelCarriesApprovers (ADR 0049; review R14): a grant's approvers
// go to the gateway as the plan names them and come back into the state as
// the gateway answers them; a grant naming none sends an empty list, never
// an absent field, since a write that left them out would hand the decision
// back to any administrator.
func TestPolicyModelCarriesApprovers(t *testing.T) {
	ctx := context.Background()
	list := func(elem attr.Type, v any) types.List {
		l, d := types.ListValueFrom(ctx, elem, v)
		if d.HasError() {
			t.Fatal(d)
		}
		return l
	}
	named := []subjectModel{{Kind: types.StringValue("group"), ID: types.StringValue("g1")}, {Kind: types.StringValue("user"), ID: types.StringValue("u1")}}
	grant := func(approvers []subjectModel) grantModel {
		return grantModel{
			ID: types.StringValue("gr1"), Kind: types.StringValue("host"), Access: types.StringValue("approval"), SignIn: types.StringValue("target"),
			RequireMFA: types.BoolValue(true), AllowClipboard: types.BoolValue(false), AllowFileTransfer: types.BoolValue(false), AllowDevTools: types.BoolValue(false),
			IdleTimeoutMinutes: types.Int64Value(15), MaxSessionMinutes: types.Int64Value(120), RetentionDays: types.Int64Null(),
			Targets:      list(grantTargetType, []grantTargetModel{{ID: types.StringValue("t1"), Protocols: []string{"ssh"}}}),
			Tags:         types.ObjectNull(tagMatchType.AttrTypes),
			TimeWindows:  list(windowType, []windowModel{}),
			Namespaces:   []string{},
			ClusterScope: types.BoolValue(false), PortForward: types.BoolValue(false),
			Approvers:    list(subjectType, approvers),
			CloudConsole: types.BoolNull(), CloudCLI: types.BoolNull(),
		}
	}
	m := policyModel{
		Name: types.StringValue("prod"), Description: types.StringValue(""), Enabled: types.BoolValue(true),
		Subjects: list(subjectType, []subjectModel{{Kind: types.StringValue("group"), ID: types.StringValue("g1")}}),
		Grants:   list(grantType, []grantModel{grant(named), grant([]subjectModel{})}),
	}

	// The write names them in order, and an empty list stays a list.
	w, d := m.write(ctx)
	if d.HasError() {
		t.Fatal(d)
	}
	if len(w.Grants) != 2 || len(w.Grants[0].Approvers) != 2 || w.Grants[0].Approvers[0] != (apiSubject{Kind: "group", ID: "g1"}) || w.Grants[0].Approvers[1] != (apiSubject{Kind: "user", ID: "u1"}) {
		t.Fatalf("written approvers: %+v", w.Grants)
	}
	if w.Grants[1].Approvers == nil || len(w.Grants[1].Approvers) != 0 {
		t.Fatalf("a grant naming nobody should send an empty list: %#v", w.Grants[1].Approvers)
	}
	body, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"approvers":[{"kind":"group","id":"g1"},{"kind":"user","id":"u1"}]`) || !strings.Contains(string(body), `"approvers":[]`) {
		t.Fatalf("the body: %s", body)
	}

	// The read puts what the gateway answered into the state.
	var read policyModel
	answered := apiPolicy{ID: "p1", Name: "prod", Enabled: true, Subjects: []apiSubject{{Kind: "group", ID: "g1"}},
		Grants: []apiGrant{{ID: "gr1", Kind: "host", Access: "approval", SignIn: "target", Targets: []apiGrantTarget{{ID: "t1", Protocols: []string{"ssh"}}},
			Approvers: []apiSubject{{Kind: "user", ID: "u9"}, {Kind: "group", ID: "g2"}}}}}
	if d := read.from(ctx, &answered); d.HasError() {
		t.Fatal(d)
	}
	var grants []grantModel
	if d := read.Grants.ElementsAs(ctx, &grants, false); d.HasError() || len(grants) != 1 {
		t.Fatalf("grants read back: %v %d", d, len(grants))
	}
	var got []subjectModel
	if d := grants[0].Approvers.ElementsAs(ctx, &got, false); d.HasError() {
		t.Fatal(d)
	}
	if len(got) != 2 || got[0].Kind.ValueString() != "user" || got[0].ID.ValueString() != "u9" || got[1].Kind.ValueString() != "group" || got[1].ID.ValueString() != "g2" {
		t.Fatalf("approvers read back: %+v", got)
	}
}
