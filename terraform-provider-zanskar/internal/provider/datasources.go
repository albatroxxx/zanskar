// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Credentials stay in the console's vault (ADR 0044): a target names one by
// id, found here by name, so no secret is in a plan or a state.

type apiCredential struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Username string `json:"username"`
}

type credentialModel struct {
	ID       types.String `tfsdk:"id"`
	Name     types.String `tfsdk:"name"`
	Type     types.String `tfsdk:"type"`
	Username types.String `tfsdk:"username"`
}

type credentialDataSource struct{ c *Client }

func newCredentialDataSource() datasource.DataSource { return &credentialDataSource{} }

func (d *credentialDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_credential"
}

func (d *credentialDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A credential in the gateway's vault, found by name. Its secret never leaves the gateway.",
		Attributes: map[string]schema.Attribute{
			"name":     schema.StringAttribute{Required: true},
			"id":       schema.StringAttribute{Computed: true},
			"type":     schema.StringAttribute{Computed: true},
			"username": schema.StringAttribute{Computed: true},
		},
	}
}

func (d *credentialDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	d.c = clientFrom(req.ProviderData)
}

func (d *credentialDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m credentialModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	cr, err := findByName(ctx, d.c, "/credentials", m.Name.ValueString(), func(c apiCredential) string { return c.Name })
	if err != nil {
		resp.Diagnostics.AddError("Read credential", err.Error())
		return
	}
	if cr == nil {
		resp.Diagnostics.AddError("Read credential", fmt.Sprintf("no credential is named %q", m.Name.ValueString()))
		return
	}
	m.ID, m.Type, m.Username = types.StringValue(cr.ID), types.StringValue(cr.Type), types.StringValue(cr.Username)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

type groupLookupModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
}

type groupDataSource struct{ c *Client }

func newGroupDataSource() datasource.DataSource { return &groupDataSource{} }

func (d *groupDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group"
}

func (d *groupDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A group found by name, such as one an identity provider brings, for a policy to name.",
		Attributes: map[string]schema.Attribute{
			"name":        schema.StringAttribute{Required: true},
			"id":          schema.StringAttribute{Computed: true},
			"description": schema.StringAttribute{Computed: true},
		},
	}
}

func (d *groupDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	d.c = clientFrom(req.ProviderData)
}

func (d *groupDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m groupLookupModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	g, err := findByName(ctx, d.c, "/groups", m.Name.ValueString(), func(g apiGroup) string { return g.Name })
	if err != nil {
		resp.Diagnostics.AddError("Read group", err.Error())
		return
	}
	if g == nil {
		resp.Diagnostics.AddError("Read group", fmt.Sprintf("no group is named %q", m.Name.ValueString()))
		return
	}
	m.ID, m.Description = types.StringValue(g.ID), types.StringValue(g.Description)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
