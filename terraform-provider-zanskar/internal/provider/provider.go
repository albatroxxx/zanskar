// SPDX-License-Identifier: Apache-2.0

// Package provider is the Terraform provider for Zanskar (ADR 0044): groups,
// targets and access policies over the gateway's configuration API, signed
// in with an administrator's API token.
package provider

import (
	"context"
	"net/http"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// New returns the provider at version.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &zanskarProvider{version: version} }
}

type zanskarProvider struct{ version string }

type providerModel struct {
	URL   types.String `tfsdk:"url"`
	Token types.String `tfsdk:"token"`
	CAPEM types.String `tfsdk:"ca_pem"`
}

func (p *zanskarProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "zanskar"
	resp.Version = p.version
}

func (p *zanskarProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Zanskar gateway's groups, targets and access policies with an administrator's API token.",
		Attributes: map[string]schema.Attribute{
			"url": schema.StringAttribute{
				Optional:    true,
				Description: "The gateway's address, such as https://zanskar.example.com. ZANSKAR_URL when unset.",
			},
			"token": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "An API token (zapi_...) from Settings › API tokens. ZANSKAR_TOKEN when unset.",
			},
			"ca_pem": schema.StringAttribute{
				Optional:    true,
				Description: "A CA certificate, PEM, to trust beside the system's: for a gateway with a private CA. ZANSKAR_CA_PEM when unset.",
			},
		},
	}
}

func (p *zanskarProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	pick := func(v types.String, env string) string {
		if !v.IsNull() && !v.IsUnknown() {
			return v.ValueString()
		}
		return os.Getenv(env)
	}
	c, err := NewClient(pick(cfg.URL, "ZANSKAR_URL"), pick(cfg.Token, "ZANSKAR_TOKEN"), pick(cfg.CAPEM, "ZANSKAR_CA_PEM"), p.version)
	if err != nil {
		resp.Diagnostics.AddError("Zanskar provider configuration", err.Error())
		return
	}
	// One call now, so a wrong address or token fails at the start of a
	// plan rather than at its first resource.
	var me struct {
		Username string `json:"username"`
	}
	if err := c.do(ctx, http.MethodGet, "/auth/me", nil, &me); err != nil {
		resp.Diagnostics.AddError("Zanskar provider configuration", "the gateway did not accept the token: "+err.Error())
		return
	}
	resp.DataSourceData, resp.ResourceData = c, c
}

func (p *zanskarProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{newGroupResource, newTargetResource, newPolicyResource}
}

func (p *zanskarProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{newCredentialDataSource, newGroupDataSource}
}

// clientFrom is the client a resource or data source was configured with,
// nil before the provider is configured (a validate run).
func clientFrom(data any) *Client {
	c, _ := data.(*Client)
	return c
}
