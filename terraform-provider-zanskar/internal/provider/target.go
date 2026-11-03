// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"net/http"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// A target is a host, a database or an application, as the API has them:
// one object, its kind told by its fields (engine for a database,
// app_upstream for an application).

type apiEndpoint struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// apiTarget is a target as the API answers it.
type apiTarget struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Address         string            `json:"address"`
	Engine          string            `json:"engine"`
	EngineVersion   string            `json:"engine_version"`
	RetentionDays   *int              `json:"retention_days"`
	DatabaseName    string            `json:"database_name"`
	TLSMode         string            `json:"tls_mode"`
	TLSCA           string            `json:"tls_ca"`
	AppUpstream     string            `json:"app_upstream"`
	AppEndpoints    []apiEndpoint     `json:"app_endpoints"`
	AppDependencies string            `json:"app_dependencies"`
	OSFamily        string            `json:"os_family"`
	Ports           map[string]int    `json:"ports"`
	Capabilities    []string          `json:"capabilities"`
	Tags            map[string]string `json:"tags"`
	Status          string            `json:"status"`
	Notes           string            `json:"notes"`
	Credentials     map[string]string `json:"credentials"`
	HostKeyStatus   string            `json:"host_key_status"`
}

// targetWrite is the body POST and PUT take: exactly these fields, every
// one (a PUT replaces the target).
type targetWrite struct {
	Name            string            `json:"name"`
	Address         string            `json:"address"`
	Engine          string            `json:"engine"`
	EngineVersion   string            `json:"engine_version"`
	RetentionDays   *int              `json:"retention_days"`
	DatabaseName    string            `json:"database_name"`
	TLSMode         string            `json:"tls_mode"`
	TLSCA           string            `json:"tls_ca"`
	AppUpstream     string            `json:"app_upstream"`
	AppEndpoints    []apiEndpoint     `json:"app_endpoints"`
	AppDependencies string            `json:"app_dependencies"`
	OSFamily        string            `json:"os_family"`
	Ports           map[string]int    `json:"ports"`
	Capabilities    []string          `json:"capabilities"`
	Tags            map[string]string `json:"tags"`
	Status          string            `json:"status"`
	Notes           string            `json:"notes"`
	Credentials     map[string]string `json:"credentials"`
}

func (t *apiTarget) write() targetWrite {
	return targetWrite{Name: t.Name, Address: t.Address, Engine: t.Engine, EngineVersion: t.EngineVersion, RetentionDays: t.RetentionDays,
		DatabaseName: t.DatabaseName, TLSMode: t.TLSMode, TLSCA: t.TLSCA, AppUpstream: t.AppUpstream, AppEndpoints: t.AppEndpoints, AppDependencies: t.AppDependencies,
		OSFamily: t.OSFamily, Ports: t.Ports, Capabilities: t.Capabilities, Tags: t.Tags, Status: t.Status, Notes: t.Notes, Credentials: t.Credentials}
}

type targetModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	Address         types.String `tfsdk:"address"`
	OSFamily        types.String `tfsdk:"os_family"`
	Engine          types.String `tfsdk:"engine"`
	EngineVersion   types.String `tfsdk:"engine_version"`
	DatabaseName    types.String `tfsdk:"database_name"`
	TLSMode         types.String `tfsdk:"tls_mode"`
	TLSCA           types.String `tfsdk:"tls_ca"`
	AppUpstream     types.String `tfsdk:"app_upstream"`
	AppEndpoints    types.List   `tfsdk:"app_endpoints"`
	AppDependencies types.String `tfsdk:"app_dependencies"`
	Ports           types.Map    `tfsdk:"ports"`
	Tags            types.Map    `tfsdk:"tags"`
	Credentials     types.Map    `tfsdk:"credentials"`
	Status          types.String `tfsdk:"status"`
	Notes           types.String `tfsdk:"notes"`
	RetentionDays   types.Int64  `tfsdk:"retention_days"`
	Capabilities    types.List   `tfsdk:"capabilities"`
	HostKeyStatus   types.String `tfsdk:"host_key_status"`
}

var endpointType = types.ObjectType{AttrTypes: map[string]attr.Type{"name": types.StringType, "url": types.StringType}}

type endpointModel struct {
	Name types.String `tfsdk:"name"`
	URL  types.String `tfsdk:"url"`
}

// from sets m to what the API answered.
func (m *targetModel) from(ctx context.Context, t *apiTarget) diag.Diagnostics {
	var diags diag.Diagnostics
	m.ID, m.Name, m.Address, m.OSFamily = types.StringValue(t.ID), types.StringValue(t.Name), types.StringValue(t.Address), types.StringValue(t.OSFamily)
	m.Engine, m.EngineVersion, m.DatabaseName = types.StringValue(t.Engine), types.StringValue(t.EngineVersion), types.StringValue(t.DatabaseName)
	m.TLSMode, m.TLSCA, m.AppUpstream = types.StringValue(t.TLSMode), types.StringValue(t.TLSCA), types.StringValue(t.AppUpstream)
	m.AppDependencies = types.StringValue(t.AppDependencies)
	m.Status, m.Notes, m.HostKeyStatus = types.StringValue(t.Status), types.StringValue(t.Notes), types.StringValue(t.HostKeyStatus)
	m.RetentionDays = types.Int64Null()
	if t.RetentionDays != nil {
		m.RetentionDays = types.Int64Value(int64(*t.RetentionDays))
	}
	eps := make([]endpointModel, 0, len(t.AppEndpoints))
	for _, e := range t.AppEndpoints {
		eps = append(eps, endpointModel{Name: types.StringValue(e.Name), URL: types.StringValue(e.URL)})
	}
	var d diag.Diagnostics
	m.AppEndpoints, d = types.ListValueFrom(ctx, endpointType, eps)
	diags.Append(d...)
	ports := map[string]int64{}
	for k, v := range t.Ports {
		ports[k] = int64(v)
	}
	m.Ports, d = types.MapValueFrom(ctx, types.Int64Type, ports)
	diags.Append(d...)
	m.Tags, d = types.MapValueFrom(ctx, types.StringType, nonNilMap(t.Tags))
	diags.Append(d...)
	m.Credentials, d = types.MapValueFrom(ctx, types.StringType, nonNilMap(t.Credentials))
	diags.Append(d...)
	caps := t.Capabilities
	if caps == nil {
		caps = []string{}
	}
	m.Capabilities, d = types.ListValueFrom(ctx, types.StringType, caps)
	diags.Append(d...)
	return diags
}

func nonNilMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// known reports whether v carries a value the plan set.
func known(v attr.Value) bool { return !v.IsNull() && !v.IsUnknown() }

// onto lays the plan over w: every field the plan knows replaces w's, a
// field it leaves to the gateway (unknown) keeps w's, so an update keeps
// what the probe found and what Terraform does not manage.
func (m *targetModel) onto(ctx context.Context, w *targetWrite) diag.Diagnostics {
	var diags diag.Diagnostics
	str := func(v types.String, dst *string) {
		if known(v) {
			*dst = v.ValueString()
		}
	}
	str(m.Name, &w.Name)
	str(m.Address, &w.Address)
	str(m.OSFamily, &w.OSFamily)
	str(m.Engine, &w.Engine)
	str(m.EngineVersion, &w.EngineVersion)
	str(m.DatabaseName, &w.DatabaseName)
	str(m.TLSMode, &w.TLSMode)
	str(m.TLSCA, &w.TLSCA)
	str(m.AppUpstream, &w.AppUpstream)
	str(m.AppDependencies, &w.AppDependencies)
	str(m.Status, &w.Status)
	str(m.Notes, &w.Notes)
	if !m.RetentionDays.IsUnknown() {
		w.RetentionDays = nil
		if !m.RetentionDays.IsNull() {
			v := int(m.RetentionDays.ValueInt64())
			w.RetentionDays = &v
		}
	}
	if known(m.AppEndpoints) {
		var eps []endpointModel
		diags.Append(m.AppEndpoints.ElementsAs(ctx, &eps, false)...)
		w.AppEndpoints = make([]apiEndpoint, 0, len(eps))
		for _, e := range eps {
			w.AppEndpoints = append(w.AppEndpoints, apiEndpoint{Name: e.Name.ValueString(), URL: e.URL.ValueString()})
		}
	}
	if known(m.Ports) {
		var ports map[string]int64
		diags.Append(m.Ports.ElementsAs(ctx, &ports, false)...)
		w.Ports = map[string]int{}
		for k, v := range ports {
			w.Ports[k] = int(v)
		}
	}
	if known(m.Tags) {
		w.Tags = map[string]string{}
		diags.Append(m.Tags.ElementsAs(ctx, &w.Tags, false)...)
	}
	if known(m.Credentials) {
		w.Credentials = map[string]string{}
		diags.Append(m.Credentials.ElementsAs(ctx, &w.Credentials, false)...)
	}
	return diags
}

type targetResource struct{ c *Client }

func newTargetResource() resource.Resource { return &targetResource{} }

func (r *targetResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_target"
}

func (r *targetResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	gateway := func(desc string) schema.StringAttribute {
		return schema.StringAttribute{Optional: true, Computed: true, Description: desc, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}}
	}
	empty := func(desc string) schema.StringAttribute {
		return schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), Description: desc}
	}
	resp.Schema = schema.Schema{
		Description: "A Zanskar target: a host (SSH, RDP, VNC, WinRM), a database (engine set) or an application (app_upstream set). Its credentials stay in the vault and are named by id (data.zanskar_credential).",
		Attributes: map[string]schema.Attribute{
			"id":             schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":           schema.StringAttribute{Required: true, Description: "Unique name."},
			"address":        gateway("Host name or IP. For an application, the gateway may fill it from app_upstream."),
			"os_family":      gateway("linux or windows, for a host."),
			"engine":         empty("For a database: postgres, mysql, mariadb, mssql."),
			"engine_version": empty("For a database, as shown."),
			"database_name":  empty("For a database: the one a session opens."),
			"tls_mode":       gateway("For a database: verify-full (the gateway's default), require or prefer."),
			"tls_ca":         empty("PEM: the CA a database's or an application's certificate is checked against."),
			"app_upstream":   empty("For an application: the URL its isolated browser opens."),
			"app_endpoints": schema.ListNestedAttribute{
				Optional: true, Computed: true, Default: listdefault.StaticValue(types.ListValueMust(endpointType, []attr.Value{})),
				Description: "For an application: its other endpoints, reached in the same session.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{Required: true},
					"url":  schema.StringAttribute{Required: true},
				}},
			},
			"app_dependencies": gateway("For an application: public (the default), its pages load from any public address on port 80 or 443; origins, from its upstream and endpoints only."),
			"ports": schema.MapAttribute{ElementType: types.Int64Type, Optional: true, Computed: true,
				PlanModifiers: []planmodifier.Map{mapplanmodifier.UseStateForUnknown()},
				Description:   "Ports by protocol (ssh, rdp, vnc, winrm, database); the gateway fills the usual ones."},
			"tags": schema.MapAttribute{ElementType: types.StringType, Optional: true, Computed: true,
				Default: mapdefault.StaticValue(types.MapValueMust(types.StringType, map[string]attr.Value{})), Description: "Tags policies match on."},
			"credentials": schema.MapAttribute{ElementType: types.StringType, Optional: true, Computed: true,
				Default:     mapdefault.StaticValue(types.MapValueMust(types.StringType, map[string]attr.Value{})),
				Description: "Credential ids by protocol, from data.zanskar_credential."},
			"status":         gateway("active (the default) or disabled."),
			"notes":          empty("Free text shown with the target."),
			"retention_days": schema.Int64Attribute{Optional: true, Description: "Recording retention for this target; unset follows the policy and the gateway."},
			"capabilities": schema.ListAttribute{ElementType: types.StringType, Computed: true,
				PlanModifiers: []planmodifier.List{listplanmodifier.UseStateForUnknown()}, Description: "What the gateway's probe found the target offers."},
			"host_key_status": schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Description: "Whether an administrator has trusted the host key; trusting it stays a person's act in the console."},
		},
	}
}

func (r *targetResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	r.c = clientFrom(req.ProviderData)
}

func (r *targetResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan targetModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	w := targetWrite{Tags: map[string]string{}, Credentials: map[string]string{}, AppEndpoints: []apiEndpoint{}}
	resp.Diagnostics.Append(plan.onto(ctx, &w)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var out apiTarget
	if err := r.c.do(ctx, http.MethodPost, "/targets", w, &out); err != nil {
		resp.Diagnostics.AddError("Create target", err.Error())
		return
	}
	resp.Diagnostics.Append(plan.from(ctx, &out)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *targetResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state targetModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var out apiTarget
	err := r.c.do(ctx, http.MethodGet, "/targets/"+url.PathEscape(state.ID.ValueString()), nil, &out)
	if IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Read target", err.Error())
		return
	}
	resp.Diagnostics.Append(state.from(ctx, &out)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *targetResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state targetModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := url.PathEscape(state.ID.ValueString())
	var cur apiTarget
	if err := r.c.do(ctx, http.MethodGet, "/targets/"+id, nil, &cur); err != nil {
		resp.Diagnostics.AddError("Update target", err.Error())
		return
	}
	w := cur.write()
	resp.Diagnostics.Append(plan.onto(ctx, &w)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var out apiTarget
	if err := r.c.do(ctx, http.MethodPut, "/targets/"+id, w, &out); err != nil {
		resp.Diagnostics.AddError("Update target", err.Error())
		return
	}
	resp.Diagnostics.Append(plan.from(ctx, &out)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *targetResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state targetModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.c.do(ctx, http.MethodDelete, "/targets/"+url.PathEscape(state.ID.ValueString()), nil, nil); err != nil && !IsNotFound(err) {
		resp.Diagnostics.AddError("Delete target", err.Error())
	}
}

func (r *targetResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
