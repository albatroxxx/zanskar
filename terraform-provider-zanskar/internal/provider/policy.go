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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// An access policy (ADR 0036): an audience (groups and users, by id) and
// grants, each naming targets or matching tags, with how they are reached.

type apiSubject struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

type apiGrantTarget struct {
	ID        string   `json:"id"`
	Protocols []string `json:"protocols"`
}

type apiTagMatch struct {
	Match     map[string][]string `json:"match"`
	Protocols []string            `json:"protocols"`
}

type apiWindow struct {
	Days []string `json:"days"`
	From string   `json:"from"`
	To   string   `json:"to"`
	TZ   string   `json:"tz"`
}

// apiGrant is a grant as the API answers it and takes it.
type apiGrant struct {
	ID                 string           `json:"id"`
	Kind               string           `json:"kind"`
	Targets            []apiGrantTarget `json:"targets"`
	Tags               *apiTagMatch     `json:"tags"`
	Access             string           `json:"access"`
	SignIn             string           `json:"sign_in"`
	RequireMFA         *bool            `json:"require_mfa"`
	AllowClipboard     bool             `json:"allow_clipboard"`
	AllowFileTransfer  bool             `json:"allow_file_transfer"`
	AllowDevTools      bool             `json:"allow_devtools"`
	RequireWatcher     bool             `json:"require_watcher"`
	IdleTimeoutMinutes int              `json:"idle_timeout_minutes"`
	MaxSessionMinutes  *int             `json:"max_session_minutes"`
	TimeWindows        []apiWindow      `json:"time_windows"`
	RetentionDays      *int             `json:"retention_days"`
}

// apiPolicy is a policy as the API answers it.
type apiPolicy struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Enabled     bool         `json:"enabled"`
	Subjects    []apiSubject `json:"subjects"`
	Grants      []apiGrant   `json:"grants"`
}

// policyWrite is the body POST and PUT take, exactly.
type policyWrite struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Enabled     *bool        `json:"enabled"`
	Subjects    []apiSubject `json:"subjects"`
	Grants      []apiGrant   `json:"grants"`
}

var (
	subjectType     = types.ObjectType{AttrTypes: map[string]attr.Type{"kind": types.StringType, "id": types.StringType}}
	grantTargetType = types.ObjectType{AttrTypes: map[string]attr.Type{"id": types.StringType, "protocols": types.ListType{ElemType: types.StringType}}}
	tagMatchType    = types.ObjectType{AttrTypes: map[string]attr.Type{"match": types.MapType{ElemType: types.ListType{ElemType: types.StringType}}, "protocols": types.ListType{ElemType: types.StringType}}}
	windowType      = types.ObjectType{AttrTypes: map[string]attr.Type{"days": types.ListType{ElemType: types.StringType}, "from": types.StringType, "to": types.StringType, "tz": types.StringType}}
	grantType       = types.ObjectType{AttrTypes: map[string]attr.Type{
		"id": types.StringType, "kind": types.StringType, "targets": types.ListType{ElemType: grantTargetType}, "tags": tagMatchType,
		"access": types.StringType, "sign_in": types.StringType, "require_mfa": types.BoolType, "allow_clipboard": types.BoolType,
		"allow_file_transfer": types.BoolType, "allow_devtools": types.BoolType, "require_watcher": types.BoolType,
		"idle_timeout_minutes": types.Int64Type, "max_session_minutes": types.Int64Type, "time_windows": types.ListType{ElemType: windowType},
		"retention_days": types.Int64Type,
	}}
)

type policyModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	Subjects    types.List   `tfsdk:"subjects"`
	Grants      types.List   `tfsdk:"grants"`
}

type subjectModel struct {
	Kind types.String `tfsdk:"kind"`
	ID   types.String `tfsdk:"id"`
}

type grantTargetModel struct {
	ID        types.String `tfsdk:"id"`
	Protocols []string     `tfsdk:"protocols"`
}

type tagMatchModel struct {
	Match     map[string][]string `tfsdk:"match"`
	Protocols []string            `tfsdk:"protocols"`
}

type windowModel struct {
	Days []string     `tfsdk:"days"`
	From types.String `tfsdk:"from"`
	To   types.String `tfsdk:"to"`
	TZ   types.String `tfsdk:"tz"`
}

type grantModel struct {
	ID                 types.String `tfsdk:"id"`
	Kind               types.String `tfsdk:"kind"`
	Targets            types.List   `tfsdk:"targets"`
	Tags               types.Object `tfsdk:"tags"`
	Access             types.String `tfsdk:"access"`
	SignIn             types.String `tfsdk:"sign_in"`
	RequireMFA         types.Bool   `tfsdk:"require_mfa"`
	AllowClipboard     types.Bool   `tfsdk:"allow_clipboard"`
	AllowFileTransfer  types.Bool   `tfsdk:"allow_file_transfer"`
	AllowDevTools      types.Bool   `tfsdk:"allow_devtools"`
	RequireWatcher     types.Bool   `tfsdk:"require_watcher"`
	IdleTimeoutMinutes types.Int64  `tfsdk:"idle_timeout_minutes"`
	MaxSessionMinutes  types.Int64  `tfsdk:"max_session_minutes"`
	TimeWindows        types.List   `tfsdk:"time_windows"`
	RetentionDays      types.Int64  `tfsdk:"retention_days"`
}

// objectAsOptions reads a known object into a struct.
var objectAsOptions = basetypes.ObjectAsOptions{}

func intPtr(v types.Int64) *int {
	if !known(v) {
		return nil
	}
	n := int(v.ValueInt64())
	return &n
}

func int64Of(p *int) types.Int64 {
	if p == nil {
		return types.Int64Null()
	}
	return types.Int64Value(int64(*p))
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// write turns the plan into the body the API takes. A grant's id, known
// from the state for a grant that was there, keeps the grant the same one
// (requests and sessions name it); a new grant goes without and gets one.
func (m *policyModel) write(ctx context.Context) (policyWrite, diag.Diagnostics) {
	var diags diag.Diagnostics
	enabled := !m.Enabled.IsNull() && m.Enabled.ValueBool()
	if !known(m.Enabled) {
		enabled = true
	}
	w := policyWrite{Name: m.Name.ValueString(), Description: m.Description.ValueString(), Enabled: &enabled, Subjects: []apiSubject{}, Grants: []apiGrant{}}
	var subs []subjectModel
	diags.Append(m.Subjects.ElementsAs(ctx, &subs, false)...)
	for _, s := range subs {
		w.Subjects = append(w.Subjects, apiSubject{Kind: s.Kind.ValueString(), ID: s.ID.ValueString()})
	}
	var grants []grantModel
	diags.Append(m.Grants.ElementsAs(ctx, &grants, false)...)
	for _, g := range grants {
		ag := apiGrant{Kind: g.Kind.ValueString(), Access: g.Access.ValueString(), SignIn: g.SignIn.ValueString(),
			AllowClipboard: g.AllowClipboard.ValueBool(), AllowFileTransfer: g.AllowFileTransfer.ValueBool(), AllowDevTools: g.AllowDevTools.ValueBool(),
			RequireWatcher: g.RequireWatcher.ValueBool(), IdleTimeoutMinutes: int(g.IdleTimeoutMinutes.ValueInt64()),
			MaxSessionMinutes: intPtr(g.MaxSessionMinutes), RetentionDays: intPtr(g.RetentionDays), Targets: []apiGrantTarget{}, TimeWindows: []apiWindow{}}
		if known(g.ID) {
			ag.ID = g.ID.ValueString()
		}
		mfa := !known(g.RequireMFA) || g.RequireMFA.ValueBool()
		ag.RequireMFA = &mfa
		var targets []grantTargetModel
		diags.Append(g.Targets.ElementsAs(ctx, &targets, false)...)
		for _, t := range targets {
			ag.Targets = append(ag.Targets, apiGrantTarget{ID: t.ID.ValueString(), Protocols: orEmpty(t.Protocols)})
		}
		if known(g.Tags) {
			var tm tagMatchModel
			diags.Append(g.Tags.As(ctx, &tm, objectAsOptions)...)
			ag.Tags = &apiTagMatch{Match: tm.Match, Protocols: orEmpty(tm.Protocols)}
		}
		var windows []windowModel
		diags.Append(g.TimeWindows.ElementsAs(ctx, &windows, false)...)
		for _, tw := range windows {
			ag.TimeWindows = append(ag.TimeWindows, apiWindow{Days: orEmpty(tw.Days), From: tw.From.ValueString(), To: tw.To.ValueString(), TZ: tw.TZ.ValueString()})
		}
		w.Grants = append(w.Grants, ag)
	}
	return w, diags
}

// from sets m to what the API answered.
func (m *policyModel) from(ctx context.Context, p *apiPolicy) diag.Diagnostics {
	var diags, d diag.Diagnostics
	m.ID, m.Name, m.Description, m.Enabled = types.StringValue(p.ID), types.StringValue(p.Name), types.StringValue(p.Description), types.BoolValue(p.Enabled)
	subs := make([]subjectModel, 0, len(p.Subjects))
	for _, s := range p.Subjects {
		subs = append(subs, subjectModel{Kind: types.StringValue(s.Kind), ID: types.StringValue(s.ID)})
	}
	m.Subjects, d = types.ListValueFrom(ctx, subjectType, subs)
	diags.Append(d...)
	grants := make([]grantModel, 0, len(p.Grants))
	for _, g := range p.Grants {
		gm := grantModel{ID: types.StringValue(g.ID), Kind: types.StringValue(g.Kind), Access: types.StringValue(g.Access), SignIn: types.StringValue(g.SignIn),
			RequireMFA: types.BoolValue(g.RequireMFA == nil || *g.RequireMFA), AllowClipboard: types.BoolValue(g.AllowClipboard),
			AllowFileTransfer: types.BoolValue(g.AllowFileTransfer), AllowDevTools: types.BoolValue(g.AllowDevTools), RequireWatcher: types.BoolValue(g.RequireWatcher),
			IdleTimeoutMinutes: types.Int64Value(int64(g.IdleTimeoutMinutes)), MaxSessionMinutes: int64Of(g.MaxSessionMinutes), RetentionDays: int64Of(g.RetentionDays)}
		targets := make([]grantTargetModel, 0, len(g.Targets))
		for _, t := range g.Targets {
			targets = append(targets, grantTargetModel{ID: types.StringValue(t.ID), Protocols: orEmpty(t.Protocols)})
		}
		gm.Targets, d = types.ListValueFrom(ctx, grantTargetType, targets)
		diags.Append(d...)
		gm.Tags = types.ObjectNull(tagMatchType.AttrTypes)
		if g.Tags != nil {
			gm.Tags, d = types.ObjectValueFrom(ctx, tagMatchType.AttrTypes, tagMatchModel{Match: g.Tags.Match, Protocols: orEmpty(g.Tags.Protocols)})
			diags.Append(d...)
		}
		windows := make([]windowModel, 0, len(g.TimeWindows))
		for _, tw := range g.TimeWindows {
			windows = append(windows, windowModel{Days: orEmpty(tw.Days), From: types.StringValue(tw.From), To: types.StringValue(tw.To), TZ: types.StringValue(tw.TZ)})
		}
		gm.TimeWindows, d = types.ListValueFrom(ctx, windowType, windows)
		diags.Append(d...)
		grants = append(grants, gm)
	}
	m.Grants, d = types.ListValueFrom(ctx, grantType, grants)
	diags.Append(d...)
	return diags
}

type policyResource struct{ c *Client }

func newPolicyResource() resource.Resource { return &policyResource{} }

func (r *policyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_access_policy"
}

func strings2() schema.ListAttribute {
	return schema.ListAttribute{ElementType: types.StringType, Required: true}
}

func (r *policyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	falseDefault := func(desc string) schema.BoolAttribute {
		return schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false), Description: desc}
	}
	resp.Schema = schema.Schema{
		Description: "A Zanskar access policy: who (groups and users, by id) and grants (what they reach and how). Its review stays a person's act in the console.",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":        schema.StringAttribute{Required: true},
			"description": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("")},
			"enabled":     schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
			"subjects": schema.ListNestedAttribute{
				Optional: true, Computed: true, Default: listdefault.StaticValue(types.ListValueMust(subjectType, []attr.Value{})),
				Description: "The audience: kind group or user, and the id (data.zanskar_group for a group by name).",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"kind": schema.StringAttribute{Required: true},
					"id":   schema.StringAttribute{Required: true},
				}},
			},
			"grants": schema.ListNestedAttribute{
				Required:    true,
				Description: "What the audience reaches, each grant of one kind: host, autoscaling, database or application.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"id":   schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
					"kind": schema.StringAttribute{Required: true},
					"targets": schema.ListNestedAttribute{
						Optional: true, Computed: true, Default: listdefault.StaticValue(types.ListValueMust(grantTargetType, []attr.Value{})),
						Description: "Targets by id, each with the protocols it is reached over.",
						NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
							"id":        schema.StringAttribute{Required: true},
							"protocols": strings2(),
						}},
					},
					"tags": schema.SingleNestedAttribute{
						Optional:    true,
						Description: "Targets by tag: every key matching one of its values, over these protocols.",
						Attributes: map[string]schema.Attribute{
							"match":     schema.MapAttribute{ElementType: types.ListType{ElemType: types.StringType}, Required: true},
							"protocols": strings2(),
						},
					},
					"access":               schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("standing"), Description: "standing or approval."},
					"sign_in":              schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("target"), Description: "target (the vaulted credential) or own."},
					"require_mfa":          schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
					"allow_clipboard":      falseDefault(""),
					"allow_file_transfer":  falseDefault(""),
					"allow_devtools":       falseDefault("Applications only."),
					"require_watcher":      falseDefault("Four eyes: a second person watches (ADR 0042)."),
					"idle_timeout_minutes": schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(15)},
					"max_session_minutes":  schema.Int64Attribute{Optional: true},
					"time_windows": schema.ListNestedAttribute{
						Optional: true, Computed: true, Default: listdefault.StaticValue(types.ListValueMust(windowType, []attr.Value{})),
						Description: "When the grant admits; none is always.",
						NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
							"days": strings2(),
							"from": schema.StringAttribute{Required: true},
							"to":   schema.StringAttribute{Required: true},
							"tz":   schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("UTC")},
						}},
					},
					"retention_days": schema.Int64Attribute{Optional: true},
				}},
			},
		},
	}
}

func (r *policyResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	r.c = clientFrom(req.ProviderData)
}

func (r *policyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan policyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	w, diags := plan.write(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	var out apiPolicy
	if err := r.c.do(ctx, http.MethodPost, "/access-policies", w, &out); err != nil {
		resp.Diagnostics.AddError("Create access policy", err.Error())
		return
	}
	resp.Diagnostics.Append(plan.from(ctx, &out)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *policyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state policyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var out apiPolicy
	err := r.c.do(ctx, http.MethodGet, "/access-policies/"+url.PathEscape(state.ID.ValueString()), nil, &out)
	if IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Read access policy", err.Error())
		return
	}
	resp.Diagnostics.Append(state.from(ctx, &out)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *policyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state policyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	w, diags := plan.write(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	var out apiPolicy
	if err := r.c.do(ctx, http.MethodPut, "/access-policies/"+url.PathEscape(state.ID.ValueString()), w, &out); err != nil {
		resp.Diagnostics.AddError("Update access policy", err.Error())
		return
	}
	resp.Diagnostics.Append(plan.from(ctx, &out)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *policyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state policyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.c.do(ctx, http.MethodDelete, "/access-policies/"+url.PathEscape(state.ID.ValueString()), nil, nil); err != nil && !IsNotFound(err) {
		resp.Diagnostics.AddError("Delete access policy", err.Error())
	}
}

func (r *policyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
