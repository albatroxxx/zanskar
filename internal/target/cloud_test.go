// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/cloud"
	"github.com/albatroxxx/zanskar/internal/credential"
	"github.com/albatroxxx/zanskar/internal/protocol"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/store/storetest"
)

const (
	adminRole = "arn:aws:iam::123456789012:role/Admin"
	readRole  = "arn:aws:iam::123456789012:role/ReadOnly"
	otherRole = "arn:aws:iam::210987654321:role/Admin"
)

// A cloud account's role (ADR 0050, 1) is a target whose role ARN makes it
// one: the account is read from the ARN, the ExternalId minted, the session
// bounded, the address the STS endpoint; it serves cloud and nothing else,
// binds no credential and takes no host field.
func TestCloudTargetValidate(t *testing.T) {
	r := &Target{Name: "prod admin", CloudRoleARN: " " + adminRole + " ", CloudRegion: " EU-West-1 "}
	if err := r.Validate(); err != nil {
		t.Fatalf("valid role: %v", err)
	}
	if !r.IsCloud() || r.Kind() != protocol.KindCloud || r.OSFamily != OtherOS {
		t.Fatalf("kind %q os %q", r.Kind(), r.OSFamily)
	}
	if r.CloudPlatform != CloudPlatformAWS || r.CloudAccountID != "123456789012" || r.CloudRoleARN != adminRole || r.CloudRegion != "eu-west-1" || r.CloudMaxMinutes != CloudMaxMinutesDefault {
		t.Fatalf("defaults: %+v", r)
	}
	if !cloud.ExternalIDRe.MatchString(r.CloudExternalID) {
		t.Fatalf("external id not minted: %q", r.CloudExternalID)
	}
	if r.Address != "sts.eu-west-1.amazonaws.com" || len(r.Capabilities) != 1 || r.Capabilities[0] != Cloud || len(r.Ports) != 0 {
		t.Fatalf("address %q capabilities %v ports %v", r.Address, r.Capabilities, r.Ports)
	}
	if r.CloudAccountLabel() != "123456789012" || r.CloudRoleName() != "Admin" {
		t.Fatalf("label %q role %q", r.CloudAccountLabel(), r.CloudRoleName())
	}
	// Given values are kept: the id the account's administrator typed, the
	// ExternalId a configuration file carries, the alias, the maximum.
	given := &Target{Name: "x", CloudRoleARN: adminRole, CloudAccountID: " 123456789012 ", CloudAccountAlias: " prod ", CloudExternalID: "zanskar-" + strings.Repeat("c", 32), CloudMaxMinutes: 15}
	if err := given.Validate(); err != nil || given.CloudExternalID != "zanskar-"+strings.Repeat("c", 32) || given.CloudAccountAlias != "prod" || given.CloudMaxMinutes != 15 || given.Address != "sts.amazonaws.com" {
		t.Fatalf("given values: %v %+v", err, given)
	}
	if given.CloudAccountLabel() != "prod" {
		t.Fatalf("label %q", given.CloudAccountLabel())
	}
	// A host is not a cloud role, and carries none of its fields.
	host := &Target{Name: "web", Address: "10.0.0.5", OSFamily: Linux}
	if err := host.Validate(); err != nil || host.IsCloud() || host.Kind() != protocol.KindHost || host.CloudExternalID != "" || host.CloudMaxMinutes != 0 {
		t.Fatalf("host: %v %+v", err, host)
	}

	long := strings.Repeat("a", CloudAccountAliasMax+1)
	for _, tc := range []struct {
		name string
		t    Target
		want string
	}{
		{"not a role arn", Target{Name: "x", CloudRoleARN: "arn:aws:iam::123456789012:user/bob"}, "cloud_role_arn must be an IAM role ARN"},
		{"a role arn with a short account", Target{Name: "x", CloudRoleARN: "arn:aws:iam::1234:role/Admin"}, "cloud_role_arn must be"},
		{"an account that is not 12 digits", Target{Name: "x", CloudRoleARN: adminRole, CloudAccountID: "12345"}, "12-digit account id"},
		{"an account that is not the role's", Target{Name: "x", CloudRoleARN: adminRole, CloudAccountID: "210987654321"}, "is not the role's account"},
		{"an alias too long", Target{Name: "x", CloudRoleARN: adminRole, CloudAccountAlias: long}, "at most 64 characters"},
		{"an alias with a control character", Target{Name: "x", CloudRoleARN: adminRole, CloudAccountAlias: "prod\x07"}, "cloud_account_alias"},
		{"an external id of another shape", Target{Name: "x", CloudRoleARN: adminRole, CloudExternalID: "my-secret"}, "cloud_external_id must be one Zanskar generated"},
		{"a maximum below 15", Target{Name: "x", CloudRoleARN: adminRole, CloudMaxMinutes: 14}, "cloud_max_minutes must be 15-720"},
		{"a maximum above 720", Target{Name: "x", CloudRoleARN: adminRole, CloudMaxMinutes: 721}, "cloud_max_minutes must be 15-720"},
		{"a region that is not one", Target{Name: "x", CloudRoleARN: adminRole, CloudRegion: "mars"}, "cloud_region must be an AWS region"},
		{"a platform not built", Target{Name: "x", CloudRoleARN: adminRole, CloudPlatform: "gcp"}, "cloud_platform must be one of aws"},
		{"with an engine", Target{Name: "x", CloudRoleARN: adminRole, Engine: "postgres"}, "not two of these"},
		{"with an upstream", Target{Name: "x", CloudRoleARN: adminRole, AppUpstream: "http://app"}, "not two of these"},
		{"with an api server", Target{Name: "x", CloudRoleARN: adminRole, KubeAPIServer: "https://k8s"}, "not two of these"},
		{"a host port", Target{Name: "x", CloudRoleARN: adminRole, Ports: map[Protocol]int{SSH: 22}}, "has no ssh port"},
		{"a credential on the slot", Target{Name: "x", CloudRoleARN: adminRole, Credentials: map[Protocol]string{Cloud: "c1"}}, "binds no credential"},
		{"an account without a role", Target{Name: "x", Address: "10.0.0.1", OSFamily: Linux, CloudAccountID: "123456789012"}, "cloud_account_id belongs to a cloud account's role"},
		{"an alias without a role", Target{Name: "x", Address: "10.0.0.1", OSFamily: Linux, CloudAccountAlias: "prod"}, "cloud_account_alias belongs to"},
		{"a maximum without a role", Target{Name: "x", Address: "10.0.0.1", OSFamily: Linux, CloudMaxMinutes: 60}, "cloud_max_minutes belongs to"},
		{"a region without a role", Target{Name: "x", Address: "10.0.0.1", OSFamily: Linux, CloudRegion: "eu-west-1"}, "cloud_region belongs to"},
		{"a platform without a role", Target{Name: "x", Address: "10.0.0.1", OSFamily: Linux, CloudPlatform: "aws"}, "cloud_platform belongs to"},
		{"an external id without a role", Target{Name: "x", Address: "10.0.0.1", OSFamily: Linux, CloudExternalID: "zanskar-" + strings.Repeat("c", 32)}, "cloud_external_id belongs to"},
	} {
		err := tc.t.Validate()
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
	slot := &Target{Name: "x", CloudRoleARN: adminRole, Credentials: map[Protocol]string{Cloud: "c1"}}
	if err := slot.Validate(); !errors.Is(err, ErrNoCredentialSlot) {
		t.Fatalf("the slot refusal has its own error: %v", err)
	}
}

// The seven columns survive the store on both engines; the kind filter finds
// a role and keeps it out of the hosts; the inventory counts roles and the
// distinct accounts they are in, active ones only.
func TestCloudTargetOnEachBackend(t *testing.T) {
	storetest.ForEachBackend(t, func(t *testing.T, db *store.DB) {
		ctx := context.Background()
		r := NewRepo(db)
		admin := &Target{Name: "prod admin", CloudRoleARN: adminRole, CloudAccountAlias: "prod", CloudRegion: "eu-west-1", CloudMaxMinutes: 120, Tags: map[string]string{"account": "prod"}}
		read := &Target{Name: "prod read", CloudRoleARN: readRole, CloudAccountAlias: "prod"}
		other := &Target{Name: "dev admin", CloudRoleARN: otherRole, CloudRegion: "us-east-1"}
		off := &Target{Name: "old admin", CloudRoleARN: "arn:aws:iam::333333333333:role/Admin", Status: StatusDisabled}
		host := &Target{Name: "web", Address: "10.0.0.9", OSFamily: Linux}
		for _, tg := range []*Target{admin, read, other, off, host} {
			if err := r.Create(ctx, tg); err != nil {
				t.Fatalf("%s: %v", tg.Name, err)
			}
		}
		got, err := r.Get(ctx, admin.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.CloudPlatform != "aws" || got.CloudAccountID != "123456789012" || got.CloudAccountAlias != "prod" || got.CloudRoleARN != adminRole ||
			got.CloudExternalID != admin.CloudExternalID || got.CloudMaxMinutes != 120 || got.CloudRegion != "eu-west-1" || got.Kind() != protocol.KindCloud {
			t.Fatalf("round trip: %+v", got)
		}
		if got.Address != "sts.eu-west-1.amazonaws.com" || len(got.Capabilities) != 1 || got.Capabilities[0] != Cloud || got.OSFamily != OtherOS {
			t.Fatalf("derived fields: address %q capabilities %v os %q", got.Address, got.Capabilities, got.OSFamily)
		}
		if got2, _ := r.Get(ctx, read.ID); got2.CloudRegion != "" || got2.CloudMaxMinutes != 60 || got2.Address != "sts.amazonaws.com" {
			t.Fatalf("defaults stored: %+v", got2)
		}
		if h, _ := r.Get(ctx, host.ID); h.IsCloud() || h.CloudExternalID != "" || h.CloudMaxMinutes != 0 || h.CloudPlatform != "" {
			t.Fatalf("a host carries no cloud fields: %+v", h)
		}
		// An edit keeps the ExternalId and changes what was changed.
		got.CloudAccountAlias, got.CloudMaxMinutes = "production", 240
		if err := r.Update(ctx, got); err != nil {
			t.Fatal(err)
		}
		if again, _ := r.Get(ctx, admin.ID); again.CloudAccountAlias != "production" || again.CloudMaxMinutes != 240 || again.CloudExternalID != admin.CloudExternalID {
			t.Fatalf("after the edit: %+v", again)
		}
		names := func(kind string) []string {
			out, _, err := r.List(ctx, "", 50, ListFilter{Kind: kind})
			if err != nil {
				t.Fatal(err)
			}
			var n []string
			for _, x := range out {
				n = append(n, x.Name)
			}
			return n
		}
		if n := names(KindCloud); len(n) != 4 {
			t.Fatalf("kind=cloud lists %v", n)
		}
		if n := names(KindHost); len(n) != 1 || n[0] != "web" {
			t.Fatalf("kind=host lists %v, a role is not a host", n)
		}
		inv, err := r.CountInventory(ctx)
		if err != nil || inv.CloudRoles != 3 || inv.CloudAccounts != 2 || inv.Hosts != 1 {
			t.Fatalf("inventory: %v %+v", err, inv)
		}
	})
}

// fakeRoleMinter stands in for STS: it records the mint it was asked for
// and answers as told.
type fakeRoleMinter struct {
	mu          sync.Mutex
	last        cloud.MintRequest
	mintErr     error
	identityErr error
	arn         string
}

func (m *fakeRoleMinter) Mint(_ context.Context, req cloud.MintRequest) (cloud.Credentials, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.last = req
	if m.mintErr != nil {
		return cloud.Credentials{}, m.mintErr
	}
	return cloud.Credentials{AccessKeyID: "ASIAFAKE", SecretAccessKey: "s", SessionToken: "t", Expires: time.Now().Add(req.Duration),
		AssumedARN: "arn:aws:sts::123456789012:assumed-role/Admin/" + req.SessionName}, nil
}

func (m *fakeRoleMinter) CallerIdentity(context.Context, cloud.Credentials) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.arn, m.identityErr
}

// Setup (ADR 0050, 1): pending with no policy while the gateway's principal
// is unknown, never a placeholder; with one, the trust policy naming it and
// the ExternalId, and the two pastes naming the role.
func TestCloudSetup(t *testing.T) {
	ctx := context.Background()
	tg := &Target{Name: "prod admin", CloudRoleARN: adminRole}
	if err := tg.Validate(); err != nil {
		t.Fatal(err)
	}
	pending := (&AdminHandler{}).cloudSetupFor(ctx, tg)
	if !pending.Pending || pending.Principal != nil || pending.TrustPolicy != "" || pending.CLI != "" || pending.CloudFormation != "" || pending.ExternalID != tg.CloudExternalID {
		t.Fatalf("pending: %+v", pending)
	}
	b, _ := json.Marshal(pending)
	if !strings.Contains(string(b), `"principal":null`) || !strings.Contains(string(b), `"trust_policy":""`) {
		t.Fatalf("pending JSON: %s", b)
	}
	ready := (&AdminHandler{Identity: cloud.NewGatewayIdentity("arn:aws:iam::111111111111:role/zanskar-gw")}).cloudSetupFor(ctx, tg)
	if ready.Pending || ready.Principal == nil || *ready.Principal != "arn:aws:iam::111111111111:role/zanskar-gw" {
		t.Fatalf("ready: %+v", ready)
	}
	for _, want := range []string{`"arn:aws:iam::111111111111:role/zanskar-gw"`, `"sts:SetSourceIdentity"`, `"sts:TagSession"`, `"sts:ExternalId": "` + tg.CloudExternalID + `"`} {
		if !strings.Contains(ready.TrustPolicy, want) {
			t.Errorf("trust policy lacks %s:\n%s", want, ready.TrustPolicy)
		}
	}
	if !strings.Contains(ready.CLI, "--role-name Admin") || !strings.Contains(ready.CloudFormation, "RoleName: Admin") {
		t.Fatalf("pastes:\n%s\n%s", ready.CLI, ready.CloudFormation)
	}
}

// RunCloudTest (ADR 0050, 1): the mint as a session makes it, with a test
// source identity and tag; the stage that refused, named; GetCallerIdentity
// as the second stage; CloudTrail not tried yet (null).
func TestRunCloudTestStages(t *testing.T) {
	ctx := context.Background()
	tg := &Target{Name: "prod admin", CloudRoleARN: adminRole, CloudMaxMinutes: 90}
	if err := tg.Validate(); err != nil {
		t.Fatal(err)
	}
	m := &fakeRoleMinter{arn: "arn:aws:sts::123456789012:assumed-role/Admin/zanskar-test-deadbeef"}
	res := RunCloudTest(ctx, m, tg)
	if !res.OK || res.Stage != "" || res.AssumedARN != m.arn || res.LookupEvents != nil || !strings.Contains(res.Message, "1h30m") {
		t.Fatalf("ok: %+v", res)
	}
	if b, _ := json.Marshal(res); !strings.Contains(string(b), `"lookup_events":null`) || !strings.Contains(string(b), `"stage":""`) {
		t.Fatalf("JSON: %s", b)
	}
	req := m.last
	if req.RoleARN != adminRole || req.ExternalID != tg.CloudExternalID || req.SourceIdentity != "zanskar-test" || req.Duration != 90*time.Minute || req.Tags["zanskar:test"] != "1" {
		t.Fatalf("the mint: %+v", req)
	}
	if !regexp.MustCompile(`^zanskar-test-[0-9a-f]{8}$`).MatchString(req.SessionName) {
		t.Fatalf("session name %q", req.SessionName)
	}

	m.mintErr = errors.New("cloud: the role could not be assumed: User is not authorized")
	m.mintErr = errors.Join(cloud.ErrMintRefused, m.mintErr)
	res = RunCloudTest(ctx, m, tg)
	if res.OK || res.Stage != CloudStageAssume || !strings.Contains(res.Message, tg.CloudExternalID) || !strings.Contains(res.Message, "sts:TagSession") {
		t.Fatalf("assume refused: %+v", res)
	}
	m.mintErr = errors.Join(cloud.ErrMintDuration, errors.New("exceeds the MaxSessionDuration"))
	res = RunCloudTest(ctx, m, tg)
	if res.OK || res.Stage != CloudStageDuration || !strings.Contains(res.Message, "below 90 minutes") || !strings.Contains(res.Message, "lower cloud_max_minutes") {
		t.Fatalf("duration refused: %+v", res)
	}
	m.mintErr = errors.New("dial tcp: i/o timeout")
	if res = RunCloudTest(ctx, m, tg); res.OK || res.Stage != CloudStageAssume || res.Message != "dial tcp: i/o timeout" {
		t.Fatalf("network: %+v", res)
	}
	m.mintErr, m.identityErr = nil, errors.New("cloud: GetCallerIdentity: AccessDenied: explicit deny")
	res = RunCloudTest(ctx, m, tg)
	if res.OK || res.Stage != CloudStageIdentity || !strings.Contains(res.AssumedARN, "assumed-role/Admin/zanskar-test-") || !strings.Contains(res.Message, "permissions boundary") {
		t.Fatalf("identity refused: %+v", res)
	}
	// STS answering no ARN falls back to the mint's.
	m.identityErr, m.arn = nil, ""
	if res = RunCloudTest(ctx, m, tg); !res.OK || !strings.Contains(res.AssumedARN, "assumed-role/Admin/zanskar-test-") {
		t.Fatalf("no arn from identity: %+v", res)
	}
}

// The role through the API, as the console's Add role form sends it (an
// empty address, os other, the maximum as a number or null): the ExternalId
// is minted on create and fixed after, the setup and the test answer, the
// slot binds nothing, and the edits that end live sessions are the account,
// the role and the ExternalId, not the alias.
func TestCloudTargetAPI(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	m := &fakeRoleMinter{arn: "arn:aws:sts::123456789012:assumed-role/Admin/zanskar-test-00000000"}
	prev := NewRoleMinter
	NewRoleMinter = func(context.Context, string) (cloud.RoleMinter, error) { return m, nil }
	t.Cleanup(func() { NewRoleMinter = prev })

	body := func(patch map[string]any) map[string]any {
		b := map[string]any{"name": "prod admin", "address": "", "os_family": "other", "cloud_platform": "aws", "cloud_account_id": "123456789012",
			"cloud_account_alias": "prod", "cloud_role_arn": adminRole, "cloud_external_id": "", "cloud_max_minutes": nil, "cloud_region": "eu-west-1",
			"tags": map[string]string{"account": "prod"}, "notes": ""}
		for k, v := range patch {
			b[k] = v
		}
		return b
	}
	code, out := e.do("POST", "/api/v1/targets", body(nil), e.admin)
	if code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	id, externalID := out["id"].(string), out["cloud_external_id"].(string)
	if !cloud.ExternalIDRe.MatchString(externalID) || out["cloud_max_minutes"] != float64(60) || out["address"] != "sts.eu-west-1.amazonaws.com" || out["cloud_platform"] != "aws" {
		t.Fatalf("created: %v", out)
	}
	if caps, _ := out["capabilities"].([]any); len(caps) != 1 || caps[0] != "cloud" {
		t.Fatalf("capabilities: %v", out["capabilities"])
	}
	if code, out := e.do("GET", "/api/v1/targets?kind=cloud", nil, e.admin); code != 200 || len(out["items"].([]any)) != 1 {
		t.Fatalf("kind=cloud: %d %v", code, out)
	}
	if code, out := e.do("GET", "/api/v1/targets?kind=host", nil, e.admin); code != 200 || len(out["items"].([]any)) != 0 {
		t.Fatalf("kind=host: %d %v", code, out)
	}

	// Setup: pending here (no identity on this handler), with the ExternalId.
	code, out = e.do("GET", "/api/v1/targets/"+id+"/cloud/setup", nil, e.admin)
	if code != 200 || out["pending"] != true || out["principal"] != nil || out["trust_policy"] != "" || out["external_id"] != externalID {
		t.Fatalf("setup: %d %v", code, out)
	}
	code, host := e.do("POST", "/api/v1/targets", map[string]any{"name": "box", "address": "10.0.0.1", "os_family": "linux"}, e.admin)
	if code != 201 {
		t.Fatal(host)
	}
	if code, out := e.do("GET", "/api/v1/targets/"+host["id"].(string)+"/cloud/setup", nil, e.admin); code != 409 || out["code"] != "not_a_cloud_role" {
		t.Fatalf("setup on a host: %d %v", code, out)
	}
	if code, out := e.do("POST", "/api/v1/targets/"+host["id"].(string)+"/cloud/test", nil, e.admin); code != 409 || out["code"] != "not_a_cloud_role" {
		t.Fatalf("test on a host: %d %v", code, out)
	}

	// Test: the role assumed with the target's ExternalId and maximum; the
	// outcome is an event with the stage.
	code, out = e.do("POST", "/api/v1/targets/"+id+"/cloud/test", nil, e.admin)
	if code != 200 || out["ok"] != true || out["assumed_arn"] != m.arn || out["stage"] != "" {
		t.Fatalf("test: %d %v", code, out)
	}
	if v, has := out["lookup_events"]; !has || v != nil {
		t.Fatalf("lookup_events must be null until phase C: %v", out)
	}
	if m.last.ExternalID != externalID || m.last.Duration != time.Hour {
		t.Fatalf("the test's mint: %+v", m.last)
	}
	m.mintErr = errors.Join(cloud.ErrMintRefused, errors.New("denied"))
	if code, out := e.do("POST", "/api/v1/targets/"+id+"/cloud/test", nil, e.admin); code != 200 || out["ok"] != false || out["stage"] != "assume" {
		t.Fatalf("refused test: %d %v", code, out)
	}
	m.mintErr = nil
	tests := auditActions(t, e, audit.TargetCloudTest)
	if len(tests) != 2 || tests[0].Outcome != audit.Failure || tests[1].Outcome != audit.Success || !strings.Contains(string(tests[0].Details), `"stage":"assume"`) {
		t.Fatalf("test events: %+v", tests)
	}

	// No credential slot: on the slot route and in a create body alike.
	pw := &credential.Credential{Name: "pw", Type: credential.TypePassword, Mode: credential.ModeVaulted, Username: "u"}
	if err := e.vault.Create(ctx, pw, &credential.Secret{Password: "p"}, ""); err != nil {
		t.Fatal(err)
	}
	if code, out := e.do("PUT", "/api/v1/targets/"+id+"/credentials/cloud", map[string]string{"credential_id": pw.ID}, e.admin); code != 400 || out["code"] != "no_credential_slot" {
		t.Fatalf("slot: %d %v", code, out)
	}
	if code, out := e.do("POST", "/api/v1/targets", body(map[string]any{"name": "with a slot", "credentials": map[string]string{"cloud": pw.ID}}), e.admin); code != 400 || out["code"] != "no_credential_slot" {
		t.Fatalf("create with a slot: %d %v", code, out)
	}

	// The ExternalId is fixed: left out it stays, changed it is refused.
	put := func(patch map[string]any) (int, map[string]any) {
		t.Helper()
		return e.do("PUT", "/api/v1/targets/"+id, body(patch), e.admin)
	}
	e.revoker.disabled = nil
	if code, out := put(map[string]any{"cloud_account_alias": "production"}); code != 200 || out["cloud_external_id"] != externalID || out["cloud_account_alias"] != "production" {
		t.Fatalf("alias edit: %d %v", code, out)
	}
	if len(e.revoker.disabled) != 0 {
		t.Fatalf("an alias edit ended the sessions: %v", e.revoker.disabled)
	}
	if code, out := put(map[string]any{"cloud_external_id": "zanskar-" + strings.Repeat("d", 32)}); code != 400 || out["code"] != "external_id_fixed" {
		t.Fatalf("external id edit: %d %v", code, out)
	}
	if code, out := put(map[string]any{"cloud_external_id": externalID, "cloud_max_minutes": 120}); code != 200 || out["cloud_max_minutes"] != float64(120) {
		t.Fatalf("the same external id passes: %d %v", code, out)
	}
	if len(e.revoker.disabled) != 0 {
		t.Fatalf("a maximum edit ended the sessions: %v", e.revoker.disabled)
	}
	// The account id must be the role's.
	if code, out := put(map[string]any{"cloud_account_id": "210987654321"}); code != 400 || !strings.Contains(out["message"].(string), "is not the role's account") {
		t.Fatalf("account not the role's: %d %v", code, out)
	}
	// The role, and the account with it: each ends the live sessions.
	for name, patch := range map[string]map[string]any{
		"the role":    {"cloud_role_arn": readRole},
		"the account": {"cloud_role_arn": otherRole, "cloud_account_id": "210987654321"},
	} {
		e.revoker.disabled = nil
		if code, out := put(patch); code != 200 {
			t.Fatalf("%s: %d %v", name, code, out)
		}
		if len(e.revoker.disabled) != 1 || e.revoker.disabled[0] != id {
			t.Errorf("%s changed: sessions ended for %v", name, e.revoker.disabled)
		}
		d := details(t, e, audit.TargetUpdate)
		if d["cloud_changed"] != true {
			t.Errorf("%s changed: update details %v", name, d)
		}
		put(nil)
	}
}
