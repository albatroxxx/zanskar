// SPDX-License-Identifier: Apache-2.0

package target

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/cloud"
	"github.com/albatroxxx/zanskar/internal/httpx"
	"github.com/albatroxxx/zanskar/internal/textsafe"
)

// A cloud account's role is a target (ADR 0050, 1): one role in one AWS
// account, which the gateway assumes for the person, as an autoscaling
// group's role is assumed for the sync. The trust is the role's trust
// policy, which names this gateway and an ExternalId Zanskar minted; the
// target binds no credential and holds no secret. Its address is the STS
// endpoint the gateway reaches for it, so the address rules read as for any
// target.

// Cloud platforms (ADR 0050, 6): AWS now; the column leaves room for GCP
// and Azure, as kube_platform did for EKS.
const CloudPlatformAWS = "aws"

// CloudPlatforms lists them in the order the console offers them.
var CloudPlatforms = []string{CloudPlatformAWS}

// A cloud session's length (ADR 0050, decision 4): the target's maximum,
// 60 minutes unless set, between AWS's shortest session and its longest.
const (
	CloudMaxMinutesDefault = 60
	CloudMaxMinutesMin     = 15
	CloudMaxMinutesCeiling = 720
)

// CloudAccountAliasMax bounds how people name the account.
const CloudAccountAliasMax = 64

var cloudAccountRe = regexp.MustCompile(`^[0-9]{12}$`)

// ErrNoCredentialSlot: a cloud account's role binds no credential; its trust
// policy is the trust. The API answers 400 no_credential_slot.
var ErrNoCredentialSlot = fmt.Errorf("%w: a cloud account's role binds no credential; its trust policy is the trust", ErrInvalid)

// IsCloud reports whether the target is a cloud account's role (ADR 0050).
func (t *Target) IsCloud() bool { return t.CloudRoleARN != "" }

// validateCloud checks and normalises the cloud fields: all of them for a
// role, none of them on anything else.
func (t *Target) validateCloud() error {
	t.CloudRoleARN = strings.TrimSpace(t.CloudRoleARN)
	if t.CloudRoleARN == "" {
		for _, set := range []struct {
			field string
			on    bool
		}{
			{"cloud_platform", t.CloudPlatform != ""}, {"cloud_account_id", t.CloudAccountID != ""}, {"cloud_account_alias", t.CloudAccountAlias != ""},
			{"cloud_external_id", t.CloudExternalID != ""}, {"cloud_max_minutes", t.CloudMaxMinutes != 0}, {"cloud_region", t.CloudRegion != ""},
		} {
			if set.on {
				return fmt.Errorf("%w: %s belongs to a cloud account's role, which needs cloud_role_arn", ErrInvalid, set.field)
			}
		}
		return nil
	}
	if t.Engine != "" || t.AppUpstream != "" || t.KubeAPIServer != "" {
		return fmt.Errorf("%w: a target is a host, a database, an application, a Kubernetes cluster or a cloud account's role, not two of these", ErrInvalid)
	}
	if !cloud.RoleARNRe.MatchString(t.CloudRoleARN) {
		return fmt.Errorf("%w: cloud_role_arn must be an IAM role ARN (arn:aws:iam::<account>:role/<name>)", ErrInvalid)
	}
	// The aws partition alone for now (ADR 0050, 1): GovCloud and China have
	// sign-in and console endpoints of their own, which are not built, and a
	// role there would be sent to the commercial ones (review 2026-11-17, C3).
	// The partition is read from the ARN and from the region alike.
	if p := cloud.PartitionOfARN(t.CloudRoleARN); p != "aws" {
		return fmt.Errorf("%w: the role's partition %s is not supported yet; aws alone", ErrInvalid, p)
	}
	t.CloudPlatform = strings.ToLower(strings.TrimSpace(t.CloudPlatform))
	if t.CloudPlatform == "" {
		t.CloudPlatform = CloudPlatformAWS
	}
	if !slices.Contains(CloudPlatforms, t.CloudPlatform) {
		return fmt.Errorf("%w: cloud_platform must be one of %s", ErrInvalid, strings.Join(CloudPlatforms, ", "))
	}
	account := cloud.AccountOf(t.CloudRoleARN)
	t.CloudAccountID = strings.TrimSpace(t.CloudAccountID)
	if t.CloudAccountID == "" {
		t.CloudAccountID = account
	}
	if !cloudAccountRe.MatchString(t.CloudAccountID) {
		return fmt.Errorf("%w: cloud_account_id must be the 12-digit account id", ErrInvalid)
	}
	if t.CloudAccountID != account {
		return fmt.Errorf("%w: cloud_account_id %s is not the role's account %s", ErrInvalid, t.CloudAccountID, account)
	}
	t.CloudAccountAlias = strings.TrimSpace(t.CloudAccountAlias)
	if len(t.CloudAccountAlias) > CloudAccountAliasMax {
		return fmt.Errorf("%w: cloud_account_alias must be at most %d characters", ErrInvalid, CloudAccountAliasMax)
	}
	if t.CloudAccountAlias != "" {
		if err := textsafe.Name(t.CloudAccountAlias); err != nil {
			return fmt.Errorf("%w: cloud_account_alias %w", ErrInvalid, err)
		}
	}
	t.CloudExternalID = strings.TrimSpace(t.CloudExternalID)
	if t.CloudExternalID == "" {
		t.CloudExternalID = cloud.NewExternalID()
	} else if !cloud.ExternalIDRe.MatchString(t.CloudExternalID) {
		return fmt.Errorf("%w: cloud_external_id must be one Zanskar generated (zanskar-<32 hex>)", ErrInvalid)
	}
	if t.CloudMaxMinutes == 0 {
		t.CloudMaxMinutes = CloudMaxMinutesDefault
	}
	if t.CloudMaxMinutes < CloudMaxMinutesMin || t.CloudMaxMinutes > CloudMaxMinutesCeiling {
		return fmt.Errorf("%w: cloud_max_minutes must be %d-%d", ErrInvalid, CloudMaxMinutesMin, CloudMaxMinutesCeiling)
	}
	t.CloudRegion = strings.ToLower(strings.TrimSpace(t.CloudRegion))
	if t.CloudRegion != "" && !cloud.ValidRegion(t.CloudRegion) {
		return fmt.Errorf("%w: cloud_region must be an AWS region (eu-west-1)", ErrInvalid)
	}
	if p := cloud.Partition(t.CloudRegion); p != "aws" {
		return fmt.Errorf("%w: the region's partition %s is not supported yet; aws alone", ErrInvalid, p)
	}
	for p := range t.Ports {
		return fmt.Errorf("%w: a cloud account's role has no %s port; nothing is dialled", ErrInvalid, p)
	}
	// No credential on any slot (ADR 0050, 1; review 2026-11-17, L6): the
	// role dials nothing a credential could open.
	if len(t.Credentials) > 0 {
		return ErrNoCredentialSlot
	}
	// What the gateway reaches for the role: STS, in the region or globally.
	t.Address = cloud.STSHost(t.CloudRegion)
	if t.OSFamily == "" {
		t.OSFamily = OtherOS
	}
	t.Ports, t.Capabilities = map[Protocol]int{}, []Protocol{Cloud}
	t.DatabaseName, t.TLSMode, t.TLSCA = "", "", ""
	return nil
}

// CloudAccountLabel is how the account reads: its alias, else its id.
func (t *Target) CloudAccountLabel() string {
	if t.CloudAccountAlias != "" {
		return t.CloudAccountAlias
	}
	return t.CloudAccountID
}

// CloudRoleName is the role's name, from its ARN.
func (t *Target) CloudRoleName() string { return cloud.RoleNameOf(t.CloudRoleARN) }

// cloudTerms is what a role's live sessions hold for their life, as one
// comparable text: the account, the role and the ExternalId. A change ends
// them (handlers.update), as a cluster's endpoint change does; "" for
// anything that is not a cloud role.
func cloudTerms(t *Target) string {
	if !t.IsCloud() {
		return ""
	}
	return t.CloudAccountID + "\n" + t.CloudRoleARN + "\n" + t.CloudExternalID
}

// CloudSetup is what the role's account needs from its administrator (ADR
// 0050, 1): the trust policy naming this gateway's principal and the
// ExternalId, allowing sts:AssumeRole, sts:SetSourceIdentity and
// sts:TagSession; the permissions policy that lets the gateway read the
// session's activity from CloudTrail (phase C, one statement,
// cloudtrail:LookupEvents); the CLI and the CloudFormation that put both on
// the role. Pending with an empty trust policy while the gateway does not
// know its own principal yet (the autoscaling page's rule, ADR 0023); the
// permissions policy names no principal and is always given.
type CloudSetup struct {
	Principal         *string `json:"principal"`
	Pending           bool    `json:"pending"`
	ExternalID        string  `json:"external_id"`
	TrustPolicy       string  `json:"trust_policy"`
	PermissionsPolicy string  `json:"permissions_policy"`
	CLI               string  `json:"cli"`
	CloudFormation    string  `json:"cloudformation"`
}

// cloudSetup answers GET /targets/{id}/cloud/setup.
func (h *AdminHandler) cloudSetup(w http.ResponseWriter, r *http.Request) {
	t, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if !t.IsCloud() {
		httpx.WriteError(w, r, http.StatusConflict, "not_a_cloud_role", "target is not a cloud account's role")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.cloudSetupFor(r.Context(), t))
}

func (h *AdminHandler) cloudSetupFor(ctx context.Context, t *Target) CloudSetup {
	principal := ""
	if h.Identity != nil {
		principal = h.Identity.Get(ctx).Principal
	}
	trust := cloud.CloudTrustPolicy(principal, t.CloudExternalID)
	activity := cloud.ActivityPermissionsPolicy()
	out := CloudSetup{Pending: trust == "", ExternalID: t.CloudExternalID, TrustPolicy: trust, PermissionsPolicy: activity}
	if trust != "" {
		out.Principal = &principal
		name := t.CloudRoleName()
		out.CLI = cloud.CloudRoleCLI(name, trust, activity)
		out.CloudFormation = cloud.CloudRoleCloudFormation(name, trust, activity)
	}
	return out
}

// CloudTest is what a role's test found (ADR 0050, 1): whether the gateway
// assumed it for the target's maximum, with the source identity and the
// tags a session carries, and as which ARN; else the stage that refused and
// why. LookupEvents is whether the role may read the account's CloudTrail
// for a session's activity (phase C): false is an answer, not a failure,
// since the activity is then simply not read; null when the test did not
// get that far.
type CloudTest struct {
	OK           bool   `json:"ok"`
	AssumedARN   string `json:"assumed_arn,omitempty"`
	Stage        string `json:"stage"`
	Message      string `json:"message"`
	LookupEvents *bool  `json:"lookup_events"`
}

// Stages a cloud test names: the mint (assume), a duration above the role's
// maximum (duration), the credentials' first call (identity), and the
// CloudTrail call that failed otherwise than by a refusal (lookup).
const (
	CloudStageAssume   = "assume"
	CloudStageDuration = "duration"
	CloudStageIdentity = "identity"
	CloudStageLookup   = "lookup"
)

// CloudTestTimeout bounds a role test: two calls to STS and one to CloudTrail.
const CloudTestTimeout = 30 * time.Second

// NewRoleMinter builds the minter a test and a session assume the role
// with; tests swap it for one that never reaches AWS. NewTrailReader builds
// what the test reads CloudTrail with, likewise.
var (
	NewRoleMinter                     = func(ctx context.Context, region string) (cloud.RoleMinter, error) { return cloud.NewSTS(ctx, region) }
	NewTrailReader cloud.TrailFactory = cloud.NewTrailReader
)

// cloudTest answers POST /targets/{id}/cloud/test: the role's probe. Nothing
// is recorded on the target; the outcome is an event.
func (h *AdminHandler) cloudTest(w http.ResponseWriter, r *http.Request) {
	t, err := h.Repo.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if !t.IsCloud() {
		httpx.WriteError(w, r, http.StatusConflict, "not_a_cloud_role", "target is not a cloud account's role")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), CloudTestTimeout)
	defer cancel()
	minter, err := NewRoleMinter(ctx, t.CloudRegion)
	if err != nil {
		httpx.Internal(w, r, h.Log, err)
		return
	}
	res := RunCloudTest(ctx, minter, NewTrailReader, t)
	outcome := audit.Success
	if !res.OK {
		outcome = audit.Failure
	}
	h.record(r, audit.TargetCloudTest, t.ID, outcome, map[string]any{"account": t.CloudAccountID, "role": t.CloudRoleARN,
		"max_minutes": t.CloudMaxMinutes, "stage": res.Stage, "assumed_arn": res.AssumedARN, "lookup_events": res.LookupEvents})
	httpx.WriteJSON(w, http.StatusOK, res)
}

// RunCloudTest assumes the role once as a session would, for the target's
// maximum, then asks STS who the credentials are, then asks CloudTrail for
// one event of the last minute with the same credentials (phase C), and
// names what refused. CloudTrail refusing is an answer: the role is usable
// and the session's activity is not read.
func RunCloudTest(ctx context.Context, minter cloud.RoleMinter, trails cloud.TrailFactory, t *Target) CloudTest {
	var nonce [4]byte
	_, _ = rand.Read(nonce[:])
	creds, err := minter.Mint(ctx, cloud.MintRequest{RoleARN: t.CloudRoleARN, ExternalID: t.CloudExternalID,
		SessionName: "zanskar-test-" + hex.EncodeToString(nonce[:]), SourceIdentity: "zanskar-test",
		Duration: time.Duration(t.CloudMaxMinutes) * time.Minute, Tags: map[string]string{"zanskar:test": "1"}})
	switch {
	case errors.Is(err, cloud.ErrMintChained):
		// The role allows it; the gateway's own identity does not (IRSA, a
		// container role): STS caps a chained session at an hour.
		return CloudTest{Stage: CloudStageDuration, Message: fmt.Sprintf("this gateway's own AWS identity is an assumed role, so AWS caps its sessions at an hour whatever the role allows; set cloud_max_minutes to 60 or less, or run the gateway under an instance profile (%d minutes asked)", t.CloudMaxMinutes)}
	case errors.Is(err, cloud.ErrMintDuration):
		return CloudTest{Stage: CloudStageDuration, Message: fmt.Sprintf("the role's maximum session is below %d minutes; lower cloud_max_minutes to what the role allows (%s)",
			t.CloudMaxMinutes, strings.TrimPrefix(err.Error(), cloud.ErrMintDuration.Error()+": "))}
	case errors.Is(err, cloud.ErrMintRefused):
		return CloudTest{Stage: CloudStageAssume, Message: "the role could not be assumed: its trust policy must name this gateway's principal, carry the ExternalId " +
			t.CloudExternalID + " and allow sts:AssumeRole, sts:SetSourceIdentity and sts:TagSession (" + strings.TrimPrefix(err.Error(), cloud.ErrMintRefused.Error()+": ") + ")"}
	case err != nil:
		return CloudTest{Stage: CloudStageAssume, Message: err.Error()}
	}
	// The credentials' first call: a role assumed whose credentials cannot
	// even say who they are has a permissions boundary or a deny-all policy.
	arn, err := minter.CallerIdentity(ctx, creds)
	if err != nil {
		return CloudTest{Stage: CloudStageIdentity, AssumedARN: creds.AssumedARN,
			Message: "the role was assumed, but its credentials could not call sts:GetCallerIdentity; check the role's permissions boundary and policies (" + err.Error() + ")"}
	}
	if arn == "" {
		arn = creds.AssumedARN
	}
	assumed := "assumed for " + (time.Duration(t.CloudMaxMinutes) * time.Minute).String()
	// Whether the role may read CloudTrail: one call, the credentials' own.
	trail, err := trails(ctx, t.CloudRegion, creds)
	if err != nil {
		return CloudTest{Stage: CloudStageLookup, AssumedARN: arn, Message: "the role was assumed, but CloudTrail could not be reached (" + err.Error() + ")"}
	}
	switch err := cloud.LookupAllowed(ctx, trail, time.Now()); {
	case err == nil:
		yes := true
		return CloudTest{OK: true, AssumedARN: arn, LookupEvents: &yes, Message: assumed}
	case errors.Is(err, cloud.ErrLookupDenied):
		no := false
		return CloudTest{OK: true, AssumedARN: arn, LookupEvents: &no, Message: assumed + "; the role lacks cloudtrail:LookupEvents, so a session's activity is not read (the Setup's activity policy adds it)"}
	default:
		return CloudTest{Stage: CloudStageLookup, AssumedARN: arn, Message: "the role was assumed, but CloudTrail could not be read (" + err.Error() + ")"}
	}
}
