// SPDX-License-Identifier: Apache-2.0

// Package asg holds autoscaling groups as access targets (ADR 0011): the
// enrolled group, its per-protocol credentials, and the instances the sync
// loop currently sees, with the health the gateway computed for each.
package asg

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/target"
)

// Group is an enrolled autoscaling group.
type Group struct {
	ID                  string                     `json:"id"`
	Name                string                     `json:"name"`
	Provider            string                     `json:"provider"`
	Region              string                     `json:"region"`
	ExternalName        string                     `json:"external_name"`
	RoleARN             string                     `json:"role_arn"`
	ExternalID          string                     `json:"external_id"`
	OSFamily            target.OSFamily            `json:"os_family"`
	Ports               map[target.Protocol]int    `json:"ports"`
	Capabilities        []target.Protocol          `json:"capabilities"`
	AddressPreference   string                     `json:"address_preference"` // private | public
	PollIntervalSeconds int                        `json:"poll_interval_seconds"`
	Tags                map[string]string          `json:"tags"`
	Status              string                     `json:"status"`
	LastSyncedAt        *time.Time                 `json:"last_synced_at"`
	LastError           string                     `json:"last_error,omitempty"`
	Credentials         map[target.Protocol]string `json:"credentials"`
	CreatedBy           string                     `json:"created_by,omitempty"`
	CreatedAt           time.Time                  `json:"created_at"`
	UpdatedAt           time.Time                  `json:"updated_at"`
}

// Instance is one member as last seen by the sync loop.
type Instance struct {
	ID                 string     `json:"id"`
	GroupID            string     `json:"asg_id"`
	InstanceID         string     `json:"instance_id"`
	PrivateIP          string     `json:"private_ip,omitempty"`
	PublicIP           string     `json:"public_ip,omitempty"`
	AvailabilityZone   string     `json:"availability_zone,omitempty"`
	LifecycleState     string     `json:"lifecycle_state"`
	LBHealth           string     `json:"lb_health,omitempty"`
	ProbeHealth        string     `json:"probe_health"` // unknown | healthy | unhealthy
	HostKeyFingerprint string     `json:"host_key_fingerprint,omitempty"`
	HostKeySource      string     `json:"host_key_source,omitempty"` // console | tofu
	LaunchedAt         *time.Time `json:"launched_at,omitempty"`
	FirstSeenAt        time.Time  `json:"first_seen_at"`
	LastSeenAt         time.Time  `json:"last_seen_at"`
	TerminatedAt       *time.Time `json:"terminated_at,omitempty"`
	// Healthy is derived: InService, LB healthy or absent, probe healthy.
	Healthy bool `json:"healthy"`
}

// Errors.
var (
	ErrNotFound     = errors.New("asg: not found")
	ErrDuplicate    = errors.New("asg: name already exists")
	ErrInvalidInput = errors.New("asg: invalid input")
)

// NewExternalID returns a random 32-hex ExternalId for the role trust policy.
func NewExternalID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "zanskar-" + hex.EncodeToString(b)
}

// Validate checks a group before storing it.
func (g *Group) Validate() error {
	g.Name = strings.TrimSpace(g.Name)
	if g.Name == "" || len(g.Name) > 64 {
		return fmt.Errorf("%w: name must be 1-64 characters", ErrInvalidInput)
	}
	if g.Provider == "" {
		g.Provider = "aws"
	}
	if g.Provider != "aws" {
		return fmt.Errorf("%w: unsupported provider %q", ErrInvalidInput, g.Provider)
	}
	if strings.TrimSpace(g.Region) == "" || strings.TrimSpace(g.ExternalName) == "" {
		return fmt.Errorf("%w: region and the cloud-side group name are required", ErrInvalidInput)
	}
	if !strings.HasPrefix(g.RoleARN, "arn:aws:iam::") || !strings.Contains(g.RoleARN, ":role/") {
		return fmt.Errorf("%w: role_arn must be an IAM role ARN", ErrInvalidInput)
	}
	if g.ExternalID == "" {
		g.ExternalID = NewExternalID()
	}
	switch g.OSFamily {
	case target.Linux, target.Windows, target.OtherOS:
	default:
		return fmt.Errorf("%w: os_family must be linux, windows or other", ErrInvalidInput)
	}
	if g.Ports == nil {
		g.Ports = map[target.Protocol]int{}
	}
	for p, n := range g.Ports {
		if !target.ValidProtocol(p) || n < 1 || n > 65535 {
			return fmt.Errorf("%w: bad port for %s", ErrInvalidInput, p)
		}
	}
	if len(g.Capabilities) == 0 {
		g.Capabilities = []target.Protocol{target.SSH}
	}
	for _, p := range g.Capabilities {
		if !target.ValidProtocol(p) {
			return fmt.Errorf("%w: unknown capability %q", ErrInvalidInput, p)
		}
	}
	if g.AddressPreference == "" {
		g.AddressPreference = "private"
	}
	if g.AddressPreference != "private" && g.AddressPreference != "public" {
		return fmt.Errorf("%w: address_preference must be private or public", ErrInvalidInput)
	}
	if g.PollIntervalSeconds == 0 {
		g.PollIntervalSeconds = 30
	}
	if g.PollIntervalSeconds < 10 || g.PollIntervalSeconds > 3600 {
		return fmt.Errorf("%w: poll_interval_seconds must be 10-3600", ErrInvalidInput)
	}
	if g.Tags == nil {
		g.Tags = map[string]string{}
	}
	if len(g.Tags) > 32 {
		return fmt.Errorf("%w: at most 32 tags", ErrInvalidInput)
	}
	if g.Status == "" {
		g.Status = "active"
	}
	if g.Status != "active" && g.Status != "disabled" {
		return fmt.Errorf("%w: status must be active or disabled", ErrInvalidInput)
	}
	if g.Credentials == nil {
		g.Credentials = map[target.Protocol]string{}
	}
	return nil
}

// Port returns the effective port for a protocol.
func (g *Group) Port(p target.Protocol) int {
	if n, ok := g.Ports[p]; ok && n > 0 {
		return n
	}
	return target.DefaultPorts[p]
}

// Address picks the instance address according to the group's preference.
func (g *Group) Address(in *Instance) string {
	if g.AddressPreference == "public" && in.PublicIP != "" {
		return in.PublicIP
	}
	if in.PrivateIP != "" {
		return in.PrivateIP
	}
	return in.PublicIP
}

// TrustPolicy renders the IAM trust policy for the role, with the
// ExternalId condition that ties the role to this Zanskar deployment.
// gatewayPrincipal is the ARN of the identity the gateway runs as.
func (g *Group) TrustPolicy(gatewayPrincipal string) string {
	if gatewayPrincipal == "" {
		gatewayPrincipal = "arn:aws:iam::<GATEWAY-ACCOUNT-ID>:role/<GATEWAY-ROLE>"
	}
	doc := map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{{
			"Effect":    "Allow",
			"Principal": map[string]any{"AWS": gatewayPrincipal},
			"Action":    "sts:AssumeRole",
			"Condition": map[string]any{"StringEquals": map[string]any{"sts:ExternalId": g.ExternalID}},
		}},
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return string(b)
}

// PermissionsPolicy renders the least-privilege permissions the role needs.
// Describe calls are read-only; SendSSHPublicKey is only needed for the
// ec2_instance_connect credential mode and is scoped to the group's tag.
func (g *Group) PermissionsPolicy() string {
	doc := map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{
			{
				"Sid":    "ZanskarDescribe",
				"Effect": "Allow",
				"Action": []string{
					"autoscaling:DescribeAutoScalingGroups",
					"ec2:DescribeInstances",
					"ec2:GetConsoleOutput",
					"elasticloadbalancing:DescribeTargetHealth",
				},
				"Resource": "*",
			},
			{
				"Sid":      "ZanskarInstanceConnect",
				"Effect":   "Allow",
				"Action":   "ec2-instance-connect:SendSSHPublicKey",
				"Resource": "arn:aws:ec2:" + g.Region + ":*:instance/*",
				"Condition": map[string]any{"StringEquals": map[string]any{
					"ec2:ResourceTag/aws:autoscaling:groupName": g.ExternalName,
				}},
			},
		},
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return string(b)
}

// Repo persists groups and instances.
type Repo struct {
	db *store.DB
}

// NewRepo returns a repository over db.
func NewRepo(db *store.DB) *Repo { return &Repo{db: db} }

const groupCols = `id, name, provider, region, external_name, role_arn, external_id, os_family, ports, capabilities,
	address_preference, poll_interval_seconds, tags, status, last_synced_at, last_error, created_by, created_at, updated_at`

// Create validates and inserts g with its credential mapping.
func (r *Repo) Create(ctx context.Context, g *Group) error {
	if err := g.Validate(); err != nil {
		return err
	}
	now := time.Now().UTC()
	g.ID, g.CreatedAt, g.UpdatedAt = store.NewID(), now, now
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	_, err = tx.ExecContext(ctx, r.db.Rebind(`INSERT INTO autoscaling_groups (`+groupCols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?)`),
		g.ID, g.Name, g.Provider, g.Region, g.ExternalName, g.RoleARN, g.ExternalID, string(g.OSFamily), mustJSON(g.Ports), mustJSON(g.Capabilities),
		g.AddressPreference, g.PollIntervalSeconds, mustJSON(g.Tags), g.Status, nullStr(g.CreatedBy), store.TimeArg(now), store.TimeArg(now))
	if err != nil {
		return mapErr(err)
	}
	if err := setCredentialsTx(ctx, tx, r.db, g.ID, g.Credentials); err != nil {
		return err
	}
	return tx.Commit()
}

// Update replaces the editable fields and credential mapping.
func (r *Repo) Update(ctx context.Context, g *Group) error {
	if err := g.Validate(); err != nil {
		return err
	}
	g.UpdatedAt = time.Now().UTC()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	res, err := tx.ExecContext(ctx, r.db.Rebind(`UPDATE autoscaling_groups SET name = ?, region = ?, external_name = ?, role_arn = ?, external_id = ?,
		os_family = ?, ports = ?, capabilities = ?, address_preference = ?, poll_interval_seconds = ?, tags = ?, status = ?, updated_at = ? WHERE id = ?`),
		g.Name, g.Region, g.ExternalName, g.RoleARN, g.ExternalID, string(g.OSFamily), mustJSON(g.Ports), mustJSON(g.Capabilities),
		g.AddressPreference, g.PollIntervalSeconds, mustJSON(g.Tags), g.Status, store.TimeArg(g.UpdatedAt), g.ID)
	if err != nil {
		return mapErr(err)
	}
	if err := affected(res); err != nil {
		return err
	}
	if err := setCredentialsTx(ctx, tx, r.db, g.ID, g.Credentials); err != nil {
		return err
	}
	return tx.Commit()
}

// Get returns one group with its credentials.
func (r *Repo) Get(ctx context.Context, id string) (*Group, error) {
	row := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT `+groupCols+` FROM autoscaling_groups WHERE id = ?`), id)
	g, err := scanGroup(row)
	if err != nil {
		return nil, err
	}
	g.Credentials, err = r.credentials(ctx, g.ID)
	return g, err
}

// List returns groups ordered by name. onlyActive filters disabled groups.
func (r *Repo) List(ctx context.Context, onlyActive bool) ([]*Group, error) {
	q := `SELECT ` + groupCols + ` FROM autoscaling_groups`
	if onlyActive {
		q += ` WHERE status = 'active'`
	}
	rows, err := r.db.QueryContext(ctx, q+` ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var out []*Group
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			_ = rows.Close() //nolint:sqlclosecheck // explicit close on SQLite's single connection; queries follow
			return nil, err
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close() // SQLite single connection: close before the credential queries below
	for _, g := range out {
		if g.Credentials, err = r.credentials(ctx, g.ID); err != nil {
			return nil, err
		}
	}
	if out == nil {
		out = []*Group{}
	}
	return out, nil
}

// Delete removes a group; its instances cascade.
func (r *Repo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM autoscaling_groups WHERE id = ?`), id)
	if err != nil {
		return err
	}
	return affected(res)
}

// RecordSync stores the outcome of a poll.
func (r *Repo) RecordSync(ctx context.Context, id string, syncErr error) error {
	now := store.TimeArg(time.Now())
	msg := ""
	if syncErr != nil {
		msg = syncErr.Error()
		if len(msg) > 500 {
			msg = msg[:500]
		}
	}
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE autoscaling_groups SET last_synced_at = ?, last_error = ? WHERE id = ?`), now, nullStr(msg), id)
	return err
}

// UpsertInstance records the latest observation of an instance and returns
// the stored row (with Healthy derived). isNew reports a first sighting.
func (r *Repo) UpsertInstance(ctx context.Context, in *Instance) (stored *Instance, isNew bool, err error) {
	now := time.Now().UTC()
	existing, err := r.instanceByCloudID(ctx, in.GroupID, in.InstanceID)
	switch {
	case errors.Is(err, ErrNotFound):
		in.ID, in.FirstSeenAt, in.LastSeenAt, in.TerminatedAt = store.NewID(), now, now, nil
		_, err = r.db.ExecContext(ctx, r.db.Rebind(`INSERT INTO asg_instances
			(id, asg_id, instance_id, private_ip, public_ip, availability_zone, lifecycle_state, lb_health, probe_health, host_key_fingerprint, host_key_source, launched_at, first_seen_at, last_seen_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
			in.ID, in.GroupID, in.InstanceID, nullStr(in.PrivateIP), nullStr(in.PublicIP), nullStr(in.AvailabilityZone), in.LifecycleState, nullStr(in.LBHealth),
			orUnknown(in.ProbeHealth), nullStr(in.HostKeyFingerprint), nullStr(in.HostKeySource), timeOrNil(in.LaunchedAt), store.TimeArg(now), store.TimeArg(now))
		if err != nil {
			return nil, false, err
		}
		in.Healthy = derive(in)
		return in, true, nil
	case err != nil:
		return nil, false, err
	}
	// Keep a pinned host key unless the caller supplies a new one.
	if in.HostKeyFingerprint == "" {
		in.HostKeyFingerprint, in.HostKeySource = existing.HostKeyFingerprint, existing.HostKeySource
	}
	in.ID, in.FirstSeenAt, in.LastSeenAt, in.TerminatedAt = existing.ID, existing.FirstSeenAt, now, nil
	_, err = r.db.ExecContext(ctx, r.db.Rebind(`UPDATE asg_instances SET private_ip = ?, public_ip = ?, availability_zone = ?, lifecycle_state = ?, lb_health = ?,
		probe_health = ?, host_key_fingerprint = ?, host_key_source = ?, launched_at = ?, last_seen_at = ?, terminated_at = NULL WHERE id = ?`),
		nullStr(in.PrivateIP), nullStr(in.PublicIP), nullStr(in.AvailabilityZone), in.LifecycleState, nullStr(in.LBHealth),
		orUnknown(in.ProbeHealth), nullStr(in.HostKeyFingerprint), nullStr(in.HostKeySource), timeOrNil(in.LaunchedAt), store.TimeArg(now), in.ID)
	if err != nil {
		return nil, false, err
	}
	in.Healthy = derive(in)
	return in, false, nil
}

// MarkTerminated flags instances of the group not in keepIDs as terminated
// and returns the affected rows (for session cleanup and audit).
func (r *Repo) MarkTerminated(ctx context.Context, groupID string, keepIDs []string) ([]*Instance, error) {
	all, err := r.Instances(ctx, groupID, false)
	if err != nil {
		return nil, err
	}
	keep := map[string]bool{}
	for _, id := range keepIDs {
		keep[id] = true
	}
	var gone []*Instance
	now := time.Now().UTC()
	for _, in := range all {
		if keep[in.InstanceID] || in.TerminatedAt != nil {
			continue
		}
		if _, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE asg_instances SET terminated_at = ?, lifecycle_state = 'Terminated', probe_health = 'unhealthy' WHERE id = ?`), store.TimeArg(now), in.ID); err != nil {
			return nil, err
		}
		in.TerminatedAt = &now
		in.LifecycleState = "Terminated"
		in.Healthy = false
		gone = append(gone, in)
	}
	return gone, nil
}

// Instances lists a group's instances (newest launch first). onlyHealthy
// applies the derived rule and excludes terminated rows.
func (r *Repo) Instances(ctx context.Context, groupID string, onlyHealthy bool) ([]*Instance, error) {
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`SELECT `+instanceCols+` FROM asg_instances WHERE asg_id = ? ORDER BY launched_at DESC, instance_id`), groupID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []*Instance{}
	for rows.Next() {
		in, err := scanInstance(rows)
		if err != nil {
			return nil, err
		}
		if onlyHealthy && (!in.Healthy || in.TerminatedAt != nil) {
			continue
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// GetInstance returns one instance row by Zanskar id.
func (r *Repo) GetInstance(ctx context.Context, id string) (*Instance, error) {
	row := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT `+instanceCols+` FROM asg_instances WHERE id = ?`), id)
	return scanInstance(row)
}

// SetCredential maps a credential to a protocol for the group.
func (r *Repo) SetCredential(ctx context.Context, groupID string, p target.Protocol, credentialID string) error {
	if !target.ValidProtocol(p) {
		return fmt.Errorf("%w: unknown protocol", ErrInvalidInput)
	}
	if _, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM asg_credentials WHERE asg_id = ? AND protocol = ?`), groupID, string(p)); err != nil {
		return err
	}
	if credentialID == "" {
		return nil
	}
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`INSERT INTO asg_credentials (asg_id, protocol, credential_id) VALUES (?, ?, ?)`), groupID, string(p), credentialID)
	return mapErr(err)
}

// ---- helpers

const instanceCols = `id, asg_id, instance_id, private_ip, public_ip, availability_zone, lifecycle_state, lb_health, probe_health,
	host_key_fingerprint, host_key_source, launched_at, first_seen_at, last_seen_at, terminated_at`

func derive(in *Instance) bool {
	if in.TerminatedAt != nil || in.LifecycleState != "InService" || in.ProbeHealth != "healthy" {
		return false
	}
	switch strings.ToLower(in.LBHealth) {
	case "", "healthy":
		return true
	}
	return false
}

func (r *Repo) instanceByCloudID(ctx context.Context, groupID, instanceID string) (*Instance, error) {
	row := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT `+instanceCols+` FROM asg_instances WHERE asg_id = ? AND instance_id = ?`), groupID, instanceID)
	return scanInstance(row)
}

func (r *Repo) credentials(ctx context.Context, groupID string) (map[target.Protocol]string, error) {
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(`SELECT protocol, credential_id FROM asg_credentials WHERE asg_id = ?`), groupID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[target.Protocol]string{}
	for rows.Next() {
		var p, c string
		if err := rows.Scan(&p, &c); err != nil {
			return nil, err
		}
		out[target.Protocol(p)] = c
	}
	return out, rows.Err()
}

func setCredentialsTx(ctx context.Context, tx *sql.Tx, db *store.DB, groupID string, creds map[target.Protocol]string) error {
	if _, err := tx.ExecContext(ctx, db.Rebind(`DELETE FROM asg_credentials WHERE asg_id = ?`), groupID); err != nil {
		return err
	}
	for p, c := range creds {
		if c == "" {
			continue
		}
		if !target.ValidProtocol(p) {
			return fmt.Errorf("%w: unknown protocol %q", ErrInvalidInput, p)
		}
		if _, err := tx.ExecContext(ctx, db.Rebind(`INSERT INTO asg_credentials (asg_id, protocol, credential_id) VALUES (?, ?, ?)`), groupID, string(p), c); err != nil {
			return mapErr(err)
		}
	}
	return nil
}

type scanner interface{ Scan(dest ...any) error }

func scanGroup(s scanner) (*Group, error) {
	var (
		g                        Group
		osFamily                 string
		ports, caps, tags        []byte
		lastErr, createdBy       sql.NullString
		synced, created, updated store.NullTime
	)
	err := s.Scan(&g.ID, &g.Name, &g.Provider, &g.Region, &g.ExternalName, &g.RoleARN, &g.ExternalID, &osFamily, &ports, &caps,
		&g.AddressPreference, &g.PollIntervalSeconds, &tags, &g.Status, &synced, &lastErr, &createdBy, &created, &updated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	g.OSFamily = target.OSFamily(osFamily)
	_ = json.Unmarshal(ports, &g.Ports)
	_ = json.Unmarshal(caps, &g.Capabilities)
	_ = json.Unmarshal(tags, &g.Tags)
	if g.Ports == nil {
		g.Ports = map[target.Protocol]int{}
	}
	if g.Tags == nil {
		g.Tags = map[string]string{}
	}
	g.LastError, g.CreatedBy = lastErr.String, createdBy.String
	g.LastSyncedAt, g.CreatedAt, g.UpdatedAt = synced.Ptr(), created.Time, updated.Time
	return &g, nil
}

func scanInstance(s scanner) (*Instance, error) {
	var (
		in                                Instance
		priv, pub, az, lb, hk, hks        sql.NullString
		launched, first, last, terminated store.NullTime
	)
	err := s.Scan(&in.ID, &in.GroupID, &in.InstanceID, &priv, &pub, &az, &in.LifecycleState, &lb, &in.ProbeHealth, &hk, &hks, &launched, &first, &last, &terminated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	in.PrivateIP, in.PublicIP, in.AvailabilityZone, in.LBHealth = priv.String, pub.String, az.String, lb.String
	in.HostKeyFingerprint, in.HostKeySource = hk.String, hks.String
	in.LaunchedAt, in.FirstSeenAt, in.LastSeenAt, in.TerminatedAt = launched.Ptr(), first.Time, last.Time, terminated.Ptr()
	in.Healthy = derive(&in)
	return &in, nil
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func timeOrNil(t *time.Time) any {
	if t == nil {
		return nil
	}
	return store.TimeArg(*t)
}

func affected(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate key") {
		return ErrDuplicate
	}
	if strings.Contains(msg, "foreign key") {
		return fmt.Errorf("%w: credential does not exist", ErrInvalidInput)
	}
	return err
}
