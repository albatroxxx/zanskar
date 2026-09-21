// SPDX-License-Identifier: Apache-2.0

// Package idp stores external identity providers (OIDC, LDAP/AD) and the
// identities they assert. Provider configuration is sealed as one JSON
// document per row because it contains client secrets and bind passwords.
// The OIDC and LDAP flows live in sub-packages; this package is the shared
// model, repository and just-in-time provisioning.
package idp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

// Type of provider.
type Type string

// Provider types.
const (
	TypeOIDC Type = "oidc"
	TypeLDAP Type = "ldap"
)

// GroupMapping maps an external group name (OIDC claim value or LDAP group
// name / DN) to a Zanskar group id. Membership is synchronised on every login:
// the user is added to mapped groups they hold and removed from mapped groups
// they no longer hold. Unmapped Zanskar groups are never touched.
type GroupMapping map[string]string

// OIDCConfig configures an OpenID Connect provider (Okta, Entra ID, Keycloak,
// Google Workspace, and so on). Discovery is used; only the issuer is needed.
type OIDCConfig struct {
	Issuer        string   `json:"issuer"`
	ClientID      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret"`
	Scopes        []string `json:"scopes,omitempty"`         // default openid profile email
	GroupsClaim   string   `json:"groups_claim,omitempty"`   // e.g. "groups"; empty disables group sync
	UsernameClaim string   `json:"username_claim,omitempty"` // default preferred_username, then email
	// AllowedDomains restricts sign-in to these email domains when set.
	AllowedDomains []string `json:"allowed_domains,omitempty"`
	// SkipMFA trusts the provider's own MFA and does not require TOTP in Zanskar.
	SkipMFA bool `json:"skip_mfa"`
}

// LDAPConfig configures an LDAP or Active Directory bind-and-search provider.
type LDAPConfig struct {
	URL      string `json:"url"` // ldaps://host:636 or ldap://host:389 with StartTLS
	StartTLS bool   `json:"start_tls"`
	// CACertPEM pins the directory's certificate chain. Required for ldaps and
	// StartTLS unless InsecureSkipVerify is set (development only).
	CACertPEM          string `json:"ca_cert_pem,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
	BindDN             string `json:"bind_dn"`
	BindPassword       string `json:"bind_password"`
	BaseDN             string `json:"base_dn"`
	// UserFilter uses %s for the login name, e.g. "(&(objectClass=user)(sAMAccountName=%s))".
	UserFilter      string `json:"user_filter"`
	UsernameAttr    string `json:"username_attr"`     // sAMAccountName / uid
	DisplayNameAttr string `json:"display_name_attr"` // displayName / cn
	EmailAttr       string `json:"email_attr"`        // mail
	// GroupAttr on the user entry lists group DNs (memberOf). When empty,
	// GroupBaseDN and GroupFilter (with %s = user DN) are searched instead.
	GroupAttr     string `json:"group_attr,omitempty"`
	GroupBaseDN   string `json:"group_base_dn,omitempty"`
	GroupFilter   string `json:"group_filter,omitempty"`
	GroupNameAttr string `json:"group_name_attr,omitempty"` // cn
	// UsernameSuffix, when set, lets users type "alice" and match "alice@corp".
	UsernameSuffix string `json:"username_suffix,omitempty"`
}

// Config is the sealed document. Exactly one of OIDC or LDAP is set.
type Config struct {
	OIDC         *OIDCConfig  `json:"oidc,omitempty"`
	LDAP         *LDAPConfig  `json:"ldap,omitempty"`
	DefaultRoles []user.Role  `json:"default_roles,omitempty"` // roles for JIT-provisioned users; default ["user"]
	GroupMapping GroupMapping `json:"group_mapping,omitempty"`
	// AutoProvision creates a Zanskar user on first successful login. When
	// false, only pre-created users whose external id matches may sign in.
	AutoProvision bool `json:"auto_provision"`
}

// Provider is the public row; Config is only returned by Open.
type Provider struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      Type      `json:"type"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Opened is a provider with its decrypted configuration.
type Opened struct {
	Provider
	Config Config
}

// Errors.
var (
	ErrNotFound     = errors.New("idp: not found")
	ErrDuplicate    = errors.New("idp: name already exists")
	ErrInvalidInput = errors.New("idp: invalid input")
)

// Validate checks a provider and its config.
func Validate(p *Provider, c *Config) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || len(p.Name) > 64 {
		return fmt.Errorf("%w: name must be 1-64 characters", ErrInvalidInput)
	}
	for _, r := range c.DefaultRoles {
		if !user.ValidRole(r) {
			return fmt.Errorf("%w: bad default role %q", ErrInvalidInput, r)
		}
	}
	if len(c.DefaultRoles) == 0 {
		c.DefaultRoles = []user.Role{user.RoleUser}
	}
	switch p.Type {
	case TypeOIDC:
		if c.OIDC == nil || c.LDAP != nil {
			return fmt.Errorf("%w: oidc provider needs an oidc config", ErrInvalidInput)
		}
		o := c.OIDC
		if !strings.HasPrefix(o.Issuer, "https://") {
			return fmt.Errorf("%w: issuer must be an https URL", ErrInvalidInput)
		}
		if o.ClientID == "" || o.ClientSecret == "" {
			return fmt.Errorf("%w: client_id and client_secret required", ErrInvalidInput)
		}
		if len(o.Scopes) == 0 {
			o.Scopes = []string{"openid", "profile", "email"}
		}
		if o.UsernameClaim == "" {
			o.UsernameClaim = "preferred_username"
		}
	case TypeLDAP:
		if c.LDAP == nil || c.OIDC != nil {
			return fmt.Errorf("%w: ldap provider needs an ldap config", ErrInvalidInput)
		}
		l := c.LDAP
		if !strings.HasPrefix(l.URL, "ldaps://") && !strings.HasPrefix(l.URL, "ldap://") {
			return fmt.Errorf("%w: url must start with ldaps:// or ldap://", ErrInvalidInput)
		}
		if strings.HasPrefix(l.URL, "ldap://") && !l.StartTLS {
			return fmt.Errorf("%w: plain ldap:// requires start_tls", ErrInvalidInput)
		}
		if l.CACertPEM == "" && !l.InsecureSkipVerify {
			return fmt.Errorf("%w: ca_cert_pem required (or insecure_skip_verify for development)", ErrInvalidInput)
		}
		if l.BindDN == "" || l.BaseDN == "" || l.UserFilter == "" || !strings.Contains(l.UserFilter, "%s") {
			return fmt.Errorf("%w: bind_dn, base_dn and a user_filter containing %%s are required", ErrInvalidInput)
		}
		if l.UsernameAttr == "" {
			l.UsernameAttr = "sAMAccountName"
		}
		if l.DisplayNameAttr == "" {
			l.DisplayNameAttr = "displayName"
		}
		if l.EmailAttr == "" {
			l.EmailAttr = "mail"
		}
		if l.GroupNameAttr == "" {
			l.GroupNameAttr = "cn"
		}
	default:
		return fmt.Errorf("%w: unknown type %q", ErrInvalidInput, p.Type)
	}
	return nil
}

// Repo persists providers.
type Repo struct {
	db   *store.DB
	ring *keyring.Ring
}

// NewRepo returns a repository sealing configs with ring.
func NewRepo(db *store.DB, ring *keyring.Ring) *Repo { return &Repo{db: db, ring: ring} }

// Create validates, seals and inserts.
func (r *Repo) Create(ctx context.Context, p *Provider, c *Config) error {
	if err := Validate(p, c); err != nil {
		return err
	}
	now := time.Now().UTC()
	p.ID, p.CreatedAt, p.UpdatedAt = store.NewID(), now, now
	sealed, ver, err := r.seal(p.ID, c)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, r.db.Rebind(`INSERT INTO identity_providers (id, name, type, config_enc, key_version, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`), p.ID, p.Name, string(p.Type), sealed, ver, p.Enabled, store.TimeArg(now), store.TimeArg(now))
	if err != nil {
		if isUnique(err) {
			return ErrDuplicate
		}
		return err
	}
	return nil
}

// Update replaces name, enabled flag and config. Secrets left empty in c
// keep their stored values so an admin can edit without re-entering them.
func (r *Repo) Update(ctx context.Context, p *Provider, c *Config) error {
	cur, err := r.Open(ctx, p.ID)
	if err != nil {
		return err
	}
	p.Type = cur.Type
	if c.OIDC != nil && c.OIDC.ClientSecret == "" && cur.Config.OIDC != nil {
		c.OIDC.ClientSecret = cur.Config.OIDC.ClientSecret
	}
	if c.LDAP != nil && c.LDAP.BindPassword == "" && cur.Config.LDAP != nil {
		c.LDAP.BindPassword = cur.Config.LDAP.BindPassword
	}
	if err := Validate(p, c); err != nil {
		return err
	}
	sealed, ver, err := r.seal(p.ID, c)
	if err != nil {
		return err
	}
	p.UpdatedAt = time.Now().UTC()
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE identity_providers SET name = ?, config_enc = ?, key_version = ?, enabled = ?, updated_at = ? WHERE id = ?`),
		p.Name, sealed, ver, p.Enabled, store.TimeArg(p.UpdatedAt), p.ID)
	if err != nil {
		if isUnique(err) {
			return ErrDuplicate
		}
		return err
	}
	return affected(res)
}

// Get returns the public row.
func (r *Repo) Get(ctx context.Context, id string) (*Provider, error) {
	row := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT id, name, type, enabled, created_at, updated_at FROM identity_providers WHERE id = ?`), id)
	return scan(row)
}

// Open returns the row with its decrypted config.
func (r *Repo) Open(ctx context.Context, id string) (*Opened, error) {
	var (
		p                Provider
		typ              string
		sealed           []byte
		ver              sql.NullInt64
		created, updated store.NullTime
	)
	err := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT id, name, type, config_enc, key_version, enabled, created_at, updated_at FROM identity_providers WHERE id = ?`), id).
		Scan(&p.ID, &p.Name, &typ, &sealed, &ver, &p.Enabled, &created, &updated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	p.Type, p.CreatedAt, p.UpdatedAt = Type(typ), created.Time, updated.Time
	plain, err := r.ring.Decrypt(keyring.AAD("identity_providers", p.ID), sealed, int(ver.Int64))
	if err != nil {
		return nil, fmt.Errorf("idp %s: unseal: %w", p.ID, err)
	}
	var c Config
	if err := json.Unmarshal(plain, &c); err != nil {
		return nil, fmt.Errorf("idp %s: config: %w", p.ID, err)
	}
	return &Opened{Provider: p, Config: c}, nil
}

// List returns providers ordered by name. Enabled-only when onlyEnabled.
func (r *Repo) List(ctx context.Context, onlyEnabled bool) ([]*Provider, error) {
	q := `SELECT id, name, type, enabled, created_at, updated_at FROM identity_providers`
	if onlyEnabled {
		q += ` WHERE enabled = TRUE`
	}
	rows, err := r.db.QueryContext(ctx, q+` ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []*Provider{}
	for rows.Next() {
		p, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Delete removes a provider. Users and groups linked to it keep their rows
// with idp_id set to NULL (schema ON DELETE SET NULL) and can no longer sign
// in through it.
func (r *Repo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM identity_providers WHERE id = ?`), id)
	if err != nil {
		return err
	}
	return affected(res)
}

// Identity is what a provider asserts after a successful authentication.
type Identity struct {
	ExternalID  string // stable subject: OIDC sub, LDAP objectGUID/entryUUID or DN
	Username    string // login name to use in Zanskar
	DisplayName string
	Email       string
	Groups      []string // external group names, matched against GroupMapping
}

// Provisioner turns an asserted Identity into a Zanskar user and syncs its
// mapped group memberships.
type Provisioner struct {
	Users  *user.Repo
	Groups GroupSyncer
}

// GroupSyncer is satisfied by *group.Repo; declared here to avoid a cycle.
type GroupSyncer interface {
	AddMember(ctx context.Context, groupID, userID string) error
	RemoveMember(ctx context.Context, groupID, userID string) error
}

// ErrNotProvisioned is returned when auto-provisioning is off and no user
// matches the external identity.
var ErrNotProvisioned = errors.New("idp: no matching user and auto-provisioning is disabled")

// Resolve finds or creates the user for id under provider p and syncs groups.
func (pv *Provisioner) Resolve(ctx context.Context, p *Opened, id Identity) (*user.User, error) {
	if !user.ValidUsername(id.Username) {
		return nil, fmt.Errorf("%w: provider asserted an unusable username %q", ErrInvalidInput, id.Username)
	}
	u, err := pv.Users.GetByExternalID(ctx, p.ID, id.ExternalID)
	switch {
	case err == nil:
		if u.DisplayName != id.DisplayName || (id.Email != "" && u.Email != id.Email) {
			name := id.DisplayName
			if name == "" {
				name = u.DisplayName
			}
			_ = pv.Users.Update(ctx, u.ID, name, firstNonEmpty(id.Email, u.Email), u.Status)
		}
	case errors.Is(err, user.ErrNotFound):
		if !p.Config.AutoProvision {
			return nil, ErrNotProvisioned
		}
		name := id.DisplayName
		if name == "" {
			name = id.Username
		}
		u = &user.User{Username: id.Username, DisplayName: name, Email: id.Email, Roles: p.Config.DefaultRoles, IdPID: p.ID, ExternalID: id.ExternalID}
		if err := pv.Users.Create(ctx, u); err != nil {
			if errors.Is(err, user.ErrDuplicate) {
				return nil, fmt.Errorf("%w: username %q already exists locally", ErrInvalidInput, id.Username)
			}
			return nil, err
		}
	default:
		return nil, err
	}
	if u.IsLocked(time.Now()) {
		return nil, errors.New("idp: account is disabled or locked")
	}
	if pv.Groups != nil && len(p.Config.GroupMapping) > 0 {
		have := map[string]bool{}
		for _, g := range id.Groups {
			have[strings.ToLower(g)] = true
		}
		for ext, gid := range p.Config.GroupMapping {
			if have[strings.ToLower(ext)] {
				_ = pv.Groups.AddMember(ctx, gid, u.ID)
			} else {
				_ = pv.Groups.RemoveMember(ctx, gid, u.ID)
			}
		}
	}
	return pv.Users.GetByID(ctx, u.ID)
}

// ---- helpers

func (r *Repo) seal(id string, c *Config) ([]byte, int, error) {
	plain, err := json.Marshal(c)
	if err != nil {
		return nil, 0, err
	}
	return r.ring.Encrypt(keyring.AAD("identity_providers", id), plain)
}

type scanner interface{ Scan(dest ...any) error }

func scan(s scanner) (*Provider, error) {
	var (
		p                Provider
		typ              string
		created, updated store.NullTime
	)
	if err := s.Scan(&p.ID, &p.Name, &typ, &p.Enabled, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	p.Type, p.CreatedAt, p.UpdatedAt = Type(typ), created.Time, updated.Time
	return &p, nil
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

func isUnique(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate key")
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
