// SPDX-License-Identifier: Apache-2.0

// Package idp stores external identity providers (OIDC, LDAP/AD) and the
// identities they assert. Provider configuration is sealed as one JSON
// document per row because it contains client secrets and bind passwords.
// The OIDC and LDAP flows live in sub-packages; this package is the shared
// model, repository and just-in-time provisioning.
package idp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/gateway"
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

// GroupMapping maps an external group to a Zanskar group id. Membership is
// synchronised on every login: the user is added to mapped groups they hold
// and removed from mapped groups they no longer hold. Unmapped Zanskar groups
// are never touched.
//
// A key is an OIDC claim value, or for LDAP either a group's full DN
// ("cn=zanskar-admins,ou=groups,dc=corp,dc=example", compared as LDAP compares
// DNs) or its bare name. A bare name matches every directory group with that
// name, in any OU, so whoever can create a group anywhere in the directory can
// create a matching one; use the DN for any group that grants real access.
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
	// AllowedDomains restricts sign-in to these email domains when set. The
	// address must be one the provider has verified (email_verified).
	AllowedDomains []string `json:"allowed_domains,omitempty"`
	// TrustEmail accepts the email claim as verified when the provider never
	// says, as Entra ID does not. Set it only for a provider whose addresses
	// its own directory assigns. An address the provider marks unverified is
	// never used, whatever this says.
	TrustEmail bool `json:"trust_email,omitempty"`
	// ZanskarMFA asks for a Zanskar authenticator after the provider's
	// sign-in, for a provider that does no MFA of its own. Off, the default,
	// the second factor is the provider's job and Zanskar asks for none
	// (ADR 0035). It replaced skip_mfa, whose default was the opposite: a
	// configuration sealed before reads as off.
	ZanskarMFA bool `json:"zanskar_mfa,omitempty"`
	// KeepProviderSession leaves the provider's session alone when someone
	// signs out of Zanskar. Off, the default, signing out ends it too
	// (RP-initiated logout, ADR 0035), so the next sign-in asks for the
	// password again; set it for a realm other applications share.
	KeepProviderSession bool `json:"keep_provider_session,omitempty"`
	// PromptLogin asks the provider to authenticate the person afresh at
	// every sign-in (OpenID Connect prompt=login), whatever session it
	// holds: for a provider whose sign-out does not end its own session
	// (Authentik's default provider flow), or a shared workstation. Google
	// does not take prompt=login.
	PromptLogin bool `json:"prompt_login,omitempty"`
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
	// AutoProvision creates a Zanskar user, with DefaultRoles, the first time
	// someone signs in through this provider and no account is theirs yet.
	// Either way, an account an administrator created with no password under
	// the username the provider asserts is adopted at that first sign-in
	// (see Provisioner.Resolve). When false, only accounts already linked to
	// the person and such pre-created accounts may sign in.
	AutoProvision bool `json:"auto_provision"`
	// SyncUsers lists everyone in the directory every SyncMinutes (ADR
	// 0035). With AutoProvision a person who joins has an account before
	// their first sign-in; one who leaves, or is disabled there, has the
	// account disabled and every session ended. Group memberships are not
	// synced; mapped groups still follow each sign-in. Only a Keycloak
	// realm (OIDC) or an LDAP directory can be listed.
	SyncUsers bool `json:"sync_users,omitempty"`
	// SyncMinutes is the time between runs: default 15, from 5 to 1440.
	SyncMinutes int `json:"sync_minutes,omitempty"`
	// SCIM lets the provider push its people to /api/v1/scim/<id> (SCIM
	// 2.0, the standard Okta, Entra ID, OneLogin, JumpCloud, PingOne and
	// Authentik speak), with a bearer token generated for it (ADR 0035).
	// A provider has its people pushed or listed (SyncUsers), not both.
	SCIM bool `json:"scim,omitempty"`
}

// Provider is the public row; Config is only returned by Open.
type Provider struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      Type      `json:"type"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	// SCIMTokenAt is when the provider's SCIM token was made; nil when it
	// has none. The token itself is shown once and kept only as a hash.
	SCIMTokenAt *time.Time `json:"scim_token_created_at,omitempty"`
}

// AccessSummary is the part of a provider's configuration that decides who
// gets in and with what, recorded when a provider is created or changed so
// the log shows who configured, say, auto-provisioning as admin (ADR 0006:
// granting admin or auditor is an audit event). It never holds a secret:
// no client secret, bind password or CA bundle.
func AccessSummary(c *Config) map[string]any {
	d := map[string]any{"auto_provision": c.AutoProvision, "default_roles": c.DefaultRoles, "group_mapping": c.GroupMapping,
		"sync_users": c.SyncUsers, "sync_minutes": c.SyncMinutes, "scim": c.SCIM}
	if c.GroupMapping == nil {
		d["group_mapping"] = GroupMapping{}
	}
	if o := c.OIDC; o != nil {
		d["issuer"], d["client_id"], d["zanskar_mfa"] = o.Issuer, o.ClientID, o.ZanskarMFA
		d["allowed_domains"], d["username_claim"], d["groups_claim"] = orEmpty(o.AllowedDomains), o.UsernameClaim, o.GroupsClaim
		d["trust_email"], d["prompt_login"] = o.TrustEmail, o.PromptLogin
	}
	if l := c.LDAP; l != nil {
		d["url"], d["start_tls"], d["insecure_skip_verify"] = l.URL, l.StartTLS, l.InsecureSkipVerify
		d["bind_dn"], d["base_dn"], d["user_filter"], d["username_suffix"] = l.BindDN, l.BaseDN, l.UserFilter, l.UsernameSuffix
		d["group_attr"], d["group_base_dn"], d["group_filter"] = l.GroupAttr, l.GroupBaseDN, l.GroupFilter
	}
	return d
}

// ProviderOwnsMFA reports whether the provider's own sign-in is the second
// factor for the people it signs in (ADR 0035): an OIDC provider, unless it
// is marked as doing no MFA of its own (zanskar_mfa). A directory reached
// over LDAP checks only a password, so its people need a Zanskar
// authenticator.
func (c *Config) ProviderOwnsMFA() bool { return c.OIDC != nil && !c.OIDC.ZanskarMFA }

// SecondFactor returns the check behind a policy's "require MFA": an
// enrolled Zanskar authenticator (enrolled), or an account linked to a
// provider whose sign-in is the second factor. Such an account has no
// password, so the provider is the only way it signs in.
func SecondFactor(users *user.Repo, providers *Repo, enrolled func(context.Context, string) (bool, error)) func(context.Context, string) (bool, error) {
	return func(ctx context.Context, userID string) (bool, error) {
		ok, err := enrolled(ctx, userID)
		if err != nil || ok {
			return ok, err
		}
		u, err := users.GetByID(ctx, userID)
		if err != nil {
			return false, err
		}
		if u.IdPID == "" || u.PasswordHash != "" {
			return false, nil
		}
		op, err := providers.Open(ctx, u.IdPID)
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return op.Enabled && op.Config.ProviderOwnsMFA(), nil
	}
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
	return validateSync(c)
}

// SyncUsernameClaims are the username claims a Keycloak listing can give
// the same value for as a sign-in: the user's username, address and id.
var SyncUsernameClaims = []string{"preferred_username", "email", "sub"}

func validateSync(c *Config) error {
	if c.SCIM && c.SyncUsers {
		return fmt.Errorf("%w: a provider's people are either pushed to Zanskar (SCIM) or listed by it (user sync), not both", ErrInvalidInput)
	}
	if !c.SyncUsers {
		c.SyncMinutes = 0
		return nil
	}
	if c.SyncMinutes == 0 {
		c.SyncMinutes = 15
	}
	if c.SyncMinutes < 5 || c.SyncMinutes > 1440 {
		return fmt.Errorf("%w: sync_minutes must be 5 to 1440", ErrInvalidInput)
	}
	if o := c.OIDC; o != nil {
		if _, _, err := KeycloakRealm(o.Issuer); err != nil {
			return fmt.Errorf("%w: user sync lists a Keycloak realm; the issuer must be https://<host>/realms/<realm>", ErrInvalidInput)
		}
		if !slices.Contains(SyncUsernameClaims, o.UsernameClaim) {
			return fmt.Errorf("%w: user sync needs the username claim to be preferred_username, email or sub", ErrInvalidInput)
		}
	}
	return nil
}

// KeycloakRealm splits a Keycloak issuer, https://host[/prefix]/realms/name,
// into the address of the realm's admin API (https://host[/prefix]/admin/realms/name)
// and the realm's name.
func KeycloakRealm(issuer string) (adminBase, realm string, err error) {
	u, err := url.Parse(strings.TrimRight(issuer, "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", "", errors.New("not an https URL")
	}
	prefix, name, ok := strings.Cut(u.Path, "/realms/")
	if !ok || name == "" || strings.Contains(name, "/") || strings.Contains(prefix, "/realms") {
		return "", "", errors.New("not a Keycloak realm issuer")
	}
	u.Path = prefix + "/admin/realms/" + name
	u.RawPath = ""
	return u.String(), name, nil
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
		if store.IsUniqueViolation(err) {
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
		if store.IsUniqueViolation(err) {
			return ErrDuplicate
		}
		return err
	}
	return store.Affected(res, ErrNotFound)
}

// Get returns the public row.
func (r *Repo) Get(ctx context.Context, id string) (*Provider, error) {
	row := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT `+providerCols+` FROM identity_providers WHERE id = ?`), id)
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
	var scimAt store.NullTime
	err := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT id, name, type, config_enc, key_version, enabled, created_at, updated_at, scim_token_created_at FROM identity_providers WHERE id = ?`), id).
		Scan(&p.ID, &p.Name, &typ, &sealed, &ver, &p.Enabled, &created, &updated, &scimAt)
	p.SCIMTokenAt = scimAt.Ptr()
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
	q := `SELECT ` + providerCols + ` FROM identity_providers`
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

// MFAOwners lists the enabled providers whose own sign-in is an account's
// second factor (Config.ProviderOwnsMFA), for counting who still needs a
// Zanskar authenticator (2026-10-31). The listing is drained before any
// provider is opened (SQLite runs on one connection).
func (r *Repo) MFAOwners(ctx context.Context) ([]string, error) {
	ps, err := r.List(ctx, true)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, p := range ps {
		op, err := r.Open(ctx, p.ID)
		if err != nil {
			return nil, err
		}
		if op.Config.ProviderOwnsMFA() {
			out = append(out, p.ID)
		}
	}
	return out, nil
}

// Delete removes a provider. Users and groups linked to it keep their rows
// with idp_id set to NULL (schema ON DELETE SET NULL) and can no longer sign
// in through it. Such a user with no password counts as unlinked, so the next
// provider that asserts its username adopts it (Provisioner.Resolve).
func (r *Repo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM identity_providers WHERE id = ?`), id)
	if err != nil {
		return err
	}
	return store.Affected(res, ErrNotFound)
}

// NewSCIMToken makes a bearer token for a provider's SCIM client and the
// hash Zanskar keeps of it: 32 random bytes, so the hash needs no salt and
// a database read cannot be turned back into the token.
func NewSCIMToken() (token, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	token = "zscim_" + base64.RawURLEncoding.EncodeToString(b)
	return token, SCIMTokenHash(token), nil
}

// SCIMTokenHash is the stored form of a SCIM token.
func SCIMTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// SetSCIMToken stores a new token hash for the provider, replacing any
// earlier one, which stops working at once.
func (r *Repo) SetSCIMToken(ctx context.Context, id, hash string, at time.Time) error {
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE identity_providers SET scim_token_hash = ?, scim_token_created_at = ? WHERE id = ?`), hash, store.TimeArg(at), id)
	if err != nil {
		return err
	}
	return store.Affected(res, ErrNotFound)
}

// ClearSCIMToken revokes the provider's SCIM token.
func (r *Repo) ClearSCIMToken(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`UPDATE identity_providers SET scim_token_hash = NULL, scim_token_created_at = NULL WHERE id = ?`), id)
	if err != nil {
		return err
	}
	return store.Affected(res, ErrNotFound)
}

// CheckSCIMToken reports whether token is the provider's current SCIM
// token, comparing hashes in constant time. A provider with none, or none
// by that id, matches nothing.
func (r *Repo) CheckSCIMToken(ctx context.Context, id, token string) (bool, error) {
	var stored sql.NullString
	err := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT scim_token_hash FROM identity_providers WHERE id = ?`), id).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil || !stored.Valid || stored.String == "" || token == "" {
		return false, err
	}
	return subtle.ConstantTimeCompare([]byte(SCIMTokenHash(token)), []byte(stored.String)) == 1, nil
}

// Identity is what a provider asserts after a successful authentication.
type Identity struct {
	ExternalID  string // stable subject: OIDC sub, LDAP objectGUID/entryUUID or DN
	Username    string // login name to use in Zanskar
	DisplayName string
	Email       string
	Groups      []string // external group names, matched against GroupMapping
	// GroupDNs are the full DNs of the user's LDAP groups, matched against
	// mapping keys written as DNs; empty for OIDC.
	GroupDNs []string
}

// Provisioner turns an asserted Identity into a Zanskar user and syncs its
// mapped group memberships.
type Provisioner struct {
	Users  *user.Repo
	Groups GroupSyncer
	// Revoker, when set, ends the live sessions a group removal takes away
	// (ADR 0013), as an administrator's removal does.
	Revoker gateway.Revoker
}

// GroupSyncer is satisfied by *group.Repo; declared here to avoid a cycle.
type GroupSyncer interface {
	AddMember(ctx context.Context, groupID, userID string) error
	RemoveMember(ctx context.Context, groupID, userID string) error
	GroupIDsForUser(ctx context.Context, userID string) ([]string, error)
}

// Resolution is what Resolve did for one sign-in, for the caller to audit:
// an adopted or created account, and group memberships the sign-in changed.
type Resolution struct {
	User *user.User
	// Linked: a pre-created account was adopted (ADR 0005 addendum).
	Linked bool
	// Created: the account was provisioned on this sign-in, with the
	// provider's default roles.
	Created bool
	// GroupsAdded and GroupsRemoved are the mapped Zanskar groups this
	// sign-in added the user to or removed it from.
	GroupsAdded, GroupsRemoved []string
	// LiveSessionsEnded counts live sessions ended because a removal took
	// away the group that granted them.
	LiveSessionsEnded int
}

// ErrNotProvisioned is returned when auto-provisioning is off and there is
// neither a user linked to the external identity nor a pre-created account to
// adopt under the asserted username.
var ErrNotProvisioned = errors.New("idp: no matching user and auto-provisioning is disabled")

// ErrAccountConflict is returned when the username a provider asserts belongs
// to a local account the provider may not adopt (one with a password, or one
// already linked to another identity), or when a user cannot be created
// because another account holds the username or email. The wrapped message
// says which, and nothing is linked or created.
var ErrAccountConflict = errors.New("idp: account conflict")

var errLocked = errors.New("idp: account is disabled or locked")

// Resolve finds, adopts or creates the user for id under provider p and syncs
// mapped groups. In order:
//
//   - A user already linked to p and id.ExternalID is that person. Later
//     sign-ins always match here, so a rename in the directory keeps the
//     account.
//   - Otherwise the local account with the username the provider asserts
//     (the one just-in-time provisioning would create) is adopted when it has
//     no password and no provider: an administrator created it for someone
//     who signs in through a provider (the admin API's password_less). It is
//     linked to p and id.ExternalID and nothing else changes; in particular
//     it keeps the roles the administrator chose. linked reports this, so
//     the caller records the link (LinkEvent). A local account with a
//     password, or one linked to another provider or to another subject at
//     p, is refused with ErrAccountConflict: a sign-in never takes over a
//     password account nor moves an account between identities. A disabled
//     or locked account is refused and not linked.
//   - Otherwise, with AutoProvision a user is created with DefaultRoles;
//     without it the answer is ErrNotProvisioned.
func (pv *Provisioner) Resolve(ctx context.Context, p *Opened, id Identity) (Resolution, error) {
	var res Resolution
	if !user.ValidUsername(id.Username) {
		return res, fmt.Errorf("%w: provider asserted an unusable username %q", ErrInvalidInput, id.Username)
	}
	u, err := pv.Users.GetByExternalID(ctx, p.ID, id.ExternalID)
	if errors.Is(err, user.ErrNotFound) {
		u, err = pv.adopt(ctx, p, id)
		res.Linked = err == nil
		if errors.Is(err, user.ErrNotFound) {
			u, err = pv.create(ctx, p, id)
			res.Created = err == nil
		}
	}
	if err != nil {
		return Resolution{}, err
	}
	if !res.Created && (u.DisplayName != id.DisplayName || (id.Email != "" && u.Email != id.Email)) {
		name := id.DisplayName
		if name == "" {
			name = u.DisplayName
		}
		_ = pv.Users.Update(ctx, u.ID, name, firstNonEmpty(id.Email, u.Email), u.Status)
	}
	if u.IsLocked(time.Now()) {
		return Resolution{}, errLocked
	}
	if pv.Groups != nil && len(p.Config.GroupMapping) > 0 {
		pv.syncGroups(ctx, p, id, u.ID, &res)
	}
	if res.User, err = pv.Users.GetByID(ctx, u.ID); err != nil {
		return Resolution{}, err
	}
	return res, nil
}

// syncGroups brings the user's mapped memberships in line with the groups
// the provider asserted, records what changed, and ends the live sessions a
// removal takes away. A group that cannot be changed is left as it is and
// the sign-in goes on; the result lists only what did change.
func (pv *Provisioner) syncGroups(ctx context.Context, p *Opened, id Identity, userID string, res *Resolution) {
	before := map[string]bool{}
	if ids, err := pv.Groups.GroupIDsForUser(ctx, userID); err == nil {
		for _, gid := range ids {
			before[gid] = true
		}
	}
	names := map[string]bool{}
	for _, g := range id.Groups {
		names[strings.ToLower(g)] = true
	}
	var dns []*goldap.DN
	for _, raw := range id.GroupDNs {
		if dn, err := goldap.ParseDN(raw); err == nil {
			dns = append(dns, dn)
		}
	}
	keys := make([]string, 0, len(p.Config.GroupMapping))
	for ext := range p.Config.GroupMapping {
		keys = append(keys, ext)
	}
	sort.Strings(keys) // a stable order for the audit details
	for _, ext := range keys {
		gid := p.Config.GroupMapping[ext]
		if holds(ext, names, dns) {
			if !before[gid] && pv.Groups.AddMember(ctx, gid, userID) == nil {
				res.GroupsAdded = append(res.GroupsAdded, gid)
				before[gid] = true
			}
			continue
		}
		if before[gid] && pv.Groups.RemoveMember(ctx, gid, userID) == nil {
			res.GroupsRemoved = append(res.GroupsRemoved, gid)
			delete(before, gid)
			if pv.Revoker != nil {
				res.LiveSessionsEnded += pv.Revoker.Recheck(ctx, []string{userID})
			}
		}
	}
}

// holds reports whether the asserted groups include the mapping key: a key
// written as a DN is compared with each group DN as LDAP compares DNs; any
// other key with the group names, ignoring case.
func holds(key string, names map[string]bool, dns []*goldap.DN) bool {
	if strings.Contains(key, "=") {
		want, err := goldap.ParseDN(key)
		if err != nil {
			return false
		}
		return slices.ContainsFunc(dns, want.EqualFold)
	}
	return names[strings.ToLower(key)]
}

// adopt links the local account named id.Username to p and id.ExternalID
// when Resolve's rules allow it. user.ErrNotFound means there is no such
// account and the caller decides whether to create one.
func (pv *Provisioner) adopt(ctx context.Context, p *Opened, id Identity) (*user.User, error) {
	u, err := pv.Users.GetByUsername(ctx, id.Username)
	if err != nil {
		return nil, err
	}
	switch {
	case u.PasswordHash != "":
		return nil, fmt.Errorf("%w: a local account named %q has a password; remove it or rename one of them", ErrAccountConflict, u.Username)
	case u.IdPID == p.ID && u.ExternalID == "":
		// Provisioned for this provider (pushed over SCIM) and never signed
		// in to: the provider vouches for the username both times, and now
		// says who holds it. Entra ID's subject is made per application, so
		// the username, not an id, is what the push and the sign-in share.
		if u.IsLocked(time.Now()) {
			return nil, errLocked
		}
	case u.IdPID == p.ID:
		return nil, fmt.Errorf("%w: the local account %q is linked to a different identity at this provider", ErrAccountConflict, u.Username)
	case u.IdPID != "":
		return nil, fmt.Errorf("%w: the local account %q is linked to another identity provider", ErrAccountConflict, u.Username)
	case u.IsLocked(time.Now()):
		return nil, errLocked
	}
	if err := pv.Users.LinkExternal(ctx, u.ID, p.ID, id.ExternalID); err != nil {
		if errors.Is(err, user.ErrDuplicate) {
			return nil, fmt.Errorf("%w: the local account %q was linked or given a password meanwhile", ErrAccountConflict, u.Username)
		}
		return nil, err
	}
	u.IdPID, u.ExternalID = p.ID, id.ExternalID
	return u, nil
}

// create provisions a new user for id when p allows it.
func (pv *Provisioner) create(ctx context.Context, p *Opened, id Identity) (*user.User, error) {
	if !p.Config.AutoProvision {
		return nil, ErrNotProvisioned
	}
	name := id.DisplayName
	if name == "" {
		name = id.Username
	}
	u := &user.User{Username: id.Username, DisplayName: name, Email: id.Email, Roles: p.Config.DefaultRoles, IdPID: p.ID, ExternalID: id.ExternalID}
	if err := pv.Users.Create(ctx, u); err != nil {
		if errors.Is(err, user.ErrDuplicate) {
			// adopt found no account by this username a moment ago, so this
			// is the email address, or another sign-in that got there first.
			return nil, fmt.Errorf("%w: the username %q or its email address is already taken", ErrAccountConflict, id.Username)
		}
		return nil, err
	}
	return u, nil
}

// Events are the audit events a sign-in's Resolution owes, in order: the
// account adopted or created (with its roles, as an administrator's create
// records them: granting admin or auditor is an audit event, ADR 0006),
// then the mapped group memberships the sign-in changed. The actor is the
// signed-in account, from ip.
func (r Resolution) Events(ip string, p *Opened, id Identity) []audit.Event {
	var out []audit.Event
	if r.Linked {
		out = append(out, LinkEvent(ip, r.User, p, id))
	}
	actor := audit.Actor{UserID: r.User.ID, IP: ip}
	if r.Created {
		d := map[string]any{"username": r.User.Username, "roles": r.User.Roles, "has_password": false,
			"via": "identity_provider", "idp": p.ID, "idp_name": p.Name, "external_id": id.ExternalID}
		var granted []user.Role
		for _, role := range r.User.Roles {
			if role != user.RoleUser {
				granted = append(granted, role)
			}
		}
		if len(granted) > 0 {
			d["roles_granted"] = granted
		}
		out = append(out, actor.Event(audit.UserCreate, "user", r.User.ID, audit.Success, d))
	}
	if len(r.GroupsAdded)+len(r.GroupsRemoved) > 0 {
		d := map[string]any{"idp": p.ID, "idp_name": p.Name, "groups_added": orEmpty(r.GroupsAdded), "groups_removed": orEmpty(r.GroupsRemoved)}
		if len(r.GroupsRemoved) > 0 {
			d["live_sessions_ended"] = r.LiveSessionsEnded
		}
		out = append(out, actor.Event(audit.UserGroupsSync, "user", r.User.ID, audit.Success, d))
	}
	return out
}

func orEmpty(ids []string) []string {
	if ids == nil {
		return []string{}
	}
	return ids
}

// LinkEvent is the audit event for a sign-in that adopted a pre-created
// account (Resolve reported linked): user.link, with the account as the actor,
// since the person signing in is who caused it. It is recorded on its own,
// apart from the user.login that follows, because the link stays even if the
// sign-in goes no further.
func LinkEvent(ip string, u *user.User, p *Opened, id Identity) audit.Event {
	return audit.Actor{UserID: u.ID, IP: ip}.Event(audit.UserLink, "user", u.ID, audit.Success,
		map[string]string{"idp": p.ID, "idp_name": p.Name, "external_id": id.ExternalID})
}

// ---- helpers

func (r *Repo) seal(id string, c *Config) ([]byte, int, error) {
	plain, err := json.Marshal(c)
	if err != nil {
		return nil, 0, err
	}
	return r.ring.Encrypt(keyring.AAD("identity_providers", id), plain)
}

const providerCols = `id, name, type, enabled, created_at, updated_at, scim_token_created_at`

func scan(s store.Scanner) (*Provider, error) {
	var (
		p                        Provider
		typ                      string
		created, updated, scimAt store.NullTime
	)
	if err := s.Scan(&p.ID, &p.Name, &typ, &p.Enabled, &created, &updated, &scimAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	p.Type, p.CreatedAt, p.UpdatedAt, p.SCIMTokenAt = Type(typ), created.Time, updated.Time, scimAt.Ptr()
	return &p, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
