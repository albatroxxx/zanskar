// SPDX-License-Identifier: Apache-2.0

// Package settings holds the runtime settings an administrator edits in the
// console and the gateway applies live, without a restart (ADR 0020). Each
// setting has a built-in default, may take an install-time value from an
// environment variable, and may be overridden from the console; the console
// value wins until it is reset. Boot settings (listen address, database,
// master key, TLS files) are environment only, read once at start, and are
// listed here read-only so the panel can show them.
package settings

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/version"
)

// Type says how a value is edited and validated.
type Type string

// Types.
const (
	TypeString   Type = "string"
	TypeText     Type = "text"     // multi-line
	TypeBool     Type = "bool"     // "true" | "false"
	TypeEnum     Type = "enum"     // one of Definition.Enum
	TypeHostPort Type = "hostport" // host:port, or empty
)

// Sources of an effective value, from lowest to highest precedence.
const (
	SourceDefault     = "default"
	SourceEnvironment = "environment"
	SourceConsole     = "console"
)

// Keys.
const (
	// KeyLoginBanner is the system-use notification shown on the sign-in
	// page before any credential is entered (NIST AC-8). Empty hides it.
	KeyLoginBanner = "login_banner"
	// KeyRequireMFA keeps a password session partial until an authenticator
	// is enrolled.
	KeyRequireMFA = "auth.require_mfa"
	// KeyGuacdAddr is the guacd host:port that relays RDP and VNC; empty
	// disables desktop sessions.
	KeyGuacdAddr = "desktop.guacd_addr"
	// KeyUpdateCheck lets the gateway fetch the latest version number from
	// the project site once a day and light the bell when it is newer
	// (ADR 0032). Nothing about this gateway is sent.
	KeyUpdateCheck = "updates.check"
	// KeyLogLevel is the gateway's log level.
	KeyLogLevel = "log.level"
	// KeyDBProxyImage is the image run as the MySQL/MariaDB relay sidecar;
	// by default the gateway's own release image at its own version.
	KeyDBProxyImage = "database.proxy_image"
	// KeyAppsDomain is the domain applications are served under (ADR 0033),
	// one subdomain each; empty means applications are off.
	KeyAppsDomain = "apps.domain"
)

// domainRe is a domain name as the apps domain must be written: lowercase
// labels joined by dots, at least two of them, no wildcard, scheme or port.
var domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+$`)

func validDomain(s string) bool { return len(s) <= 253 && domainRe.MatchString(s) }

// DefaultDBProxyImage is the gateway's own image at the running version. A
// development build has no published tag, so it points at latest and the
// setting must be overridden to test the relay from a local build. It is a
// tag, not a digest: the binary that names it is built into that image, so
// the digest is not known when the binary is.
func DefaultDBProxyImage() string {
	v := strings.TrimPrefix(version.Version, "v")
	if v == "" || v == "dev" {
		v = "latest"
	}
	return "ghcr.io/albatroxxx/zanskar:" + v
}

// Image references as the OCI distribution spec writes them, cut to what a
// relay image needs: an optional registry host with an optional port, a
// lowercase repository path, an optional tag and an optional sha256 digest.
const (
	refHostPart = `(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])`
	refRegistry = refHostPart + `(?:\.` + refHostPart + `)*(?::[0-9]+)?`
	refPathPart = `[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*`
	refName     = `(?:` + refRegistry + `/)?` + refPathPart + `(?:/` + refPathPart + `)*`
)

// imageRefRe matches a whole image reference and captures its name. Anchored
// at both ends it admits no space, no control character and no leading "-",
// so the value cannot become a flag or a second argument of the `docker run`
// it is placed in.
var imageRefRe = regexp.MustCompile(`^(` + refName + `)(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$`)

// maxImageName is the longest repository name a registry takes, registry host
// included; with a tag of at most 128 characters and a digest the whole
// reference stays under 460.
const maxImageName = 255

// checkImageRef refuses a value that is not an image reference.
func checkImageRef(v string) error {
	m := imageRefRe.FindStringSubmatch(v)
	if m == nil {
		return errors.New("must be an image reference, such as ghcr.io/albatroxxx/zanskar:1.3.0 or a mirror's registry.example.com/zanskar@sha256:<64 hex digits>: a lowercase repository path, an optional :tag and an optional @sha256 digest, with no spaces")
	}
	if len(m[1]) > maxImageName {
		return fmt.Errorf("must be an image reference whose name (registry and repository) is at most %d characters", maxImageName)
	}
	return nil
}

// RequireDigest is the console-side check on the relay image: a value set
// over HTTP must pin its content by digest, so what the next database
// session hands the credential to is exactly what the administrator named
// (threat model risk 7). The environment file, root's to edit, may name a
// tag, as the default does.
func RequireDigest(v string) error {
	if !strings.Contains(v, "@sha256:") {
		return errors.New("must be pinned by digest when set from the console: registry/repository@sha256:<64 hex digits>")
	}
	return nil
}

// MaxLoginBanner bounds the banner: long enough for a legal notice, short
// enough that the sign-in form stays on the page.
const MaxLoginBanner = 4000

// Definition describes one runtime setting.
type Definition struct {
	Key         string   `json:"key"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Type        Type     `json:"type"`
	Default     string   `json:"default"`
	EnvVar      string   `json:"env_var,omitempty"`
	Enum        []string `json:"enum,omitempty"`
	// StepUp marks a setting that decides where a vaulted credential is
	// sent; changing or resetting it from the console asks for an
	// authenticator code proved in the last auth.StepUpWindow (ADR 0020,
	// threat model risk 7).
	StepUp bool `json:"step_up,omitempty"`
}

// Definitions lists every runtime setting, in the order the panel shows them.
var Definitions = []Definition{
	{Key: KeyLoginBanner, Category: "Sign-in", Title: "Login banner", Type: TypeText,
		Description: "System-use notification shown above the sign-in form before any credential is entered. Plain text, line breaks kept; empty hides it."},
	{Key: KeyRequireMFA, Category: "Sign-in", Title: "Require an authenticator", Type: TypeBool, Default: "true", EnvVar: "ZANSKAR_REQUIRE_MFA",
		Description: "Every password sign-in must enroll an authenticator before the session becomes usable. Turn off only for a throwaway installation."},
	{Key: KeyUpdateCheck, Category: "Updates", Title: "Check for new versions", Type: TypeBool, Default: "true",
		Description: "Once a day, fetch the latest version number from the project site and light the bell when it is newer. Nothing about this gateway is sent."},
	{Key: KeyGuacdAddr, Category: "Desktops", Title: "guacd address", Type: TypeHostPort, EnvVar: "ZANSKAR_GUACD_ADDR", StepUp: true,
		Description: "host:port of the guacd relay for RDP and VNC. Empty disables desktop sessions. Applies to the next session opened. guacd receives the desktop credential, so the console accepts a loopback or private address only, and a change asks for a fresh authenticator code."},
	{Key: KeyLogLevel, Category: "Logging", Title: "Log level", Type: TypeEnum, Default: "info", EnvVar: "ZANSKAR_LOG_LEVEL", Enum: []string{"debug", "info", "warn", "error"},
		Description: "Verbosity of the gateway's log. Applies at once; go back to info afterwards."},
	{Key: KeyDBProxyImage, Category: "Databases", Title: "MySQL relay image", Type: TypeString, Default: DefaultDBProxyImage(), EnvVar: "ZANSKAR_DBPROXY_IMAGE", StepUp: true,
		Description: "Container image started beside each MySQL or MariaDB session to hold the credential and relay the protocol: the gateway's own image, running zanskar dbproxy. Change it only to pin a mirror or test a local build. The relay receives the database credential, so the console accepts only an image pinned by digest (registry/repository@sha256:<64 hex digits>, a :tag before it is fine) and a change asks for a fresh authenticator code; the environment file may name a tag. Applies to the next session."},
	{Key: KeyAppsDomain, Category: "Applications", Title: "Apps domain", Type: TypeString, EnvVar: "ZANSKAR_APPS_DOMAIN",
		Description: "The domain applications are served under, one subdomain each: an application labelled wiki is reached at wiki.<domain>. Needs wildcard DNS for *.<domain> pointing at the gateway and a certificate for it (TLS certificate below). It must not be the console's own host or a parent of it. Empty turns applications off."},
}

// Lookup returns the definition for key.
func Lookup(key string) (Definition, bool) {
	for _, d := range Definitions {
		if d.Key == key {
			return d, true
		}
	}
	return Definition{}, false
}

// Value is one runtime setting as resolved: the effective value and where it
// came from, with who last set it in the console when that is the source.
type Value struct {
	Definition
	Value     string     `json:"value"`
	Source    string     `json:"source"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	UpdatedBy string     `json:"updated_by,omitempty"`
}

// Boot is a setting fixed at start from the environment, shown read-only.
type Boot struct {
	Key         string `json:"key"`
	Title       string `json:"title"`
	EnvVar      string `json:"env_var"`
	Value       string `json:"value"` // masked where it is a secret
	Description string `json:"description"`
}

// Setting is one stored console row.
type Setting struct {
	Key       string     `json:"key"`
	Value     string     `json:"value"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	UpdatedBy string     `json:"updated_by,omitempty"`
}

// Errors.
var (
	ErrInvalid = errors.New("settings: invalid value")
	ErrUnknown = errors.New("settings: unknown setting")
)

// Validate normalises a value for its definition and refuses what the type
// does not accept.
func Validate(d Definition, value string) (string, error) {
	switch d.Type {
	case TypeText:
		v := strings.TrimSpace(strings.ReplaceAll(value, "\r\n", "\n"))
		if !utf8.ValidString(v) {
			return "", fmt.Errorf("%w: %s must be valid UTF-8", ErrInvalid, d.Key)
		}
		if d.Key == KeyLoginBanner && utf8.RuneCountInString(v) > MaxLoginBanner {
			return "", fmt.Errorf("%w: banner must be at most %d characters", ErrInvalid, MaxLoginBanner)
		}
		return v, nil
	case TypeBool:
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "true", "1", "yes", "on":
			return "true", nil
		case "false", "0", "no", "off":
			return "false", nil
		}
		return "", fmt.Errorf("%w: %s must be true or false", ErrInvalid, d.Key)
	case TypeEnum:
		v := strings.ToLower(strings.TrimSpace(value))
		if slices.Contains(d.Enum, v) {
			return v, nil
		}
		return "", fmt.Errorf("%w: %s must be one of %s", ErrInvalid, d.Key, strings.Join(d.Enum, ", "))
	case TypeHostPort:
		v := strings.TrimSpace(value)
		if v == "" {
			return "", nil
		}
		host, port, err := net.SplitHostPort(v)
		if err != nil || host == "" {
			return "", fmt.Errorf("%w: %s must be host:port", ErrInvalid, d.Key)
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("%w: %s port must be 1-65535", ErrInvalid, d.Key)
		}
		return v, nil
	default:
		v := strings.TrimSpace(value)
		if !utf8.ValidString(v) || len(v) > 4096 {
			return "", fmt.Errorf("%w: %s must be valid UTF-8 up to 4096 bytes", ErrInvalid, d.Key)
		}
		// The relay image is an argument of `docker run`; free text there
		// could be read as one of its flags (--privileged, a host mount).
		if d.Key == KeyDBProxyImage {
			if err := checkImageRef(v); err != nil {
				return "", fmt.Errorf("%w: %s %w", ErrInvalid, d.Key, err)
			}
		}
		// The apps domain is matched against every request's host and named
		// in certificates: one plain domain, nothing else.
		if d.Key == KeyAppsDomain {
			v = strings.ToLower(strings.TrimSuffix(v, "."))
			if v != "" && !validDomain(v) {
				return "", fmt.Errorf("%w: %s must be a domain name such as apps.example.com: lowercase letters, digits and hyphens, at least one dot, no wildcard, scheme or port", ErrInvalid, d.Key)
			}
		}
		return v, nil
	}
}

// EnvValues reads the install-time value of every runtime setting that has
// an environment variable, normalised; variables that are unset are absent.
// A value that fails validation is left out and reported, naming the
// variable: it used to be dropped without a word, so ZANSKAR_GUACD_ADDR
// without a port switched desktops off and nothing said why (B13).
func EnvValues() (map[string]string, []error) {
	out := map[string]string{}
	var errs []error
	for _, d := range Definitions {
		if d.EnvVar == "" {
			continue
		}
		raw, ok := os.LookupEnv(d.EnvVar)
		if !ok {
			continue
		}
		v, err := Validate(d, raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", d.EnvVar, err))
			continue
		}
		out[d.Key] = v
	}
	return out, errs
}

// Repo reads and writes console rows.
type Repo struct{ db *store.DB }

// NewRepo returns a repository over db.
func NewRepo(db *store.DB) *Repo { return &Repo{db: db} }

// All returns every console row.
func (r *Repo) All(ctx context.Context) ([]Setting, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT key, value, updated_at, updated_by FROM settings ORDER BY key`)
	if err != nil {
		return nil, fmt.Errorf("settings: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Setting
	for rows.Next() {
		var s Setting
		var updated store.NullTime
		var by sql.NullString
		if err := rows.Scan(&s.Key, &s.Value, &updated, &by); err != nil {
			return nil, err
		}
		s.UpdatedAt, s.UpdatedBy = updated.Ptr(), by.String
		out = append(out, s)
	}
	return out, rows.Err()
}

// Get returns the console row, or an empty one for a key never set.
func (r *Repo) Get(ctx context.Context, key string) (Setting, error) {
	s := Setting{Key: key}
	var updated store.NullTime
	var by sql.NullString
	err := r.db.QueryRowContext(ctx, r.db.Rebind(`SELECT value, updated_at, updated_by FROM settings WHERE key = ?`), key).Scan(&s.Value, &updated, &by)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return s, nil
		}
		return s, fmt.Errorf("settings: get %s: %w", key, err)
	}
	s.UpdatedAt, s.UpdatedBy = updated.Ptr(), by.String
	return s, nil
}

// Set stores an already-validated value, recording who set it.
func (r *Repo) Set(ctx context.Context, key, value, actorUserID string) (Setting, error) {
	now := time.Now().UTC()
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by`),
		key, value, store.TimeArg(now), sql.NullString{String: actorUserID, Valid: actorUserID != ""})
	if err != nil {
		return Setting{}, fmt.Errorf("settings: set %s: %w", key, err)
	}
	return r.Get(ctx, key)
}

// Delete removes the console row so the environment or default applies.
func (r *Repo) Delete(ctx context.Context, key string) error {
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM settings WHERE key = ?`), key)
	if err != nil {
		return fmt.Errorf("settings: delete %s: %w", key, err)
	}
	return nil
}

// Service resolves settings with their precedence, caches them for the hot
// paths that read them per request, and tells subscribers when one changes
// so it applies live.
type Service struct {
	repo *Repo
	env  map[string]string
	boot []Boot
	// Logger, when set, names a stored value Load leaves out.
	Logger *slog.Logger

	mu     sync.RWMutex
	rows   map[string]Setting
	subs   map[string][]func(string)
	checks map[string]func(string) error
}

// NewService builds a service over repo. env holds install-time values by
// key (EnvValues, or a literal in tests); boot is the read-only list.
func NewService(repo *Repo, env map[string]string, boot []Boot) *Service {
	if env == nil {
		env = map[string]string{}
	}
	return &Service{repo: repo, env: env, boot: boot, rows: map[string]Setting{}, subs: map[string][]func(string){}, checks: map[string]func(string) error{}}
}

// Check adds a rule for key that Set applies after Validate: what depends on
// the rest of the configuration, which Validate cannot see, such as the apps
// domain against the console's own host. The rule's error is shown to the
// administrator after the key's name.
func (s *Service) Check(key string, fn func(value string) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checks[key] = fn
}

// Load reads every console row into the cache. Call once after migrations.
func (s *Service) Load(ctx context.Context) error {
	all, err := s.repo.All(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows = map[string]Setting{}
	for _, row := range all {
		d, ok := Lookup(row.Key)
		if !ok {
			continue
		}
		// A value stored before its check existed (a relay image that is
		// not an image reference) is not used: the environment value or the
		// default applies until an administrator sets it again. It is named
		// at start, so a mirror pinned in an air-gapped install does not
		// vanish in silence.
		if _, err := Validate(d, row.Value); err != nil {
			if s.Logger != nil {
				s.Logger.Warn("stored setting ignored; set it again in the console", "setting", row.Key, "err", err)
			}
			continue
		}
		s.rows[row.Key] = row
	}
	return nil
}

// Get resolves the effective value of key: console, else environment, else
// the built-in default.
func (s *Service) Get(key string) (Value, error) {
	d, ok := Lookup(key)
	if !ok {
		return Value{}, ErrUnknown
	}
	s.mu.RLock()
	row, set := s.rows[key]
	s.mu.RUnlock()
	v := Value{Definition: d, Value: d.Default, Source: SourceDefault}
	if env, ok := s.env[key]; ok {
		v.Value, v.Source = env, SourceEnvironment
	}
	if set {
		v.Value, v.Source, v.UpdatedAt, v.UpdatedBy = row.Value, SourceConsole, row.UpdatedAt, row.UpdatedBy
	}
	return v, nil
}

// String returns the effective value, or "" for an unknown key.
func (s *Service) String(key string) string {
	v, _ := s.Get(key)
	return v.Value
}

// Bool returns the effective value as a boolean; anything but "true" is false.
func (s *Service) Bool(key string) bool { return s.String(key) == "true" }

// All returns every runtime setting resolved, in definition order.
func (s *Service) All() []Value {
	out := make([]Value, 0, len(Definitions))
	for _, d := range Definitions {
		v, _ := s.Get(d.Key)
		out = append(out, v)
	}
	return out
}

// BootSettings returns the read-only install-time settings.
func (s *Service) BootSettings() []Boot {
	out := append([]Boot(nil), s.boot...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Set validates and stores a console value, applies it to the cache and
// tells subscribers. Returns the resolved value.
func (s *Service) Set(ctx context.Context, key, value, actorUserID string) (Value, error) {
	d, ok := Lookup(key)
	if !ok {
		return Value{}, ErrUnknown
	}
	value, err := Validate(d, value)
	if err != nil {
		return Value{}, err
	}
	s.mu.RLock()
	check := s.checks[key]
	s.mu.RUnlock()
	if check != nil {
		if err := check(value); err != nil {
			return Value{}, fmt.Errorf("%w: %s %w", ErrInvalid, key, err)
		}
	}
	row, err := s.repo.Set(ctx, key, value, actorUserID)
	if err != nil {
		return Value{}, err
	}
	s.mu.Lock()
	s.rows[key] = row
	subs := append([]func(string){}, s.subs[key]...)
	s.mu.Unlock()
	for _, fn := range subs {
		fn(value)
	}
	return s.Get(key)
}

// Reset removes the console value so the environment or default applies
// again, and tells subscribers the new effective value.
func (s *Service) Reset(ctx context.Context, key string) (Value, error) {
	if _, ok := Lookup(key); !ok {
		return Value{}, ErrUnknown
	}
	if err := s.repo.Delete(ctx, key); err != nil {
		return Value{}, err
	}
	s.mu.Lock()
	delete(s.rows, key)
	subs := append([]func(string){}, s.subs[key]...)
	s.mu.Unlock()
	v, _ := s.Get(key)
	for _, fn := range subs {
		fn(v.Value)
	}
	return v, nil
}

// Subscribe registers fn to run with the new effective value whenever key is
// set or reset. fn runs on the caller's goroutine and must be quick.
func (s *Service) Subscribe(key string, fn func(string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subs[key] = append(s.subs[key], fn)
}
