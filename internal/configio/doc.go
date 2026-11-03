// SPDX-License-Identifier: Apache-2.0

// Package configio exports the gateway's configuration as YAML and imports
// it back (ADR 0043): groups, hosts, databases, applications and access
// policies, every reference by name, so a file kept in git can rebuild a
// gateway or be reviewed in a pull request. Secrets never leave: a credential
// is named, not copied, and must exist where the file is imported.
//
// Every read and every change goes through the gateway's own API, in
// process, as the importing administrator: the same validation, address
// rules, step-up, audit events and live-session re-checks as a change made in
// the console. The package knows the API's JSON, not its repositories.
package configio

// Version is the file format this build writes and reads.
const Version = 1

// Document is the file.
type Document struct {
	Zanskar    int      `yaml:"zanskar"`
	ExportedAt string   `yaml:"exported_at,omitempty"`
	Groups     []Group  `yaml:"groups,omitempty"`
	Targets    []Target `yaml:"targets,omitempty"`
	Policies   []Policy `yaml:"policies,omitempty"`
}

// Group is a group of people; members by username.
type Group struct {
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description,omitempty" json:"description"`
	Members     []string `yaml:"members,omitempty" json:"-"`
}

// Endpoint is one of an application's further origins (ADR 0037).
type Endpoint struct {
	Name string `yaml:"name" json:"name"`
	URL  string `yaml:"url" json:"url"`
}

// Target is a host, database or application, as the target API writes it,
// its credentials named.
type Target struct {
	Name          string            `yaml:"name"`
	Address       string            `yaml:"address,omitempty"`
	OSFamily      string            `yaml:"os_family,omitempty"`
	Engine        string            `yaml:"engine,omitempty"`
	EngineVersion string            `yaml:"engine_version,omitempty"`
	DatabaseName  string            `yaml:"database_name,omitempty"`
	TLSMode       string            `yaml:"tls_mode,omitempty"`
	TLSCA         string            `yaml:"tls_ca,omitempty"`
	AppUpstream   string            `yaml:"app_upstream,omitempty"`
	AppEndpoints  []Endpoint        `yaml:"app_endpoints,omitempty"`
	Ports         map[string]int    `yaml:"ports,omitempty"`
	Tags          map[string]string `yaml:"tags,omitempty"`
	Status        string            `yaml:"status,omitempty"`
	Notes         string            `yaml:"notes,omitempty"`
	RetentionDays *int              `yaml:"retention_days,omitempty"`
	// Credentials names the credential each protocol signs in with.
	Credentials map[string]string `yaml:"credentials,omitempty"`
}

// Subject is a group or a person a policy is for: one of the two set.
type Subject struct {
	Group string `yaml:"group,omitempty"`
	User  string `yaml:"user,omitempty"`
}

// GrantTarget is a target or autoscaling group a grant names, with the
// protocols it grants there.
type GrantTarget struct {
	Name      string   `yaml:"name"`
	Protocols []string `yaml:"protocols,omitempty,flow"`
}

// TagMatch selects targets by tag (ADR 0036).
type TagMatch struct {
	Match     map[string][]string `yaml:"match"`
	Protocols []string            `yaml:"protocols,omitempty,flow"`
}

// TimeWindow is a weekly window.
type TimeWindow struct {
	Days []string `yaml:"days,flow" json:"days"`
	From string   `yaml:"from" json:"from"`
	To   string   `yaml:"to" json:"to"`
	TZ   string   `yaml:"tz,omitempty" json:"tz"`
}

// Grant is one grant of a policy, its targets named.
type Grant struct {
	Kind              string        `yaml:"kind"`
	Targets           []GrantTarget `yaml:"targets,omitempty"`
	Tags              *TagMatch     `yaml:"tags,omitempty"`
	Access            string        `yaml:"access,omitempty"`
	SignIn            string        `yaml:"sign_in,omitempty"`
	RequireMFA        bool          `yaml:"require_mfa"`
	AllowClipboard    bool          `yaml:"allow_clipboard,omitempty"`
	AllowFileTransfer bool          `yaml:"allow_file_transfer,omitempty"`
	AllowDevTools     bool          `yaml:"allow_devtools,omitempty"`
	// RequireWatcher is read only to refuse it: four eyes was removed in
	// 1.16.0, and a file from 1.15.0 may still ask for it.
	RequireWatcher     bool         `yaml:"require_watcher,omitempty"`
	IdleTimeoutMinutes int          `yaml:"idle_timeout_minutes,omitempty"`
	MaxSessionMinutes  *int         `yaml:"max_session_minutes,omitempty"`
	TimeWindows        []TimeWindow `yaml:"time_windows,omitempty"`
	RetentionDays      *int         `yaml:"retention_days,omitempty"`
}

// Policy is an audience and its grants (ADR 0036).
type Policy struct {
	Name        string    `yaml:"name"`
	Description string    `yaml:"description,omitempty"`
	Enabled     bool      `yaml:"enabled"`
	Subjects    []Subject `yaml:"subjects,omitempty"`
	Grants      []Grant   `yaml:"grants,omitempty"`
}
