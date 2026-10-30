// SPDX-License-Identifier: Apache-2.0

// Package bootedit is what the console may change in the environment file
// through the root helper (ADR 0020, amended 2026-10-30): the allowlist, the
// TLS presets, a validator for each key, and the merge of a change into the
// file. The gateway and the helper share it, so the gateway refuses what the
// helper would refuse, and the helper trusts nothing the gateway wrote.
package bootedit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/albatroxxx/zanskar/internal/tlscert"
)

// Files under the state directory: the gateway writes the request, the
// helper the result.
const (
	RequestFile = "config-request"
	ResultFile  = "config-result"
	// MaxRequest bounds a request the helper will read.
	MaxRequest = 16 << 10
)

// Result states.
const (
	Applied    = "applied"     // written, and the gateway came back with it
	Refused    = "refused"     // not written: the request or the new file did not pass
	RolledBack = "rolled_back" // written, the gateway did not come back, the previous file is back
)

// ErrInvalid is a request the helper would refuse.
var ErrInvalid = errors.New("bootedit: invalid change")

// Request is what the gateway writes for the helper.
type Request struct {
	ID          string    `json:"id"`
	RequestedBy string    `json:"requested_by"`
	RequestedAt time.Time `json:"requested_at"`
	// Values are new values for allowlisted variables; "" takes a line out.
	Values map[string]string `json:"values,omitempty"`
	// TLSMode picks a preset (managed or proxy) that sets the listen
	// address and the proxy trust with the mode.
	TLSMode string `json:"tls_mode,omitempty"`
}

// Result is what the helper writes back; the gateway reads it.
type Result struct {
	ID string `json:"id"`
	// RequestedBy is the request's, so the gateway can audit the outcome
	// under the administrator who asked.
	RequestedBy string    `json:"requested_by,omitempty"`
	State       string    `json:"state"`
	Message     string    `json:"message,omitempty"`
	Changed     []string  `json:"changed,omitempty"` // variable names only
	At          time.Time `json:"at"`
	// Acknowledged marks a result the gateway has audited.
	Acknowledged bool `json:"acknowledged,omitempty"`
}

// allowed is what the console may set, each with its check. What is left
// out stays install-only on purpose (ADR 0020, amended 2026-10-30): the
// database, the master key, the container runtime, the listen address
// outside the presets, plain HTTP, the proxy trust, the TLS file paths,
// the recordings directory, SIEM export.
var allowed = map[string]func(string) error{
	"ZANSKAR_APPS_MAX_SESSIONS":     sessionCap,
	"ZANSKAR_DATABASE_MAX_SESSIONS": sessionCap,
	"ZANSKAR_PUBLIC_URL":            publicURL,
	"ZANSKAR_TLS_HOSTS":             tlsHosts,
	"ZANSKAR_LOG_FORMAT":            oneOf("json", "text"),
	"ZANSKAR_ISSUER":                issuer,
	"ZANSKAR_AWS_GATEWAY_PRINCIPAL": awsPrincipal,
}

// presets are the only way the TLS mode changes: the mode, the listen
// address and the proxy trust move together, or the gateway would come up
// unreachable. "" takes a line out.
var presets = map[string]map[string]string{
	"managed": {"ZANSKAR_TLS_MODE": "managed", "ZANSKAR_LISTEN_ADDR": ":443", "ZANSKAR_HTTP_REDIRECT_ADDR": ":80", "ZANSKAR_TRUST_PROXY_TLS": "false"},
	"proxy":   {"ZANSKAR_TLS_MODE": "proxy", "ZANSKAR_LISTEN_ADDR": "127.0.0.1:8443", "ZANSKAR_HTTP_REDIRECT_ADDR": "", "ZANSKAR_TRUST_PROXY_TLS": "true"},
}

// Editable reports whether the console may set the variable.
func Editable(key string) bool {
	_, ok := allowed[key]
	return ok
}

// Presets lists the TLS presets by name.
func Presets() []string { return []string{"managed", "proxy"} }

// ParseRequest reads a request strictly: at most MaxRequest bytes, one JSON
// object, no field it does not know.
func ParseRequest(r io.Reader) (Request, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxRequest+1))
	if err != nil {
		return Request{}, err
	}
	if len(b) > MaxRequest {
		return Request{}, fmt.Errorf("%w: the request is over %d bytes", ErrInvalid, MaxRequest)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var req Request
	if err := dec.Decode(&req); err != nil {
		return Request{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if dec.More() {
		return Request{}, fmt.Errorf("%w: more than one JSON value", ErrInvalid)
	}
	return req, nil
}

// Changes checks a request and returns the variables to write, "" meaning
// take the line out. It refuses the whole request on any variable outside
// the allowlist, a preset's variable given on its own, or a value its
// check rejects.
func Changes(req Request) (map[string]string, error) {
	out := map[string]string{}
	if req.TLSMode != "" {
		p, ok := presets[req.TLSMode]
		if !ok {
			return nil, fmt.Errorf("%w: TLS mode must be managed or proxy", ErrInvalid)
		}
		maps.Copy(out, p)
	}
	keys := make([]string, 0, len(req.Values))
	for k := range req.Values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := strings.TrimSpace(req.Values[k])
		check, ok := allowed[k]
		if !ok {
			return nil, fmt.Errorf("%w: %s cannot be changed from the console", ErrInvalid, safeName(k))
		}
		if err := plain(v); err != nil {
			return nil, fmt.Errorf("%w: %s %v", ErrInvalid, k, err)
		}
		if v != "" {
			if err := check(v); err != nil {
				return nil, fmt.Errorf("%w: %s %v", ErrInvalid, k, err)
			}
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: nothing to change", ErrInvalid)
	}
	return out, nil
}

// safeName is a variable name fit for a message: it may come from a hostile
// request, so anything but a plain name is not repeated.
func safeName(k string) string {
	if len(k) <= 64 && regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`).MatchString(k) {
		return k
	}
	return "that variable"
}

// plain refuses what would let a value break out of its line or its quotes.
func plain(v string) error {
	if !utf8.ValidString(v) || len(v) > 1024 {
		return errors.New("must be valid UTF-8 up to 1024 bytes")
	}
	for _, r := range v {
		if r == '"' || r == '\\' || r == '`' || r == '$' || unicode.IsControl(r) {
			return errors.New(`must not contain quotes, backslashes, $, backticks or control characters`)
		}
	}
	return nil
}

func sessionCap(v string) error {
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 1000 {
		return errors.New("must be a whole number from 0 to 1000")
	}
	return nil
}

func publicURL(v string) error {
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must be an https:// address with no path, such as https://zanskar.example.com")
	}
	return nil
}

func tlsHosts(v string) error {
	parts := strings.Split(v, ",")
	if len(parts) > 32 {
		return errors.New("must name at most 32 hosts")
	}
	for _, h := range parts {
		if err := tlscert.ValidHost(strings.TrimSpace(h)); err != nil {
			return fmt.Errorf("must list host names or IP addresses, comma-separated: %v", err)
		}
	}
	return nil
}

func oneOf(choices ...string) func(string) error {
	return func(v string) error {
		if !slices.Contains(choices, v) {
			return fmt.Errorf("must be one of %s", strings.Join(choices, ", "))
		}
		return nil
	}
}

func issuer(v string) error {
	if utf8.RuneCountInString(v) > 64 {
		return errors.New("must be at most 64 characters")
	}
	for _, r := range v {
		if !unicode.IsPrint(r) {
			return errors.New("must be printable")
		}
	}
	return nil
}

var arnRe = regexp.MustCompile(`^arn:aws[a-z-]*:(iam|sts)::[0-9]{12}:(role|user|assumed-role)/[A-Za-z0-9+=,.@_/-]{1,512}$`)

func awsPrincipal(v string) error {
	if !arnRe.MatchString(v) {
		return errors.New("must be an IAM role or user ARN")
	}
	return nil
}

// Merge writes changes into an environment file's text. Each changed
// variable's line is replaced where it first appears and its later copies
// dropped; a variable set to "" is taken out; one the file lacks is added
// at the end. Every other line, comments and the master key included, is
// kept byte for byte, and no value is read out of the file.
func Merge(file []byte, changes map[string]string) []byte {
	var out bytes.Buffer
	written := map[string]bool{}
	lines := bytes.SplitAfter(file, []byte("\n"))
	for i := 0; i < len(lines); i++ {
		raw := lines[i]
		if len(raw) == 0 {
			continue
		}
		// A line continued with a trailing backslash is one entry.
		entry := raw
		for bytes.HasSuffix(bytes.TrimRight(entry, "\r\n"), []byte("\\")) && i+1 < len(lines) {
			i++
			entry = append(append([]byte{}, entry...), lines[i]...)
		}
		key := keyOf(entry)
		v, change := changes[key]
		if !change {
			out.Write(entry)
			continue
		}
		if written[key] || v == "" {
			continue
		}
		written[key] = true
		out.WriteString(line(key, v))
	}
	keys := make([]string, 0, len(changes))
	for k := range changes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if v := changes[k]; !written[k] && v != "" {
			if out.Len() > 0 && !bytes.HasSuffix(out.Bytes(), []byte("\n")) {
				out.WriteByte('\n')
			}
			out.WriteString(line(k, v))
		}
	}
	return out.Bytes()
}

// keyOf is the variable an entry sets, in lifecycle.ParseEnvFile's terms, or
// "" for a comment, a blank line or anything else.
func keyOf(entry []byte) string {
	s := strings.TrimSpace(string(entry))
	if s == "" || s[0] == '#' || s[0] == ';' {
		return ""
	}
	s = strings.TrimPrefix(s, "export ")
	k, _, ok := strings.Cut(s, "=")
	if !ok {
		return ""
	}
	return strings.TrimSpace(k)
}

// line writes one variable, quoted when the value has a space or a comment
// character; plain() has already refused anything a quote could not hold.
func line(k, v string) string {
	if strings.ContainsAny(v, " \t#;'") {
		return k + `="` + v + "\"\n"
	}
	return k + "=" + v + "\n"
}
