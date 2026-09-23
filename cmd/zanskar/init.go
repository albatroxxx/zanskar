// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// runInit handles `zanskar init`: it gathers configuration and writes the
// environment file the server reads (ADR 0014). It does not apply migrations or
// create the admin; it prints those as the next steps.
func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	out := fs.String("out", "/etc/zanskar/env", "path of the environment file to write")
	force := fs.Bool("force", false, "overwrite an existing env file (an existing master key is always preserved)")
	stdout := fs.Bool("print", false, "write the env file to stdout instead of --out")
	nonInteractive := fs.Bool("non-interactive", false, "never prompt; take values from flags and defaults")
	listen := fs.String("listen", "", "listen address (default 127.0.0.1:8443)")
	behindProxy := fs.Bool("behind-proxy", false, "a TLS proxy terminates in front on loopback (no cert needed)")
	tlsCert := fs.String("tls-cert", "", "path to the TLS certificate (own-certificate mode)")
	tlsKey := fs.String("tls-key", "", "path to the TLS private key (own-certificate mode)")
	dataDir := fs.String("data-dir", "", "directory for the database and recordings (default /var/lib/zanskar)")
	guacd := fs.String("guacd", "", "guacd host:port to enable RDP and VNC (empty disables desktop access)")
	issuer := fs.String("issuer", "", "name shown in authenticator apps (default Zanskar)")
	logLevel := fs.String("log-level", "", "log level: debug|info|warn|error (default info)")
	logFormat := fs.String("log-format", "", "log format: json|text (default json)")
	noMFA := fs.Bool("no-mfa", false, "allow password-only login (throwaway installs only)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Preserve an existing master key: writing a fresh one would make every
	// stored credential undecryptable (ADR 0014).
	existingKey := ""
	if info, err := os.Stat(*out); err == nil && !info.IsDir() {
		if !*force && !*stdout {
			return fmt.Errorf("%s already exists; re-run with --force to overwrite (its master key is preserved either way)", *out)
		}
		existingKey = masterKeyFrom(*out)
	}

	a := defaultAnswers()
	if existingKey != "" {
		a.MasterKey = existingKey
	}
	// Flags override defaults; interactive mode fills the rest by prompting.
	if *listen != "" {
		a.ListenAddr = *listen
	}
	if *behindProxy {
		a.TLSMode = tlsModeProxy
	}
	if *tlsCert != "" || *tlsKey != "" {
		a.TLSMode = tlsModeCert
		a.TLSCert, a.TLSKey = *tlsCert, *tlsKey
	}
	if *dataDir != "" {
		a.DataDir = *dataDir
	}
	if *guacd != "" {
		a.GuacdAddr = *guacd
	}
	if *issuer != "" {
		a.Issuer = *issuer
	}
	if *logLevel != "" {
		a.LogLevel = *logLevel
	}
	if *logFormat != "" {
		a.LogFormat = *logFormat
	}
	if *noMFA {
		a.RequireMFA = false
	}

	interactive := !*nonInteractive && !*stdout && isTerminal()
	if interactive {
		if err := promptAnswers(&a); err != nil {
			return err
		}
	}

	if a.MasterKey == "" {
		key, err := newMasterKey()
		if err != nil {
			return err
		}
		a.MasterKey = key
	}

	if err := validateAnswers(a); err != nil {
		return err
	}
	for _, w := range checkPrereqs(a) {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}

	content := renderEnv(a)
	if *stdout {
		fmt.Print(content)
		return nil
	}
	if err := writeFileAtomic(*out, []byte(content), 0o600); err != nil {
		return err
	}
	printNextSteps(a, *out, existingKey == "")
	return nil
}

// tls modes
const (
	tlsModeCert  = "cert"
	tlsModeProxy = "proxy"
)

// initAnswers is the full set of inputs the env file is built from.
type initAnswers struct {
	ListenAddr string
	TLSMode    string // cert | proxy
	TLSCert    string
	TLSKey     string
	RequireMFA bool
	GuacdAddr  string // empty disables desktop access
	DataDir    string
	Issuer     string
	LogLevel   string
	LogFormat  string
	MasterKey  string // base64, 32 bytes
}

func defaultAnswers() initAnswers {
	return initAnswers{
		ListenAddr: "127.0.0.1:8443",
		TLSMode:    tlsModeProxy,
		RequireMFA: true,
		DataDir:    "/var/lib/zanskar",
		Issuer:     "Zanskar",
		LogLevel:   "info",
		LogFormat:  "json",
	}
}

var (
	logLevels  = map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	logFormats = map[string]bool{"json": true, "text": true}
	hostPortRe = regexp.MustCompile(`^.+:\d+$`)
)

// validateAnswers rejects inputs that would produce an env file the server
// refuses, so a bad choice fails here rather than at first start.
func validateAnswers(a initAnswers) error {
	if !hostPortRe.MatchString(a.ListenAddr) {
		return fmt.Errorf("listen address %q must be host:port", a.ListenAddr)
	}
	switch a.TLSMode {
	case tlsModeCert:
		if a.TLSCert == "" || a.TLSKey == "" {
			return errors.New("own-certificate mode needs both --tls-cert and --tls-key")
		}
	case tlsModeProxy:
		// A loopback bind is what makes plain HTTP acceptable behind a proxy;
		// refuse a non-loopback bind with no certificate, matching the server.
		if !isLoopbackAddr(a.ListenAddr) {
			return errors.New("behind-proxy mode must bind to loopback (e.g. 127.0.0.1:8443); use own-certificate mode to bind a public address")
		}
	default:
		return fmt.Errorf("unknown TLS mode %q", a.TLSMode)
	}
	if a.DataDir == "" || !filepath.IsAbs(a.DataDir) {
		return fmt.Errorf("data directory %q must be an absolute path", a.DataDir)
	}
	if !logLevels[a.LogLevel] {
		return fmt.Errorf("log level %q must be one of debug, info, warn, error", a.LogLevel)
	}
	if !logFormats[a.LogFormat] {
		return fmt.Errorf("log format %q must be json or text", a.LogFormat)
	}
	if _, err := base64.StdEncoding.DecodeString(a.MasterKey); err != nil || len(a.MasterKey) == 0 {
		return errors.New("master key is missing or not valid base64")
	}
	return nil
}

// checkPrereqs returns non-fatal warnings for conditions that will bite at
// runtime: an unwritable data directory, an unreachable guacd, or TLS files
// that do not load.
func checkPrereqs(a initAnswers) []string {
	var w []string
	if err := os.MkdirAll(a.DataDir, 0o700); err != nil {
		w = append(w, fmt.Sprintf("data directory %s is not creatable: %v", a.DataDir, err))
	}
	if a.GuacdAddr != "" {
		d := net.Dialer{Timeout: 3 * time.Second}
		c, err := d.DialContext(context.Background(), "tcp", a.GuacdAddr)
		if err != nil {
			w = append(w, fmt.Sprintf("guacd at %s is not reachable now (%v); RDP and VNC will fail until it is", a.GuacdAddr, err))
		} else {
			_ = c.Close()
		}
	}
	if a.TLSMode == tlsModeCert {
		if _, err := tls.LoadX509KeyPair(a.TLSCert, a.TLSKey); err != nil {
			w = append(w, fmt.Sprintf("TLS certificate and key do not load: %v", err))
		}
	}
	return w
}

// renderEnv produces the environment file. Only valid variable combinations are
// emitted for the chosen TLS mode.
func renderEnv(a initAnswers) string {
	var b strings.Builder
	p := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	p("# Zanskar configuration, written by `zanskar init`.\n")
	p("# The server reads these variables from the environment (ADR 0014); this\n")
	p("# file is loaded by the systemd unit. Mode 0600: it holds the master key.\n\n")

	p("ZANSKAR_LISTEN_ADDR=%s\n", a.ListenAddr)
	switch a.TLSMode {
	case tlsModeCert:
		p("# TLS terminates in Zanskar.\n")
		p("ZANSKAR_TLS_CERT=%s\n", a.TLSCert)
		p("ZANSKAR_TLS_KEY=%s\n", a.TLSKey)
	case tlsModeProxy:
		p("# A TLS proxy terminates in front on loopback; cookies stay Secure and\n")
		p("# the real client address is read from the proxy.\n")
		p("ZANSKAR_TRUST_PROXY_TLS=true\n")
		p("ZANSKAR_TRUSTED_PROXIES=127.0.0.1/32,::1/128\n")
	}
	p("\n")

	p("ZANSKAR_DB_DRIVER=sqlite\n")
	// Quote the DSN: it contains &, ( and ), which a shell sourcing this file
	// would otherwise mangle. systemd's EnvironmentFile strips the quotes, so
	// both consumers see the same literal value.
	p("ZANSKAR_DB_DSN=\"file:%s?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)\"\n",
		filepath.Join(a.DataDir, "zanskar.db"))
	p("ZANSKAR_RECORDINGS_DIR=%s\n\n", filepath.Join(a.DataDir, "recordings"))

	if a.GuacdAddr != "" {
		p("# RDP and VNC through guacd.\n")
		p("ZANSKAR_GUACD_ADDR=%s\n\n", a.GuacdAddr)
	} else {
		p("# Desktop access (RDP/VNC) is disabled; set ZANSKAR_GUACD_ADDR to enable it.\n\n")
	}

	p("ZANSKAR_REQUIRE_MFA=%t\n", a.RequireMFA)
	p("ZANSKAR_ISSUER=%s\n", a.Issuer)
	p("ZANSKAR_LOG_LEVEL=%s\n", a.LogLevel)
	p("ZANSKAR_LOG_FORMAT=%s\n\n", a.LogFormat)

	p("# Sealing key for all stored secrets. Back it up: losing it makes every\n")
	p("# stored credential unrecoverable. Never change it on an existing install.\n")
	p("ZANSKAR_MASTER_KEY=%s\n", a.MasterKey)
	return b.String()
}

// ---- helpers

func newMasterKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// masterKeyFrom extracts an existing ZANSKAR_MASTER_KEY from an env file, or ""
// if none. Best-effort: a read error means "no key found", and the caller then
// generates one.
func masterKeyFrom(path string) string {
	f, err := os.Open(path) // #nosec G304 -- path is the operator-specified env file being (re)written; reading it back preserves the master key
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if v, ok := strings.CutPrefix(line, "ZANSKAR_MASTER_KEY="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// writeFileAtomic writes via a temp file in the same directory then renames, so
// a crash never leaves a half-written env file (which could lose the key line).
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".zanskar-env-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func printNextSteps(a initAnswers, out string, freshKey bool) {
	fmt.Printf("\nWrote %s (mode 0600).\n\n", out)
	if freshKey {
		fmt.Println("A new master key was generated. Back up this file now — losing the")
		fmt.Println("master key makes every stored credential unrecoverable.")
		fmt.Println()
	}
	// The migrate and admin-create commands write the database. When a dedicated
	// service user owns the data directory (the package install), they must run
	// as that user, or the SQLite files end up root-owned and the service cannot
	// write them. Wrap those commands in runuser when that is the case.
	svcUser, useRunuser := dataDirServiceUser(a.DataDir)
	pfx := ""
	fmt.Println("Next steps (load the env, then run each command):")
	fmt.Printf("     set -a; . %s; set +a\n", out)
	if useRunuser {
		pfx = "runuser -u " + svcUser + " -- "
		fmt.Printf("  (run the database commands as %q, which owns %s, so it owns the files)\n", svcUser, a.DataDir)
	}
	fmt.Printf("  1. Apply migrations:   %szanskar migrate   (or let the unit's ExecStartPre do it)\n", pfx)
	fmt.Printf("  2. Create the admin:   ZANSKAR_ADMIN_PASSWORD=... %szanskar admin create --username admin --name \"Your Name\"\n", pfx)
	fmt.Println("  3. Start the service:  sudo systemctl enable --now zanskar")
	fmt.Println()
	fmt.Println("Log destinations: application logs go to the service's stderr (journald under")
	fmt.Println("systemd); the audit log lives in the database and is exported via SIEM, not a")
	fmt.Printf("file; session recordings are written under %s.\n", filepath.Join(a.DataDir, "recordings"))
}

// dataDirServiceUser reports the username that owns dir when init runs as root
// and that owner is a different, non-root user — the packaged-install case,
// where the database-writing commands must run as that service user or the
// SQLite files end up root-owned and the service cannot write them. It returns
// ("", false) for a manual install (not root, or the owner is the current
// user), where those commands run as-is.
func dataDirServiceUser(dir string) (string, bool) {
	if os.Geteuid() != 0 {
		return "", false
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return "", false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 {
		return "", false
	}
	u, err := user.LookupId(fmt.Sprintf("%d", st.Uid))
	if err != nil {
		return "", false
	}
	return u.Username, true
}

// promptAnswers fills a by asking on the terminal, showing current values as
// defaults. Kept thin: all validation and rendering happen on the result.
func promptAnswers(a *initAnswers) error {
	r := bufio.NewReader(os.Stdin)
	fmt.Println("Configuring Zanskar. Press Enter to accept the [default].")
	fmt.Println()

	a.ListenAddr = ask(r, "Listen address", a.ListenAddr)
	fmt.Println("TLS: [1] Zanskar terminates TLS (needs a cert)   [2] behind a TLS proxy on loopback")
	if askBool(r, "Terminate TLS in Zanskar?", a.TLSMode == tlsModeCert) {
		a.TLSMode = tlsModeCert
		a.TLSCert = ask(r, "  TLS certificate path", a.TLSCert)
		a.TLSKey = ask(r, "  TLS private key path", a.TLSKey)
	} else {
		a.TLSMode = tlsModeProxy
		if !isLoopbackAddr(a.ListenAddr) {
			a.ListenAddr = "127.0.0.1:8443"
			fmt.Printf("  (bind set to %s for proxy mode)\n", a.ListenAddr)
		}
	}
	a.DataDir = ask(r, "Data directory (database + recordings)", a.DataDir)
	if askBool(r, "Enable desktop access (RDP/VNC via guacd)?", a.GuacdAddr != "") {
		def := a.GuacdAddr
		if def == "" {
			def = "127.0.0.1:4822"
		}
		a.GuacdAddr = ask(r, "  guacd address", def)
	} else {
		a.GuacdAddr = ""
	}
	a.RequireMFA = askBool(r, "Require MFA (TOTP)?", a.RequireMFA)
	a.Issuer = ask(r, "Authenticator issuer name", a.Issuer)
	a.LogLevel = ask(r, "Log level (debug|info|warn|error)", a.LogLevel)
	a.LogFormat = ask(r, "Log format (json|text)", a.LogFormat)
	return nil
}

func ask(r *bufio.Reader, label, def string) string {
	fmt.Printf("%s [%s]: ", label, def)
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func askBool(r *bufio.Reader, label string, def bool) bool {
	d := "y/N"
	if def {
		d = "Y/n"
	}
	fmt.Printf("%s [%s]: ", label, d)
	line, _ := r.ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	if line == "" {
		return def
	}
	return line == "y" || line == "yes"
}
