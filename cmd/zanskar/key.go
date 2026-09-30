// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/crypto"
	"github.com/albatroxxx/zanskar/internal/keyring"
	"github.com/albatroxxx/zanskar/internal/store"
)

// runKey dispatches `zanskar key <status|rotate|rotate-master>`.
//
// The master key wraps the data keys in key_versions; secrets are sealed
// under data keys (ADR 0007). So "rotate-master" rewraps a few small rows and
// leaves every secret's ciphertext alone, and "rotate" starts a fresh data
// key for whatever is sealed from now on. Neither touches secrets already
// stored; a leak of the database itself is remedied only by rotating the
// secrets at their targets.
func runKey(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: zanskar key <status|rotate|rotate-master>")
	}
	switch args[0] {
	case "status":
		return runKeyStatus()
	case "rotate":
		return runKeyRotate()
	case "rotate-master":
		return runKeyRotateMaster(args[1:])
	default:
		return fmt.Errorf("unknown key subcommand %q (status, rotate, rotate-master)", args[0])
	}
}

// openRing opens the database and the key ring with the configured master
// key, the way serve does but without the server.
func openRing(ctx context.Context) (*config.Config, *store.DB, *keyring.Ring, error) {
	cfg, err := config.Load(config.Options{RequireMasterKey: true})
	if err != nil {
		return nil, nil, nil, err
	}
	db, err := store.Open(ctx, cfg.DBDriver, cfg.DBDSN)
	if err != nil {
		return nil, nil, nil, err
	}
	kek, err := crypto.NewLocalKEK(cfg.MasterKey)
	if err != nil {
		_ = db.Close()
		return nil, nil, nil, err
	}
	ring, err := keyring.Open(ctx, db, kek)
	if err != nil {
		_ = db.Close()
		return nil, nil, nil, fmt.Errorf("key ring: %w", err)
	}
	return cfg, db, ring, nil
}

// sealedTables lists every table that stores ciphertext under a data key,
// with the column that says whether a row holds any. status counts rows per
// key version so an operator can see what an old version still protects.
var sealedTables = []struct{ table, has string }{
	{"credentials", "secret_enc IS NOT NULL"},
	{"identity_providers", "config_enc IS NOT NULL"},
	{"mfa_totp", "secret_enc IS NOT NULL"},
}

func runKeyStatus() error {
	ctx := context.Background()
	_, db, ring, err := openRing(ctx)
	if err != nil {
		return err
	}
	defer func() { ring.Close(); _ = db.Close() }()

	rows, err := db.QueryContext(ctx, `SELECT id, kek_source, created_at, rotated_at, retired_at FROM key_versions ORDER BY id`)
	if err != nil {
		return err
	}
	type version struct{ id, source, created, rotated, retired string }
	var versions []version
	for rows.Next() {
		var v version
		var rotated, retired store.NullTime
		if err := rows.Scan(&v.id, &v.source, &v.created, &rotated, &retired); err != nil {
			_ = rows.Close()
			return err
		}
		if rotated.Valid {
			v.rotated = rotated.Time.UTC().Format("2006-01-02 15:04")
		}
		if retired.Valid {
			v.retired = retired.Time.UTC().Format("2006-01-02 15:04")
		}
		versions = append(versions, v)
	}
	_ = rows.Close() // SQLite: one connection; the counts below need it
	fmt.Printf("active data-key version: %d\n\n", ring.ActiveVersion())
	fmt.Println("version  wrapped-by  created           rotated           retired")
	for _, v := range versions {
		fmt.Printf("%-8s %-11s %-17s %-17s %s\n", v.id, v.source, firstN(v.created, 16), orDash(v.rotated), orDash(v.retired))
	}
	fmt.Println()
	fmt.Println("sealed rows per version:")
	for _, st := range sealedTables {
		// Table and column names come from the static list above, not input.
		q := fmt.Sprintf(`SELECT key_version, COUNT(*) FROM %s WHERE %s GROUP BY key_version ORDER BY key_version`, st.table, st.has) // #nosec G201
		crow, err := db.QueryContext(ctx, q)
		if err != nil {
			return err
		}
		var parts []string
		for crow.Next() {
			var ver, n int
			if err := crow.Scan(&ver, &n); err != nil {
				_ = crow.Close()
				return err
			}
			parts = append(parts, fmt.Sprintf("v%d: %d", ver, n))
		}
		_ = crow.Close()
		if len(parts) == 0 {
			parts = []string{"none"}
		}
		fmt.Printf("  %-20s %s\n", st.table, strings.Join(parts, ", "))
	}
	return nil
}

func runKeyRotate() error {
	ctx := context.Background()
	_, db, ring, err := openRing(ctx)
	if err != nil {
		return err
	}
	defer func() { ring.Close(); _ = db.Close() }()
	ver, err := ring.Rotate(ctx)
	if err != nil {
		return err
	}
	if _, err := audit.NewLog(db).Record(ctx, audit.Actor{IP: "cli"}.Event("key.rotate", "key_version", fmt.Sprint(ver), audit.Success,
		map[string]any{"active_version": ver})); err != nil {
		return fmt.Errorf("rotated to version %d but the audit event failed: %w", ver, err)
	}
	fmt.Printf("data-key version %d is now active; secrets stored from now on are sealed under it.\n", ver)
	fmt.Println("Secrets stored earlier stay under their version until they are rotated or re-entered;")
	fmt.Println("`zanskar key status` shows how many each version still protects. Restart the service so it")
	fmt.Println("picks up the new version.")
	return nil
}

func runKeyRotateMaster(args []string) error {
	fs := flag.NewFlagSet("key rotate-master", flag.ContinueOnError)
	envFile := fs.String("env-file", "", "environment file whose ZANSKAR_MASTER_KEY line is replaced after the rewrap (the one the service loads)")
	keyFile := fs.String("key-file", "", "master key file replaced after the rewrap; defaults to ZANSKAR_MASTER_KEY_FILE when the key is loaded from one")
	generate := fs.Bool("generate", false, "generate the new key instead of reading it; with -env-file or -key-file it is written there and never shown")
	yes := fs.Bool("yes", false, "proceed without the confirmation prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx := context.Background()
	cfg, db, ring, err := openRing(ctx)
	if err != nil {
		return err
	}
	defer func() { ring.Close(); _ = db.Close() }()

	// A key loaded from a file is replaced in that file: it is the one the
	// service reads, and an env-file edit would leave the file holding a key
	// that opens nothing.
	if cfg.MasterKeyFile != "" {
		if *envFile != "" {
			return fmt.Errorf("the master key is read from %s (ZANSKAR_MASTER_KEY_FILE); drop -env-file", cfg.MasterKeyFile)
		}
		if *keyFile == "" {
			*keyFile = cfg.MasterKeyFile
		}
	}
	if *envFile != "" && *keyFile != "" {
		return errors.New("pass -env-file or -key-file, not both")
	}
	if *keyFile != "" {
		b, err := os.ReadFile(*keyFile) // #nosec G304 -- the operator names the key file
		if err != nil {
			return err
		}
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b))); err != nil || !bytes.Equal(raw, cfg.MasterKey) {
			return fmt.Errorf("%s holds a different master key than the one this command runs with; pass the file the service actually loads", *keyFile)
		}
	}

	// The env file must be the one this process runs with, or the service
	// would be left with a key that opens nothing.
	if *envFile != "" {
		current := masterKeyFrom(*envFile)
		if current == "" {
			return fmt.Errorf("%s has no ZANSKAR_MASTER_KEY line", *envFile)
		}
		if raw, err := base64.StdEncoding.DecodeString(current); err != nil || !bytes.Equal(raw, cfg.MasterKey) {
			return fmt.Errorf("%s holds a different master key than the one this command runs with; pass the file the service actually loads", *envFile)
		}
	}

	// Prove the file can be replaced before anything is rewrapped: failing
	// afterwards would leave the database under a key that exists nowhere.
	for _, f := range []string{*keyFile, *envFile} {
		if f == "" {
			continue
		}
		if err := checkReplaceable(f); err != nil {
			return fmt.Errorf("%w (nothing was changed; run as a user that can write %s, usually root)", err, filepath.Dir(f))
		}
	}

	newB64, err := newMasterKeyInput(*generate)
	if err != nil {
		return err
	}
	newKey, err := base64.StdEncoding.DecodeString(newB64)
	if err != nil || len(newKey) != 32 {
		return errors.New("the new master key must be 32 bytes, base64-encoded (zanskar keygen makes one)")
	}
	defer crypto.Zero(newKey)
	newKEK, err := crypto.NewLocalKEK(newKey)
	if err != nil {
		return err
	}

	if !*yes {
		fmt.Fprintln(os.Stderr, "This rewraps every data key under the new master key in one transaction. Afterwards the")
		fmt.Fprintln(os.Stderr, "service must be restarted with the new key, or it refuses to start (\"cannot unwrap key")
		fmt.Fprintln(os.Stderr, "version\"). Open browser tabs will need a reload and sign-ins in progress restart; user")
		fmt.Fprintln(os.Stderr, "sessions survive. Re-run with -yes to proceed.")
		return errors.New("refusing to rotate without -yes")
	}

	n, err := ring.Rewrap(ctx, newKEK)
	if err != nil {
		return fmt.Errorf("%w (nothing was changed)", err)
	}
	if _, err := audit.NewLog(db).Record(ctx, audit.Actor{IP: "cli"}.Event("key.rotate_master", "key_versions", "all", audit.Success,
		map[string]any{"versions_rewrapped": n, "env_file_updated": *envFile != "", "key_file_updated": *keyFile != ""})); err != nil {
		fmt.Fprintln(os.Stderr, "warning: the rewrap succeeded but the audit event could not be written:", err)
	}
	fmt.Printf("rewrapped %d data-key version(s) under the new master key.\n", n)

	switch {
	case *keyFile != "":
		if err := replaceKeyFile(*keyFile, newB64); err != nil {
			fmt.Fprintln(os.Stderr, "The database is already under the new key, which is not stored anywhere yet. Put it")
			fmt.Fprintln(os.Stderr, "in the key file the service loads before restarting it:")
			fmt.Fprintln(os.Stderr, newB64)
			return fmt.Errorf("updating %s: %w", *keyFile, err)
		}
		fmt.Printf("updated the master key in %s.\n", *keyFile)
	case *envFile != "":
		if err := replaceEnvMasterKey(*envFile, newB64); err != nil {
			fmt.Fprintln(os.Stderr, "The database is already under the new key, which is not stored anywhere yet. Set")
			fmt.Fprintln(os.Stderr, "ZANSKAR_MASTER_KEY to it in the environment the service loads before restarting:")
			fmt.Fprintln(os.Stderr, newB64)
			return fmt.Errorf("updating %s: %w", *envFile, err)
		}
		fmt.Printf("updated ZANSKAR_MASTER_KEY in %s.\n", *envFile)
	case *generate:
		fmt.Println("new master key (put it in the service's environment now; it is not stored anywhere else):")
		fmt.Println(newB64)
	default:
		fmt.Println("put the new key in the service's environment as ZANSKAR_MASTER_KEY.")
	}
	fmt.Println()
	fmt.Println("Next: restart the service (sudo systemctl restart zanskar). The old key now opens nothing")
	fmt.Println("in this database; escrow the new one where the database backup cannot reach. If the")
	fmt.Println("database itself may have leaked alongside the old key, the stored secrets were exposed:")
	fmt.Println("rotate them at their targets; no re-encryption undoes that.")
	return nil
}

// newMasterKeyInput takes ZANSKAR_NEW_MASTER_KEY when set (for scripts),
// generates one when asked, and otherwise prompts twice without echo, so the
// key never has to be typed on a command line.
func newMasterKeyInput(generate bool) (string, error) {
	if v := strings.TrimSpace(os.Getenv("ZANSKAR_NEW_MASTER_KEY")); v != "" {
		return v, nil
	}
	if generate {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(key), nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("no terminal: set ZANSKAR_NEW_MASTER_KEY or pass -generate")
	}
	fmt.Fprint(os.Stderr, "New master key (base64): ")
	first, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "Confirm: ")
	second, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(first, second) {
		return "", errors.New("keys do not match")
	}
	return strings.TrimSpace(string(first)), nil
}

// replaceEnvMasterKey rewrites the ZANSKAR_MASTER_KEY line of an env file in
// place, keeping every other line and the file's mode, through the same
// atomic write init uses so a crash never loses the key line.
func replaceEnvMasterKey(path, newB64 string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	f, err := os.Open(path) // #nosec G304 -- the operator names the env file to update
	if err != nil {
		return err
	}
	var out []string
	replaced := false
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "ZANSKAR_MASTER_KEY=") {
			line = "ZANSKAR_MASTER_KEY=" + newB64
			replaced = true
		}
		out = append(out, line)
	}
	_ = f.Close()
	if err := s.Err(); err != nil {
		return err
	}
	if !replaced {
		return errors.New("no ZANSKAR_MASTER_KEY line found")
	}
	return writeFileAtomic(path, []byte(strings.Join(out, "\n")+"\n"), info.Mode().Perm())
}

// checkReplaceable proves a file can be replaced the way writeFileAtomic
// replaces it: a temporary file created and removed in its directory.
func checkReplaceable(path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".zanskar-check-*")
	if err != nil {
		return fmt.Errorf("cannot replace %s: %w", path, err)
	}
	name := tmp.Name()
	_ = tmp.Close()
	return os.Remove(name)
}

// replaceKeyFile swaps a master key file's contents for the new key through
// the same atomic write the env file uses, keeping its owner and mode, so the
// service user can still read it and nobody else can.
func replaceKeyFile(path, newB64 string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, []byte(newB64+"\n"), info.Mode().Perm())
}

func firstN(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
