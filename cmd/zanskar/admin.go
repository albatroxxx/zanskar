// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"golang.org/x/term"

	"github.com/albatroxxx/zanskar/internal/audit"
	"github.com/albatroxxx/zanskar/internal/auth"
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

// runAdmin handles `zanskar admin <create>`. It exists so the first admin can
// be created on the box, without an unauthenticated bootstrap endpoint.
func runAdmin(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: zanskar admin create --username U --name \"Display Name\" [--email E] | zanskar admin reset-mfa --username U")
	}
	switch args[0] {
	case "create":
		return runAdminCreate(args[1:])
	case "reset-mfa":
		return runAdminResetMFA(args[1:])
	default:
		return fmt.Errorf("unknown admin subcommand %q", args[0])
	}
}

func runAdminCreate(args []string) error {
	fs := flag.NewFlagSet("admin create", flag.ContinueOnError)
	username := fs.String("username", "", "login name")
	name := fs.String("name", "", "display name")
	email := fs.String("email", "", "email address (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" || *name == "" {
		return errors.New("--username and --name are required")
	}

	password, err := readPassword()
	if err != nil {
		return err
	}
	if err := user.CheckPasswordPolicy(password); err != nil {
		return err
	}
	hash, err := user.HashPassword(password)
	if err != nil {
		return err
	}

	cfg, err := config.Load(config.Options{})
	if err != nil {
		return err
	}
	ctx := context.Background()
	db, err := store.Open(ctx, cfg.DBDriver, cfg.DBDSN)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	if pending, err := store.Pending(ctx, db); err != nil {
		return err
	} else if len(pending) > 0 {
		return fmt.Errorf("%d migration(s) pending; run `zanskar migrate` first", len(pending))
	}

	u := &user.User{
		Username:     *username,
		DisplayName:  *name,
		Email:        *email,
		Roles:        []user.Role{user.RoleAdmin, user.RoleUser},
		PasswordHash: hash,
	}
	if err := user.NewRepo(db).Create(ctx, u); err != nil {
		return err
	}
	_, err = audit.NewLog(db).Record(ctx, audit.Actor{IP: "cli"}.Event("user.create", "user", u.ID, audit.Success,
		map[string]any{"username": u.Username, "roles": u.Roles, "via": "zanskar admin create"}))
	if err != nil {
		return fmt.Errorf("user created but audit record failed: %w", err)
	}
	fmt.Printf("created admin %q (id %s)\n", u.Username, u.ID)
	return nil
}

// readPassword takes ZANSKAR_ADMIN_PASSWORD when set (for provisioning
// scripts), otherwise prompts twice on the terminal without echo.
func readPassword() (string, error) {
	if pw := os.Getenv("ZANSKAR_ADMIN_PASSWORD"); pw != "" {
		return pw, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("no terminal: set ZANSKAR_ADMIN_PASSWORD to provide the password")
	}
	fmt.Fprint(os.Stderr, "Password: ")
	first, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "Confirm password: ")
	second, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(first) != string(second) {
		return "", errors.New("passwords do not match")
	}
	return string(first), nil
}

// runAdminResetMFA removes a user's authenticator and recovery codes and
// revokes their sessions, so the next login re-enrolls. It exists for the
// lost-authenticator case of the only admin, who cannot reach the admin API
// without a second factor. It requires shell access to the gateway host,
// which is the trust boundary here, and it is audited.
func runAdminResetMFA(args []string) error {
	fs := flag.NewFlagSet("admin reset-mfa", flag.ContinueOnError)
	username := fs.String("username", "", "login name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" {
		return errors.New("--username is required")
	}
	cfg, err := config.Load(config.Options{})
	if err != nil {
		return err
	}
	ctx := context.Background()
	db, err := store.Open(ctx, cfg.DBDriver, cfg.DBDSN)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	users := user.NewRepo(db)
	u, err := users.GetByUsername(ctx, *username)
	if err != nil {
		return err
	}
	if err := auth.NewTOTP(db, nil, cfg.Issuer).Reset(ctx, u.ID); err != nil {
		return fmt.Errorf("reset authenticator: %w", err)
	}
	revoked, err := auth.NewSessions(db, nil, false).RevokeAllForUser(ctx, u.ID)
	if err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}
	if _, err := audit.NewLog(db).Record(ctx, audit.Actor{IP: "cli"}.Event("user.mfa.reset", "user", u.ID, audit.Success,
		map[string]any{"username": u.Username, "sessions_revoked": revoked, "via": "zanskar admin reset-mfa"})); err != nil {
		return fmt.Errorf("authenticator reset but audit record failed: %w", err)
	}
	fmt.Printf("authenticator reset for %q; %d session(s) revoked; the next login will enroll a new one\n", u.Username, revoked)
	return nil
}
