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
	"github.com/albatroxxx/zanskar/internal/config"
	"github.com/albatroxxx/zanskar/internal/store"
	"github.com/albatroxxx/zanskar/internal/user"
)

// runAdmin handles `zanskar admin <create>`. It exists so the first admin can
// be created on the box, without an unauthenticated bootstrap endpoint.
func runAdmin(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: zanskar admin create --username U --name \"Display Name\" [--email E]")
	}
	switch args[0] {
	case "create":
		return runAdminCreate(args[1:])
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
