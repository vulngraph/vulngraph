package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"github.com/vulngraph/vulngraph/internal/app/audit"
	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/db"
)

// userCmd handles `graph user create|totp|token`.
func userCmd(ctx context.Context, args []string, getenv func(string) string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: graph user <create|totp|token>")
	}

	// A short-lived CLI command never overlaps with the long-running pods'
	// steady-state pool usage, but it still needs to fit inside whatever
	// headroom is free at the moment it runs — small and safe either way.
	pool, err := db.NewPool(ctx, pgDSN(getenv), 5)
	if err != nil {
		return fmt.Errorf("user: %w", err)
	}
	defer pool.Close()
	cipher, err := newCipher(getenv)
	if err != nil {
		return fmt.Errorf("user: %w", err)
	}
	// Every user command is an audited admin action, so it needs ClickHouse
	// as well. It is checked up front; a write that fails after the change
	// logs AUDIT WRITE FAILED and the change stands.
	ch, err := db.NewCH(ctx, chDSN(getenv), 1)
	if err != nil {
		return fmt.Errorf("user: audit trail: %w", err)
	}
	defer func() { _ = ch.Close() }()
	svc := auth.NewService(auth.NewPGRepo(pool, cipher)).
		WithAudit(audit.NewService(audit.NewCHRepo(ch)).WithFallbackActor(audit.ActorCLI))

	switch args[0] {
	case "create":
		return userCreate(ctx, svc, args[1:])
	case "totp":
		return userTOTP(ctx, svc, args[1:])
	case "token":
		return userToken(ctx, svc, args[1:])
	default:
		return fmt.Errorf("unknown user command %q (usage: graph user <create|totp|token>)", args[0])
	}
}

func userCreate(ctx context.Context, svc *auth.Service, args []string) error {
	fs := flag.NewFlagSet("user create", flag.ContinueOnError)
	email := fs.String("email", "", "user email (required)")
	role := fs.String("role", "viewer", "role: admin, analyst, or viewer")
	password := fs.String("password", "", "password (generated when omitted; prefer that, since a password passed here is exposed to shell history and process listings)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" {
		return fmt.Errorf("user create: --email is required")
	}

	pw := *password
	generated := pw == ""
	if generated {
		var err error
		if pw, err = generatePassword(); err != nil {
			return fmt.Errorf("user create: %w", err)
		}
	}

	user, err := svc.CreateUser(ctx, *email, pw, auth.Role(*role))
	if err != nil {
		return fmt.Errorf("user create: %w", err)
	}

	_, _ = fmt.Fprintf(os.Stdout, "created %s (%s)\n", user.Email, user.Role)
	if generated {
		_, _ = fmt.Fprintf(os.Stdout, "password: %s\n", pw)
	}
	return nil
}

// userToken mints a session token for an existing user and prints it, with no
// password or TOTP step. The token is a full session for that user (7 days,
// the user's role), not an API key: Vulngraph cannot tell it from the person
// signing in, so for ADR 087 it counts as a person. It runs non-destructive
// executor actions with no grant, mints two-person grants and manages users
// and keys, all of which an API key is refused. Use it for bootstrap (connector
// registration needs an admin) and hand it only to tooling you would let act
// as that person; give agents and standing CI jobs an API key. End it with
// POST /api/users/{id}/revoke-sessions.
func userToken(ctx context.Context, svc *auth.Service, args []string) error {
	fs := flag.NewFlagSet("user token", flag.ContinueOnError)
	email := fs.String("email", "", "user email (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" {
		return fmt.Errorf("user token: --email is required")
	}

	token, err := svc.IssueToken(ctx, *email)
	if err != nil {
		return fmt.Errorf("user token: %w", err)
	}
	_, _ = fmt.Fprintln(os.Stdout, token)
	return nil
}

func userTOTP(ctx context.Context, svc *auth.Service, args []string) error {
	fs := flag.NewFlagSet("user totp", flag.ContinueOnError)
	email := fs.String("email", "", "user email (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" {
		return fmt.Errorf("user totp: --email is required")
	}

	url, err := svc.EnrollTOTP(ctx, *email)
	if err != nil {
		return fmt.Errorf("user totp: %w", err)
	}
	_, _ = fmt.Fprintln(os.Stdout, url)
	return nil
}

func generatePassword() (string, error) {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
