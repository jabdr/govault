package main

import (
	"context"
	"fmt"

	"github.com/jabdr/govault/pkg/vault"
	"github.com/urfave/cli/v3"
)

func registerCmd() *cli.Command {
	return &cli.Command{
		Name:  "register",
		Usage: "Self-register a new account on the server",
		Flags: []cli.Flag{
			&cli.IntFlag{Name: "kdf", Value: 0, Usage: "KDF algorithm (0=PBKDF2, 1=Argon2id)"},
			&cli.IntFlag{Name: "kdf-iterations", Value: 600000, Usage: "KDF iterations (PBKDF2) or Argon2 memory iterations"},
			&cli.IntFlag{Name: "kdf-memory", Value: 64, Usage: "KDF memory in MB (Argon2id only)"},
			&cli.IntFlag{Name: "kdf-parallelism", Value: 4, Usage: "KDF parallelism (Argon2id only)"},
		},
		Action: runRegister,
	}
}

func runRegister(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	if appCtx.Server == "" || appCtx.Email == "" || appCtx.Password == "" {
		return fmt.Errorf("server, email, and password are required")
	}
	if err := vault.Register(appCtx.Server, appCtx.Email, appCtx.Password,
		int(cmd.Int("kdf")), int(cmd.Int("kdf-iterations")),
		int(cmd.Int("kdf-memory")), int(cmd.Int("kdf-parallelism")),
		appCtx.Insecure, appCtx.Logger); err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Account %s successfully registered", appCtx.Email)})
	return nil
}

func cipherTypeName(typ int) string {
	switch typ {
	case vault.CipherTypeLogin:
		return "Login"
	case vault.CipherTypeSecureNote:
		return "Note"
	case vault.CipherTypeCard:
		return "Card"
	case vault.CipherTypeIdentity:
		return "Identity"
	case vault.CipherTypeSshKey:
		return "SshKey"
	}
	return "Unknown"
}
