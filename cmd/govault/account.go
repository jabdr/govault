package main

import (
	"context"
	"fmt"

	"github.com/jabdr/govault/pkg/vault"
	"github.com/urfave/cli/v3"
)

func accountCmd() *cli.Command {
	return &cli.Command{
		Name:  "account",
		Usage: "Manage your account",
		Commands: []*cli.Command{
			{
				Name:  "change-password",
				Usage: "Change the master password",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "new-password", Required: true, Usage: "New master password"},
					&cli.IntFlag{Name: "kdf", Value: 0, Usage: "KDF algorithm (0=PBKDF2, 1=Argon2id)"},
					&cli.IntFlag{Name: "kdf-iterations", Value: 600000, Usage: "KDF iterations (PBKDF2) or Argon2 memory iterations"},
					&cli.IntFlag{Name: "kdf-memory", Value: 64, Usage: "KDF memory in MB (Argon2id only)"},
					&cli.IntFlag{Name: "kdf-parallelism", Value: 4, Usage: "KDF parallelism (Argon2id only)"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client
					password := appCtx.Password
					actionChangePassword(vClient, password, cmd.String("new-password"), int(cmd.Int("kdf")), int(cmd.Int("kdf-iterations")), int(cmd.Int("kdf-memory")), int(cmd.Int("kdf-parallelism")))
					return nil
				},
			},
			{
				Name:  "change-name",
				Usage: "Change your account name",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true, Usage: "New account name"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

					err = vClient.ChangeName(cmd.String("name"))
					if err != nil {
						return err
					}
					printOutput(MessageResult{Message: fmt.Sprintf("Name changed to: %s", cmd.String("name"))})
					return nil
				},
			},
			{
				Name:  "change-email",
				Usage: "Change your account email (use without --token to request a verification token first)",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "new-email", Required: true, Usage: "New email address"},
					&cli.StringFlag{Name: "token", Usage: "Verification token from email (omit to request a new token)"},
					&cli.IntFlag{Name: "kdf", Value: 0, Usage: "KDF algorithm (0=PBKDF2, 1=Argon2id)"},
					&cli.IntFlag{Name: "kdf-iterations", Value: 600000, Usage: "KDF iterations"},
					&cli.IntFlag{Name: "kdf-memory", Value: 64, Usage: "KDF memory in MB (Argon2id only)"},
					&cli.IntFlag{Name: "kdf-parallelism", Value: 4, Usage: "KDF parallelism (Argon2id only)"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client
					password := appCtx.Password
					newEmail := cmd.String("new-email")
					token := cmd.String("token")

					if token == "" {
						// Step 1: Request the verification token
						err := vClient.RequestEmailChange(newEmail)
						if err != nil {
							return err
						}
						printOutput(MessageResult{Message: fmt.Sprintf("Verification token sent to %s. Run this command again with --token to complete the change.", newEmail)})
						return nil
					}

					// Step 2: Perform the email change with the token
					err = vClient.ChangeEmail(newEmail, password, token, int(cmd.Int("kdf")), int(cmd.Int("kdf-iterations")), int(cmd.Int("kdf-memory")), int(cmd.Int("kdf-parallelism")))
					if err != nil {
						return err
					}
					printOutput(MessageResult{Message: fmt.Sprintf("Email changed to: %s", newEmail)})
					return nil
				},
			},
			{
				Name:  "get-api-key",
				Usage: "Get your API key",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

					clientID, secret, err := vClient.GetAPIKey()
					if err != nil {
						return err
					}
					printOutput(APIKeyResult{ClientID: clientID, ClientSecret: secret})
					return nil
				},
			},
		},
	}
}

func actionChangePassword(v *vault.Vault, currentPassword, newPassword string, kdf, kdfIter, kdfMem, kdfParal int) {
	err := v.ChangePassword(currentPassword, newPassword, kdf, kdfIter, kdfMem, kdfParal)
	exitOnErr(err)
}
