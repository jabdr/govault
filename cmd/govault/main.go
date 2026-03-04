// Command govault is a CLI tool for interacting with Bitwarden/Vaultwarden.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/jabdr/govault/pkg/vault"
	"github.com/urfave/cli/v3"
)

func main() {
	cmd := &cli.Command{
		Name:  "govault",
		Usage: "A CLI tool for interacting with Bitwarden/Vaultwarden.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "server",
				Usage:   "Vaultwarden/Bitwarden server URL",
				Sources: cli.EnvVars("GOVAULT_SERVER"),
			},
			&cli.StringFlag{
				Name:    "email",
				Usage:   "Account email",
				Sources: cli.EnvVars("GOVAULT_EMAIL"),
			},
			&cli.StringFlag{
				Name:    "password",
				Usage:   "Master password",
				Sources: cli.EnvVars("GOVAULT_PASSWORD"),
			},
			&cli.StringFlag{
				Name:    "client-id",
				Usage:   "API Client ID",
				Sources: cli.EnvVars("GOVAULT_CLIENT_ID"),
			},
			&cli.StringFlag{
				Name:    "client-secret",
				Usage:   "API Client Secret",
				Sources: cli.EnvVars("GOVAULT_CLIENT_SECRET"),
			},
			&cli.BoolFlag{
				Name:  "insecure-skip-verify",
				Usage: "Skip TLS verification",
			},
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				Usage:   "Enable verbose logging",
			},
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "Output format: text, json, yaml",
				Value:   "text",
			},
		},
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			outputFormat = cmd.String("output")
			verbose := cmd.Bool("verbose")

			var logHandler slog.Handler
			if verbose {
				logHandler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
			} else {
				logHandler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})
			}
			logger := slog.New(logHandler)
			slog.SetDefault(logger)

			server := cmd.String("server")
			email := cmd.String("email")
			password := cmd.String("password")
			clientID := cmd.String("client-id")
			clientSecret := cmd.String("client-secret")
			insecureSkipVerify := cmd.Bool("insecure-skip-verify")

			appCtx := &AppContext{
				Password: password,
				Server:   server,
				Insecure: insecureSkipVerify,
				Logger:   logger,
			}

			cmdName := cmd.Args().First()
			if cmdName == "register" || cmdName == "public" || cmdName == "admin" {
				return SetAppCtx(ctx, appCtx), nil
			}

			var v *vault.Vault
			var err error

			if clientID != "" && clientSecret != "" {
				v, err = vault.LoginAPIKey(server, clientID, clientSecret, email, password, insecureSkipVerify, logger)
			} else if email != "" && password != "" {
				v, err = vault.Login(server, email, password, insecureSkipVerify, logger)
			} else {
				err = fmt.Errorf("missing credentials")
			}

			if err != nil {
				return ctx, err
			}

			appCtx.Client = v

			return SetAppCtx(ctx, appCtx), nil
		},
		Commands: []*cli.Command{
			cipherCmd(),
			accountCmd(),
			orgCmd(),
			collectionCmd(),
			groupCmd(),
			folderCmd(),
			sendCmd(),
			emergencyCmd(),
			registerCmd(),
			adminCmd(),
			publicCmd(),
		},
	}

	// Pre-parse --output/-o from raw args so we can suppress CLI framework errors
	// for structured output formats (the Destination binding happens inside cmd.Run).
	for i, arg := range os.Args {
		if (arg == "--output" || arg == "-o") && i+1 < len(os.Args) {
			outputFormat = os.Args[i+1]
			break
		}
		if strings.HasPrefix(arg, "--output=") {
			outputFormat = strings.TrimPrefix(arg, "--output=")
			break
		}
		if strings.HasPrefix(arg, "-o=") {
			outputFormat = strings.TrimPrefix(arg, "-o=")
			break
		}
	}

	// Suppress CLI framework error output for structured formats
	if outputFormat != "" && outputFormat != "text" {
		cmd.ErrWriter = io.Discard
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		printError(err)
		os.Exit(1)
	}
}

// exitOnErr prints the error and exits.
func exitOnErr(err error) {
	if err != nil {
		printError(err)
		os.Exit(1)
	}
}
