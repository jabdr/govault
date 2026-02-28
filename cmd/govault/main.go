// Command govault is a CLI tool for interacting with Bitwarden/Vaultwarden.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/jabdr/govault/pkg/api"
	"github.com/jabdr/govault/pkg/vault"
	"github.com/urfave/cli/v3"
)

var (
	server             string
	email              string
	password           string
	clientID           string
	clientSecret       string
	insecureSkipVerify bool
	verbose            bool
	logger             *slog.Logger
	vClient            *vault.Vault
)

func main() {
	cmd := &cli.Command{
		Name:  "govault",
		Usage: "A CLI tool for interacting with Bitwarden/Vaultwarden.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "server",
				Usage:       "Vaultwarden/Bitwarden server URL",
				Sources:     cli.EnvVars("GOVAULT_SERVER"),
				Destination: &server,
			},
			&cli.StringFlag{
				Name:        "email",
				Usage:       "Account email",
				Sources:     cli.EnvVars("GOVAULT_EMAIL"),
				Destination: &email,
			},
			&cli.StringFlag{
				Name:        "password",
				Usage:       "Master password",
				Sources:     cli.EnvVars("GOVAULT_PASSWORD"),
				Destination: &password,
			},
			&cli.StringFlag{
				Name:        "client-id",
				Usage:       "API Client ID",
				Sources:     cli.EnvVars("GOVAULT_CLIENT_ID"),
				Destination: &clientID,
			},
			&cli.StringFlag{
				Name:        "client-secret",
				Usage:       "API Client Secret",
				Sources:     cli.EnvVars("GOVAULT_CLIENT_SECRET"),
				Destination: &clientSecret,
			},
			&cli.BoolFlag{
				Name:        "insecure-skip-verify",
				Usage:       "Skip TLS verification",
				Destination: &insecureSkipVerify,
			},
			&cli.BoolFlag{
				Name:        "verbose",
				Aliases:     []string{"v"},
				Usage:       "Enable verbose logging",
				Destination: &verbose,
			},
			&cli.StringFlag{
				Name:        "output",
				Aliases:     []string{"o"},
				Usage:       "Output format: text, json, yaml",
				Value:       "text",
				Destination: &outputFormat,
			},
		},
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			logLevel := slog.LevelWarn
			if verbose {
				logLevel = slog.LevelInfo
			}
			logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

			// Skip login for 'register' and 'help' commands
			for _, arg := range os.Args {
				if arg == "register" || arg == "help" || arg == "-h" || arg == "--help" {
					return ctx, nil
				}
			}

			if server == "" || email == "" || password == "" {
				return ctx, fmt.Errorf("server, email, and password are required for this command")
			}

			var err error
			if clientID != "" && clientSecret != "" {
				vClient, err = vault.LoginAPIKey(server, clientID, clientSecret, email, password, insecureSkipVerify, logger)
			} else {
				vClient, err = vault.Login(server, email, password, insecureSkipVerify, logger)
			}

			if err != nil {
				return ctx, fmt.Errorf("login failed: %w", err)
			}
			return ctx, nil
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

// -----------------------------------------------------------------------------
// Cipher Commands
// -----------------------------------------------------------------------------
func cipherCmd() *cli.Command {
	return &cli.Command{
		Name:  "cipher",
		Usage: "Manage ciphers",
		Commands: []*cli.Command{
			{
				Name:  "list",
				Usage: "List ciphers",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionList(vClient)
					return nil
				},
			},
			{
				Name:  "get",
				Usage: "Get a specific cipher by ID",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					id := cmd.Args().First()
					if id == "" {
						return fmt.Errorf("cipher ID is required")
					}
					actionGet(vClient, id)
					return nil
				},
			},
			{
				Name:  "create",
				Usage: "Create a new cipher",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true, Usage: "Name of the cipher"},
					&cli.IntFlag{Name: "type", Value: vault.CipherTypeLogin, Usage: "Type of cipher (1=Login, 2=Note, 3=Card, 4=Identity, 5=SshKey)"},
					&cli.StringFlag{Name: "notes", Usage: "Notes for the cipher"},
					&cli.StringFlag{Name: "login-username", Usage: "Login username"},
					&cli.StringFlag{Name: "login-password", Usage: "Login password"},
					&cli.StringSliceFlag{Name: "url", Usage: "Login URLs (can be specified multiple times)"},
					&cli.StringSliceFlag{Name: "field", Usage: "Custom fields (format: Name=Value)"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionCreate(vClient, cmd)
					return nil
				},
			},
			{
				Name:  "update",
				Usage: "Update a cipher",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Required: true, Usage: "Cipher ID"},
					&cli.StringFlag{Name: "name", Usage: "Name of the cipher"},
					&cli.StringFlag{Name: "notes", Usage: "Notes for the cipher"},
					&cli.StringFlag{Name: "login-username", Usage: "Login username (updates independent of password)"},
					&cli.StringFlag{Name: "login-password", Usage: "Login password (updates independent of username)"},
					&cli.StringSliceFlag{Name: "url", Usage: "Login URLs (can be specified multiple times, replaces existing)"},
					&cli.StringSliceFlag{Name: "field", Usage: "Custom fields to add (format: Name=Value)"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionUpdate(vClient, cmd)
					return nil
				},
			},
			{
				Name:  "delete",
				Usage: "Delete a cipher",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					id := cmd.Args().First()
					if id == "" {
						return fmt.Errorf("cipher ID is required")
					}
					actionDelete(vClient, id)
					return nil
				},
			},
		},
	}
}

// -----------------------------------------------------------------------------
// Account Commands
// -----------------------------------------------------------------------------
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
					err := vClient.ChangeName(cmd.String("name"))
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
					err := vClient.ChangeEmail(newEmail, password, token, int(cmd.Int("kdf")), int(cmd.Int("kdf-iterations")), int(cmd.Int("kdf-memory")), int(cmd.Int("kdf-parallelism")))
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

// -----------------------------------------------------------------------------
// Organization Commands
// -----------------------------------------------------------------------------
func orgCmd() *cli.Command {
	return &cli.Command{
		Name:  "org",
		Usage: "Manage organizations",
		Commands: []*cli.Command{
			{
				Name:  "list",
				Usage: "List accessible organizations",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionOrgList(vClient)
					return nil
				},
			},
			{
				Name:  "create",
				Usage: "Create an organization",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true, Usage: "Organization name"},
					&cli.StringFlag{Name: "billing-email", Required: true, Usage: "Billing email address"},
					&cli.StringFlag{Name: "collection-name", Value: "Default Collection", Usage: "Name of the default collection"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionOrgCreate(vClient, cmd.String("name"), cmd.String("billing-email"), cmd.String("collection-name"))
					return nil
				},
			},
			{
				Name:  "members",
				Usage: "List organization members",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Required: true, Usage: "Organization ID"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionOrgMembers(vClient, cmd.String("id"))
					return nil
				},
			},
			{
				Name:  "invite",
				Usage: "Invite an email to an organization",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Required: true, Usage: "Organization ID"},
					&cli.StringFlag{Name: "email", Required: true, Usage: "Email(s) to invite (comma-separated)"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionOrgInvite(vClient, cmd.String("id"), cmd.String("email"))
					return nil
				},
			},
			{
				Name:  "confirm",
				Usage: "Confirm an organization invitation",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Required: true, Usage: "Organization ID"},
					&cli.StringFlag{Name: "member-id", Required: true, Usage: "Member ID"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionOrgConfirm(vClient, cmd.String("id"), cmd.String("member-id"))
					return nil
				},
			},
		},
	}
}

// -----------------------------------------------------------------------------
// Collection Commands
// -----------------------------------------------------------------------------
func collectionCmd() *cli.Command {
	return &cli.Command{
		Name:  "collection",
		Usage: "Manage collections",
		Commands: []*cli.Command{
			{
				Name:  "list",
				Usage: "List collections in an organization",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "org-id", Required: true, Usage: "Organization ID"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionCollections(vClient, cmd.String("org-id"))
					return nil
				},
			},
			{
				Name:  "create",
				Usage: "Create a collection",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "org-id", Required: true, Usage: "Organization ID"},
					&cli.StringFlag{Name: "name", Required: true, Usage: "Collection Name"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionCollectionCreate(vClient, cmd.String("org-id"), cmd.String("name"))
					return nil
				},
			},
			{
				Name:  "update",
				Usage: "Update a collection",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "org-id", Required: true, Usage: "Organization ID"},
					&cli.StringFlag{Name: "id", Required: true, Usage: "Collection ID or Name"},
					&cli.StringFlag{Name: "users", Usage: "JSON array of user access for collection"},
					&cli.StringFlag{Name: "groups", Usage: "JSON array of group access for collection"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionCollectionUpdate(vClient, cmd.String("org-id"), cmd.String("id"), cmd.String("users"), cmd.String("groups"))
					return nil
				},
			},
			{
				Name:  "delete",
				Usage: "Delete a collection",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "org-id", Required: true, Usage: "Organization ID"},
					&cli.StringFlag{Name: "id", Required: true, Usage: "Collection ID"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionCollectionDelete(vClient, cmd.String("org-id"), cmd.String("id"))
					return nil
				},
			},
		},
	}
}

// -----------------------------------------------------------------------------
// Group Commands
// -----------------------------------------------------------------------------
func groupCmd() *cli.Command {
	return &cli.Command{
		Name:  "group",
		Usage: "Manage groups",
		Commands: []*cli.Command{
			{
				Name:  "list",
				Usage: "List groups in an organization",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "org-id", Required: true, Usage: "Organization ID"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionGroups(vClient, cmd.String("org-id"))
					return nil
				},
			},
			{
				Name:  "create",
				Usage: "Create a group",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "org-id", Required: true, Usage: "Organization ID"},
					&cli.StringFlag{Name: "name", Required: true, Usage: "Group Name"},
					&cli.BoolFlag{Name: "access-all", Usage: "Access all collections"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionGroupCreate(vClient, cmd.String("org-id"), cmd.String("name"), cmd.Bool("access-all"))
					return nil
				},
			},
			{
				Name:  "update",
				Usage: "Update a group",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "org-id", Required: true, Usage: "Organization ID"},
					&cli.StringFlag{Name: "id", Required: true, Usage: "Group ID or Name"},
					&cli.StringFlag{Name: "name", Required: true, Usage: "Group Name"},
					&cli.BoolFlag{Name: "access-all", Usage: "Access all collections"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionGroupUpdate(vClient, cmd.String("org-id"), cmd.String("id"), cmd.String("name"), cmd.Bool("access-all"))
					return nil
				},
			},
			{
				Name:  "delete",
				Usage: "Delete a group",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "org-id", Required: true, Usage: "Organization ID"},
					&cli.StringFlag{Name: "id", Required: true, Usage: "Group ID or Name"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionGroupDelete(vClient, cmd.String("org-id"), cmd.String("id"))
					return nil
				},
			},
		},
	}
}

// -----------------------------------------------------------------------------
// Folder Commands
// -----------------------------------------------------------------------------
func folderCmd() *cli.Command {
	return &cli.Command{
		Name:  "folder",
		Usage: "Manage folders",
		Commands: []*cli.Command{
			{
				Name:  "list",
				Usage: "List folders",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionFolderList(vClient)
					return nil
				},
			},
			{
				Name:  "create",
				Usage: "Create a folder",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true, Usage: "Folder name"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionFolderCreate(vClient, cmd.String("name"))
					return nil
				},
			},
			{
				Name:  "update",
				Usage: "Rename a folder",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Required: true, Usage: "Folder ID"},
					&cli.StringFlag{Name: "name", Required: true, Usage: "New folder name"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionFolderUpdate(vClient, cmd.String("id"), cmd.String("name"))
					return nil
				},
			},
			{
				Name:  "delete",
				Usage: "Delete a folder",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					id := cmd.Args().First()
					if id == "" {
						return fmt.Errorf("folder ID is required")
					}
					actionFolderDelete(vClient, id)
					return nil
				},
			},
		},
	}
}

// -----------------------------------------------------------------------------
// Send Commands
// -----------------------------------------------------------------------------
func sendCmd() *cli.Command {
	return &cli.Command{
		Name:  "send",
		Usage: "Manage sends",
		Commands: []*cli.Command{
			{
				Name:  "list",
				Usage: "List sends",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionSends(vClient)
					return nil
				},
			},
			{
				Name:  "create",
				Usage: "Create a send",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Usage: "Send name (defaults to file name or 'Text Send')"},
					&cli.StringFlag{Name: "text", Usage: "Send text content"},
					&cli.StringFlag{Name: "file", Usage: "Path to file to upload"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionSendCreate(vClient, cmd.String("name"), cmd.String("text"), cmd.String("file"))
					return nil
				},
			},
			{
				Name:  "get",
				Usage: "Get a send by ID",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					id := cmd.Args().First()
					if id == "" {
						return fmt.Errorf("send ID is required")
					}
					actionSendGet(vClient, id)
					return nil
				},
			},
			{
				Name:  "delete",
				Usage: "Delete a send",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					id := cmd.Args().First()
					if id == "" {
						return fmt.Errorf("send ID is required")
					}
					actionSendDelete(vClient, id)
					return nil
				},
			},
		},
	}
}

// -----------------------------------------------------------------------------
// Emergency Access Commands
// -----------------------------------------------------------------------------
func emergencyCmd() *cli.Command {
	return &cli.Command{
		Name:  "emergency",
		Usage: "Manage emergency access",
		Commands: []*cli.Command{
			{
				Name:  "trusted",
				Usage: "List trusted emergency contacts",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionEmergencyTrusted(vClient)
					return nil
				},
			},
			{
				Name:  "granted",
				Usage: "List granted emergency contacts",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionEmergencyGranted(vClient)
					return nil
				},
			},
			{
				Name:  "invite",
				Usage: "Invite an emergency contact",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "email", Required: true, Usage: "Contact email"},
					&cli.IntFlag{Name: "type", Value: 0, Usage: "Access type (0=view, 1=takeover)"},
					&cli.IntFlag{Name: "wait", Value: 7, Usage: "Wait time in days"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionEmergencyInvite(vClient, cmd.String("email"), int(cmd.Int("type")), int(cmd.Int("wait")))
					return nil
				},
			},
			{
				Name:  "confirm",
				Usage: "Confirm an emergency contact invitation",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Required: true, Usage: "Emergency Contact ID"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionEmergencyConfirm(vClient, cmd.String("id"))
					return nil
				},
			},
			{
				Name:  "initiate",
				Usage: "Initiate emergency access",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Required: true, Usage: "Emergency Contact ID"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionEmergencyInitiate(vClient, cmd.String("id"))
					return nil
				},
			},
			{
				Name:  "approve",
				Usage: "Approve emergency access request",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Required: true, Usage: "Emergency Contact ID"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionEmergencyApprove(vClient, cmd.String("id"))
					return nil
				},
			},
			{
				Name:  "reject",
				Usage: "Reject emergency access request",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Required: true, Usage: "Emergency Contact ID"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionEmergencyReject(vClient, cmd.String("id"))
					return nil
				},
			},
			{
				Name:  "view",
				Usage: "View ciphers from granted emergency access",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Required: true, Usage: "Emergency Contact ID"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionEmergencyView(vClient, cmd.String("id"))
					return nil
				},
			},
			{
				Name:  "takeover",
				Usage: "Takeover an account via emergency access",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Required: true, Usage: "Emergency Contact ID"},
					&cli.StringFlag{Name: "new-password", Required: true, Usage: "New master password"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionEmergencyTakeover(vClient, cmd.String("id"), cmd.String("new-password"))
					return nil
				},
			},
		},
	}
}

// -----------------------------------------------------------------------------
// Legacy Actions
// -----------------------------------------------------------------------------

func exitOnErr(err error) {
	if err != nil {
		printError(err)
		os.Exit(1)
	}
}

func actionList(v *vault.Vault) {
	ciphers, err := v.ListCiphers()
	exitOnErr(err)
	results := make([]CipherResult, 0, len(ciphers))
	for _, c := range ciphers {
		results = append(results, CipherResult{
			ID:   c.ID(),
			Name: c.Name(),
			Type: cipherTypeName(c.Type()),
		})
	}
	printList(results)
}

func actionGet(v *vault.Vault, id string) {
	c, err := v.GetCipher(id)
	exitOnErr(err)
	result := CipherResult{
		ID:   c.ID(),
		Name: c.Name(),
		Type: cipherTypeName(c.Type()),
	}
	if c.Type() == vault.CipherTypeLogin {
		if u, p, err := c.GetLogin(); err == nil {
			result.Username = u
			result.Password = p
		}
		if urls, err := c.GetLoginURLs(); err == nil && len(urls) > 0 {
			result.URLs = urls
		}
	}
	if notes := c.Notes(); notes != "" {
		result.Notes = notes
	}
	printOutput(result)
}

func actionCreate(v *vault.Vault, cmd *cli.Command) {
	c, err := vault.NewCipher(cmd.Int("type"), cmd.String("name"), v.SymmetricKey())
	exitOnErr(err)

	if cmd.IsSet("notes") {
		exitOnErr(c.SetNotes(cmd.String("notes")))
	}

	if cmd.IsSet("login-username") {
		exitOnErr(c.SetLoginUsername(cmd.String("login-username")))
	}
	if cmd.IsSet("login-password") {
		exitOnErr(c.SetLoginPassword(cmd.String("login-password")))
	}
	if cmd.IsSet("url") {
		exitOnErr(c.SetLoginURLs(cmd.StringSlice("url")))
	}

	if cmd.IsSet("field") {
		for _, field := range cmd.StringSlice("field") {
			parts := strings.SplitN(field, "=", 2)
			if len(parts) == 2 {
				exitOnErr(c.AddField(parts[0], parts[1], 0))
			}
		}
	}

	err = v.CreateCipher(c)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Created cipher: %s", c.ID()), ID: c.ID()})
}

func actionUpdate(v *vault.Vault, cmd *cli.Command) {
	id := cmd.String("id")
	c, err := v.GetCipher(id)
	exitOnErr(err)

	if cmd.IsSet("name") {
		exitOnErr(c.SetName(cmd.String("name")))
	}

	if cmd.IsSet("notes") {
		exitOnErr(c.SetNotes(cmd.String("notes")))
	}

	if cmd.IsSet("login-username") {
		exitOnErr(c.SetLoginUsername(cmd.String("login-username")))
	}
	if cmd.IsSet("login-password") {
		exitOnErr(c.SetLoginPassword(cmd.String("login-password")))
	}
	if cmd.IsSet("url") {
		exitOnErr(c.SetLoginURLs(cmd.StringSlice("url")))
	}

	if cmd.IsSet("field") {
		for _, field := range cmd.StringSlice("field") {
			parts := strings.SplitN(field, "=", 2)
			if len(parts) == 2 {
				exitOnErr(c.AddField(parts[0], parts[1], 0))
			}
		}
	}

	err = v.UpdateCipher(c)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Updated cipher: %s", c.ID()), ID: c.ID()})
}

func actionDelete(v *vault.Vault, id string) {
	err := v.DeleteCipher(id)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Deleted cipher: %s", id), ID: id})
}

func actionChangePassword(v *vault.Vault, currentPassword, newPassword string, kdf, kdfIter, kdfMem, kdfParal int) {
	err := v.ChangePassword(currentPassword, newPassword, kdf, kdfIter, kdfMem, kdfParal)
	exitOnErr(err)
}

func actionOrgList(v *vault.Vault) {
	orgs, err := v.ListOrganizations()
	exitOnErr(err)
	results := make([]OrgResult, 0, len(orgs))
	for _, o := range orgs {
		results = append(results, OrgResult{ID: o.ID, Name: o.Name})
	}
	printList(results)
}

func actionOrgCreate(v *vault.Vault, name, billingEmail, collectionName string) {
	orgID, err := v.CreateOrganization(name, billingEmail, collectionName)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Created organization: %s", orgID), ID: orgID})
}

func actionOrgMembers(v *vault.Vault, orgID string) {
	members, err := v.ListOrgMembers(orgID)
	exitOnErr(err)
	results := make([]OrgMemberResult, 0, len(members))
	for _, m := range members {
		results = append(results, OrgMemberResult{ID: m.ID, Email: m.Email, Status: m.Status, Type: m.Type})
	}
	printList(results)
}

func actionOrgInvite(v *vault.Vault, orgID, emails string) {
	emailList := strings.Split(emails, ",")
	for i, e := range emailList {
		emailList[i] = strings.TrimSpace(e)
	}
	err := v.InviteToOrganization(orgID, emailList, 1) // 1=User
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Invited %d users to org %s", len(emailList), orgID)})
}

func actionOrgConfirm(v *vault.Vault, orgID, memberID string) {
	err := v.ConfirmMember(orgID, memberID)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Confirmed member %s in org %s", memberID, orgID), ID: memberID})
}

func actionCollections(v *vault.Vault, orgID string) {
	cols, err := v.ListCollections(orgID)
	exitOnErr(err)
	results := make([]CollectionResult, 0, len(cols))
	for _, c := range cols {
		results = append(results, CollectionResult{ID: c.ID, Name: c.Name})
	}
	printList(results)
}

func actionCollectionCreate(v *vault.Vault, orgID, name string) {
	col, err := v.CreateCollection(orgID, name)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Created: %s", col.ID), ID: col.ID})
}

func actionCollectionUpdate(v *vault.Vault, orgID, collectionIDOrName, reqUsers, reqGroups string) {
	cols, err := v.ListCollections(orgID)
	exitOnErr(err)

	collectionID := collectionIDOrName
	for _, c := range cols {
		if c.Name == collectionIDOrName {
			collectionID = c.ID
			break
		}
	}

	var parsedUsers []map[string]interface{}
	var parsedGroups []map[string]interface{}

	if reqUsers != "" {
		if err := json.Unmarshal([]byte(reqUsers), &parsedUsers); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing --users-access JSON: %v\n", err)
			os.Exit(1)
		}
	}
	if reqGroups != "" {
		if err := json.Unmarshal([]byte(reqGroups), &parsedGroups); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing --groups-access JSON: %v\n", err)
			os.Exit(1)
		}
	}

	members, err := v.ListOrgMembers(orgID)
	exitOnErr(err)
	memberMap := make(map[string]string) // email -> id
	for _, m := range members {
		memberMap[m.Email] = m.ID
	}

	groups, _ := v.ListGroups(orgID)    // Might fail if groups not supported, ignore err
	groupMap := make(map[string]string) // name -> id
	for _, g := range groups {
		groupMap[g.Name] = g.ID
	}

	var users []api.CollectionUserAccess
	var groupsAccess []api.CollectionGroupAccess

	for _, pu := range parsedUsers {
		id := pu["id"].(string)
		if email, ok := pu["email"].(string); ok && email != "" {
			if matchedID, found := memberMap[email]; found {
				id = matchedID
			}
		} else if emailOrID, ok := pu["id"].(string); ok {
			if matchedID, found := memberMap[emailOrID]; found {
				id = matchedID
			}
		}

		ro, _ := pu["readOnly"].(bool)
		hp, _ := pu["hidePasswords"].(bool)
		mng, _ := pu["manage"].(bool)
		users = append(users, api.CollectionUserAccess{
			ID:            id,
			ReadOnly:      ro,
			HidePasswords: hp,
			Manage:        mng,
		})
	}

	for _, pg := range parsedGroups {
		id := pg["id"].(string)
		if name, ok := pg["name"].(string); ok && name != "" {
			if matchedID, found := groupMap[name]; found {
				id = matchedID
			}
		} else if nameOrID, ok := pg["id"].(string); ok {
			if matchedID, found := groupMap[nameOrID]; found {
				id = matchedID
			}
		}

		ro, _ := pg["readOnly"].(bool)
		hp, _ := pg["hidePasswords"].(bool)
		mng, _ := pg["manage"].(bool)
		groupsAccess = append(groupsAccess, api.CollectionGroupAccess{
			ID:            id,
			ReadOnly:      ro,
			HidePasswords: hp,
			Manage:        mng,
		})
	}

	err = v.UpdateCollectionPermissions(orgID, collectionID, groupsAccess, users)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Collection permissions updated for %s", collectionID), ID: collectionID})
}

func actionGroups(v *vault.Vault, orgID string) {
	groups, err := v.ListGroups(orgID)
	exitOnErr(err)

	results := make([]GroupResult, 0, len(groups))
	for _, g := range groups {
		results = append(results, GroupResult{ID: g.ID, Name: g.Name, AccessAll: g.AccessAll})
	}
	if len(results) == 0 {
		printOutput(MessageResult{Message: "No groups found."})
		return
	}
	printList(results)
}

func actionGroupCreate(v *vault.Vault, orgID, name string, accessAll bool) {
	grp, err := v.CreateGroup(orgID, name, accessAll)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Created Group: %s (ID: %s)", grp.Name, grp.ID), ID: grp.ID})
}

func actionGroupUpdate(v *vault.Vault, orgID, idOrName, name string, accessAll bool) {
	groups, err := v.ListGroups(orgID)
	exitOnErr(err)

	groupID := idOrName
	for _, g := range groups {
		if g.Name == idOrName {
			groupID = g.ID
			break
		}
	}

	err = v.UpdateGroup(orgID, groupID, name, accessAll)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Updated Group: %s", groupID), ID: groupID})
}

func actionGroupDelete(v *vault.Vault, orgID, idOrName string) {
	groups, err := v.ListGroups(orgID)
	exitOnErr(err)

	groupID := idOrName
	for _, g := range groups {
		if g.Name == idOrName {
			groupID = g.ID
			break
		}
	}

	err = v.DeleteGroup(orgID, groupID)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Deleted Group: %s", groupID), ID: groupID})
}

func actionCollectionDelete(v *vault.Vault, orgID, collectionID string) {
	err := v.DeleteCollection(orgID, collectionID)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Deleted collection: %s", collectionID), ID: collectionID})
}

// -----------------------------------------------------------------------------
// Folder Actions
// -----------------------------------------------------------------------------

func actionFolderList(v *vault.Vault) {
	folders, err := v.ListFolders()
	exitOnErr(err)
	results := make([]FolderResult, 0, len(folders))
	for _, f := range folders {
		results = append(results, FolderResult{ID: f.ID, Name: f.Name})
	}
	if len(results) == 0 {
		printOutput(MessageResult{Message: "No folders found."})
		return
	}
	printList(results)
}

func actionFolderCreate(v *vault.Vault, name string) {
	f, err := v.CreateFolder(name)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Created folder: %s", name), ID: f.ID})
}

func actionFolderUpdate(v *vault.Vault, id, name string) {
	f, err := v.UpdateFolder(id, name)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Renamed folder to: %s", name), ID: f.ID})
}

func actionFolderDelete(v *vault.Vault, id string) {
	err := v.DeleteFolder(id)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Deleted folder: %s", id), ID: id})
}

func actionSends(v *vault.Vault) {
	sends, err := v.ListSends()
	exitOnErr(err)
	results := make([]SendResult, 0, len(sends))
	for _, s := range sends {
		results = append(results, SendResult{
			ID:             s.ID,
			Name:           s.Name,
			FileName:       s.FileName,
			URL:            s.URL,
			AccessCount:    s.AccessCount,
			MaxAccessCount: s.MaxAccessCount,
		})
	}
	printList(results)
}

func actionSendCreate(v *vault.Vault, name, text, filePath string) {
	if text == "" && filePath == "" {
		exitOnErr(fmt.Errorf("either --text or --file must be provided"))
	}

	var s *vault.Send
	var accessURL string
	var err error

	if filePath != "" {
		data, err := os.ReadFile(filePath)
		exitOnErr(err)
		fileName := filepath.Base(filePath)
		if name == "" {
			name = fileName
		}
		s, accessURL, err = v.CreateFileSend(name, fileName, data, vault.SendOptions{})
		exitOnErr(err)
	} else {
		if name == "" {
			name = "Text Send"
		}
		s, accessURL, err = v.CreateTextSend(name, text, vault.SendOptions{})
		exitOnErr(err)
	}

	printOutput(MessageResult{Message: fmt.Sprintf("Created send: %s", s.ID), ID: s.ID, URL: accessURL})
}

func actionSendGet(v *vault.Vault, id string) {
	sends, err := v.ListSends()
	exitOnErr(err)
	var send *vault.Send
	for _, s := range sends {
		if s.ID == id {
			send = s
			break
		}
	}
	if send == nil {
		printOutput(MessageResult{Message: fmt.Sprintf("Send not found: %s", id)})
		return
	}
	result := SendResult{
		ID:          send.ID,
		Name:        send.Name,
		FileName:    send.FileName,
		URL:         send.URL,
		AccessCount: send.AccessCount,
	}
	if send.Type == vault.SendTypeText {
		result.Text = send.Text
	}
	printOutput(result)
}

func actionSendDelete(v *vault.Vault, id string) {
	err := v.DeleteSend(id)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Deleted send: %s", id), ID: id})
}

func actionEmergencyTrusted(v *vault.Vault) {
	contacts, err := v.ListTrustedEmergencyAccess()
	exitOnErr(err)
	results := make([]EmergencyContactResult, 0, len(contacts))
	for _, c := range contacts {
		results = append(results, EmergencyContactResult{ID: c.ID, Email: c.Email, Status: c.Status, Type: c.Type})
	}
	printList(results)
}

func actionEmergencyGranted(v *vault.Vault) {
	granted, err := v.ListGrantedEmergencyAccess()
	exitOnErr(err)
	results := make([]EmergencyContactResult, 0, len(granted))
	for _, g := range granted {
		results = append(results, EmergencyContactResult{ID: g.ID, Email: g.Email, Status: g.Status, Type: g.Type})
	}
	printList(results)
}

func actionEmergencyInvite(v *vault.Vault, email string, accessType, waitDays int) {
	err := v.InviteEmergencyAccess(email, accessType, waitDays)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Invited %s as emergency contact", email)})
}

func actionEmergencyConfirm(v *vault.Vault, id string) {
	err := v.ConfirmEmergencyAccess(id)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Confirmed emergency contact %s", id), ID: id})
}

func actionEmergencyInitiate(v *vault.Vault, id string) {
	err := v.InitiateEmergencyAccess(id)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Initiated emergency access for %s", id), ID: id})
}

func actionEmergencyApprove(v *vault.Vault, id string) {
	err := v.ApproveEmergencyAccess(id)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Approved emergency access request %s", id), ID: id})
}

func actionEmergencyReject(v *vault.Vault, id string) {
	err := v.RejectEmergencyAccess(id)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Rejected emergency access request %s", id), ID: id})
}

func actionEmergencyView(v *vault.Vault, id string) {
	ciphers, err := v.ViewEmergencyVault(id)
	exitOnErr(err)
	results := make([]CipherResult, 0, len(ciphers))
	for _, c := range ciphers {
		results = append(results, CipherResult{ID: c.ID(), Name: c.Name(), Type: cipherTypeName(c.Type())})
	}
	printList(results)
}

func actionEmergencyTakeover(v *vault.Vault, id, newPassword string) {
	err := v.TakeoverEmergencyAccess(id, newPassword)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Emergency takeover successful for %s. New master password is set.", id), ID: id})
}

// -----------------------------------------------------------------------------
// Register Command
// -----------------------------------------------------------------------------

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
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if server == "" || email == "" || password == "" {
				return fmt.Errorf("server, email, and password are required")
			}
			err := vault.Register(server, email, password, int(cmd.Int("kdf")), int(cmd.Int("kdf-iterations")), int(cmd.Int("kdf-memory")), int(cmd.Int("kdf-parallelism")), insecureSkipVerify, logger)
			if err != nil {
				return err
			}
			printOutput(MessageResult{Message: fmt.Sprintf("Account %s successfully registered", email)})
			return nil
		},
	}
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
