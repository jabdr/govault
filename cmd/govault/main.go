// Command govault is a CLI tool for interacting with Bitwarden/Vaultwarden.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"

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
				Usage:       "Enable verbose logging",
				Destination: &verbose,
			},
		},
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			logLevel := slog.LevelInfo
			if verbose {
				logLevel = slog.LevelDebug
			}
			logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

			if server == "" || email == "" || password == "" {
				return ctx, fmt.Errorf("server, email, and password are required")
			}

			var err error
			if clientID != "" && clientSecret != "" {
				vClient, err = vault.LoginAPIKey(server, clientID, clientSecret, email, password, insecureSkipVerify, logger)
			} else {
				vClient, err = vault.Login(server, email, password, insecureSkipVerify, logger)
			}

			if err != nil {
				return ctx, fmt.Errorf("login failed: %v", err)
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
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
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
				Usage: "Create a new login cipher",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true, Usage: "Name of the cipher"},
					&cli.StringFlag{Name: "username", Usage: "Login username"},
					&cli.StringFlag{Name: "login-password", Usage: "Login password"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionCreate(vClient, cmd.String("name"), cmd.String("username"), cmd.String("login-password"))
					return nil
				},
			},
			{
				Name:  "update",
				Usage: "Update a login cipher",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Required: true, Usage: "Cipher ID"},
					&cli.StringFlag{Name: "name", Usage: "Name of the cipher"},
					&cli.StringFlag{Name: "username", Usage: "Login username"},
					&cli.StringFlag{Name: "login-password", Usage: "Login password"},
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
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return fmt.Errorf("Not implemented yet")
				},
			},
			{
				Name:  "change-email",
				Usage: "Change your account email",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return fmt.Errorf("Not implemented yet")
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
					fmt.Printf("Client ID: %s\nClient Secret: %s\n", clientID, secret)
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
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return fmt.Errorf("Not implemented yet")
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
					return fmt.Errorf("Not implemented yet")
				},
			},
			{
				Name:  "create",
				Usage: "Create a folder",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return fmt.Errorf("Not implemented yet")
				},
			},
			{
				Name:  "update",
				Usage: "Update a folder",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return fmt.Errorf("Not implemented yet")
				},
			},
			{
				Name:  "delete",
				Usage: "Delete a folder",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return fmt.Errorf("Not implemented yet")
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
				Usage: "Create a text send",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true, Usage: "Send name"},
					&cli.StringFlag{Name: "text", Required: true, Usage: "Send text content"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					actionSendCreate(vClient, cmd.String("name"), cmd.String("text"))
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
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func actionList(v *vault.Vault) {
	ciphers, err := v.ListCiphers()
	exitOnErr(err)
	for _, c := range ciphers {
		fmt.Printf("%-36s  %-8s  %s\n", c.ID(), cipherTypeName(c.Type()), c.Name())
	}
}

func actionGet(v *vault.Vault, id string) {
	c, err := v.GetCipher(id)
	exitOnErr(err)
	fmt.Printf("ID:   %s\n", c.ID())
	fmt.Printf("Name: %s\n", c.Name())
	fmt.Printf("Type: %s\n", cipherTypeName(c.Type()))

	if c.Type() == vault.CipherTypeLogin { // CipherTypeLogin
		if u, p, err := c.GetLogin(); err == nil {
			fmt.Printf("User: %s\n", u)
			fmt.Printf("Pass: %s\n", p)
		}
	}
}

func actionCreate(v *vault.Vault, name, username, loginPassword string) {
	c := vault.NewCipher(vault.CipherTypeLogin, name)
	if username != "" || loginPassword != "" {
		c.SetLogin(username, loginPassword)
	}
	err := v.CreateCipher(c)
	exitOnErr(err)
	fmt.Printf("Created cipher: %s\n", c.ID())
}

func actionUpdate(v *vault.Vault, cmd *cli.Command) {
	id := cmd.String("id")
	c, err := v.GetCipher(id)
	exitOnErr(err)

	if cmd.IsSet("name") {
		c.SetField("name", cmd.String("name"))
	}

	if cmd.IsSet("username") || cmd.IsSet("login-password") {
		u, p, _ := c.GetLogin()
		if cmd.IsSet("username") {
			u = cmd.String("username")
		}
		if cmd.IsSet("login-password") {
			p = cmd.String("login-password")
		}
		c.SetLogin(u, p)
	}

	err = v.UpdateCipher(c)
	exitOnErr(err)
	fmt.Printf("Updated cipher: %s\n", c.ID())
}

func actionDelete(v *vault.Vault, id string) {
	err := v.DeleteCipher(id)
	exitOnErr(err)
	fmt.Printf("Deleted cipher: %s\n", id)
}

func actionChangePassword(v *vault.Vault, currentPassword, newPassword string, kdf, kdfIter, kdfMem, kdfParal int) {
	err := v.ChangePassword(currentPassword, newPassword, kdf, kdfIter, kdfMem, kdfParal)
	exitOnErr(err)
}

func actionOrgList(v *vault.Vault) {
	orgs, err := v.ListOrganizations()
	exitOnErr(err)
	for _, o := range orgs {
		fmt.Printf("%s  %s\n", o.ID, o.Name)
	}
}

func actionOrgMembers(v *vault.Vault, orgID string) {
	members, err := v.ListOrgMembers(orgID)
	exitOnErr(err)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tEMAIL\tSTATUS\tTYPE")
	for _, m := range members {
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\n", m.ID, m.Email, m.Status, m.Type)
	}
	w.Flush()
}

func actionOrgInvite(v *vault.Vault, orgID, emails string) {
	emailList := strings.Split(emails, ",")
	for i, e := range emailList {
		emailList[i] = strings.TrimSpace(e)
	}
	err := v.InviteToOrganization(orgID, emailList, 1) // 1=User
	exitOnErr(err)
	fmt.Printf("Invited %d users to org %s\n", len(emailList), orgID)
}

func actionOrgConfirm(v *vault.Vault, orgID, memberID string) {
	err := v.ConfirmMember(orgID, memberID)
	exitOnErr(err)
	fmt.Printf("Confirmed member %s in org %s\n", memberID, orgID)
}

func actionCollections(v *vault.Vault, orgID string) {
	cols, err := v.ListCollections(orgID)
	exitOnErr(err)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tSYNC")
	for _, c := range cols {
		fmt.Fprintf(w, "%s\t%s\t%t\n", c.ID, c.Name, err == nil)
	}
	w.Flush()
}

func actionCollectionCreate(v *vault.Vault, orgID, name string) {
	col, err := v.CreateCollection(orgID, name)
	exitOnErr(err)
	fmt.Printf("Created: %s\n", col.ID)
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
	fmt.Printf("Collection permissions updated for %s\n", collectionID)
}

func actionGroups(v *vault.Vault, orgID string) {
	groups, err := v.ListGroups(orgID)
	exitOnErr(err)

	if len(groups) == 0 {
		fmt.Println("No groups found.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tACCESS ALL")
	for _, g := range groups {
		fmt.Fprintf(w, "%s\t%s\t%t\n", g.ID, g.Name, g.AccessAll)
	}
	w.Flush()
}

func actionGroupCreate(v *vault.Vault, orgID, name string, accessAll bool) {
	grp, err := v.CreateGroup(orgID, name, accessAll)
	exitOnErr(err)
	fmt.Printf("Created Group: %s (ID: %s)\n", grp.Name, grp.ID)
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
	fmt.Printf("Updated Group: %s\n", groupID)
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
	fmt.Printf("Deleted Group: %s\n", groupID)
}

func actionCollectionDelete(v *vault.Vault, orgID, collectionID string) {
	err := v.DeleteCollection(orgID, collectionID)
	exitOnErr(err)
	fmt.Printf("Deleted collection: %s\n", collectionID)
}

func actionSends(v *vault.Vault) {
	sends, err := v.ListSends()
	exitOnErr(err)
	for _, s := range sends {
		fmt.Printf("%s  %s (Views: %d/%d)\n", s.ID, s.Name, s.AccessCount, s.MaxAccessCount)
	}
}

func actionSendCreate(v *vault.Vault, name, text string) {
	s, _, err := v.CreateTextSend(name, text, vault.SendOptions{})
	exitOnErr(err)
	fmt.Printf("Created send: %s\n", s.ID)
	// BaseURL and clientAccess are not directly exported this simply anymore based on structure
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
		fmt.Printf("Send not found: %s\n", id)
		return
	}
	fmt.Printf("ID:   %s\n", send.ID)
	fmt.Printf("Name: %s\n", send.Name)
	if send.Type == vault.SendTypeText {
		fmt.Printf("Text: %s\n", send.Text)
	}
}

func actionSendDelete(v *vault.Vault, id string) {
	err := v.DeleteSend(id)
	exitOnErr(err)
	fmt.Printf("Deleted send: %s\n", id)
}

func actionEmergencyTrusted(v *vault.Vault) {
	contacts, err := v.ListTrustedEmergencyAccess()
	exitOnErr(err)
	fmt.Println("Trusted Emergency Contacts (where I am the grantor):")
	for _, c := range contacts {
		fmt.Printf("  %s  %s  (Status: %d, Type: %d)\n", c.ID, c.Email, c.Status, c.Type)
	}
}

func actionEmergencyGranted(v *vault.Vault) {
	granted, err := v.ListGrantedEmergencyAccess()
	exitOnErr(err)
	fmt.Println("Granted Emergency Access (where I am the grantee):")
	for _, g := range granted {
		fmt.Printf("  %s  %s  (Status: %d, Type: %d)\n", g.ID, g.Email, g.Status, g.Type)
	}
}

func actionEmergencyInvite(v *vault.Vault, email string, accessType, waitDays int) {
	err := v.InviteEmergencyAccess(email, accessType, waitDays)
	exitOnErr(err)
	fmt.Printf("Invited %s as emergency contact\n", email)
}

func actionEmergencyConfirm(v *vault.Vault, id string) {
	err := v.ConfirmEmergencyAccess(id)
	exitOnErr(err)
	fmt.Printf("Confirmed emergency contact %s\n", id)
}

func actionEmergencyInitiate(v *vault.Vault, id string) {
	err := v.InitiateEmergencyAccess(id)
	exitOnErr(err)
	fmt.Printf("Initiated emergency access for %s\n", id)
}

func actionEmergencyApprove(v *vault.Vault, id string) {
	err := v.ApproveEmergencyAccess(id)
	exitOnErr(err)
	fmt.Printf("Approved emergency access request %s\n", id)
}

func actionEmergencyReject(v *vault.Vault, id string) {
	err := v.RejectEmergencyAccess(id)
	exitOnErr(err)
	fmt.Printf("Rejected emergency access request %s\n", id)
}

func actionEmergencyView(v *vault.Vault, id string) {
	ciphers, err := v.ViewEmergencyVault(id)
	exitOnErr(err)
	fmt.Println("Ciphers available via emergency access:")
	for _, c := range ciphers {
		fmt.Printf("%-36s  %s\n", c.ID(), c.Name())
	}
}

func actionEmergencyTakeover(v *vault.Vault, id, newPassword string) {
	err := v.TakeoverEmergencyAccess(id, newPassword)
	exitOnErr(err)
	fmt.Printf("Emergency takeover successful for %s. New master password is set.\n", id)
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
	}
	return "Unknown"
}
