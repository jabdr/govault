package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/jabdr/govault/pkg/vault"
	"github.com/urfave/cli/v3"
)

func cipherCmd() *cli.Command {
	return &cli.Command{
		Name:  "cipher",
		Usage: "Manage ciphers",
		Commands: []*cli.Command{
			{
				Name:  "list",
				Usage: "List ciphers",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

					actionList(vClient)
					return nil
				},
			},
			{
				Name:  "get",
				Usage: "Get a specific cipher by ID",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

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
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

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
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

					actionUpdate(vClient, cmd)
					return nil
				},
			},
			{
				Name:  "delete",
				Usage: "Delete a cipher",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

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
