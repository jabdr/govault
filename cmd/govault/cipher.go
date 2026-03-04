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
				Name:   "list",
				Usage:  "List ciphers",
				Action: runCipherList,
			},
			{
				Name:   "get",
				Usage:  "Get a specific cipher by ID",
				Action: runCipherGet,
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
				Action: runCipherCreate,
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
				Action: runCipherUpdate,
			},
			{
				Name:   "delete",
				Usage:  "Delete a cipher",
				Action: runCipherDelete,
			},
		},
	}
}

func runCipherList(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	ciphers, err := appCtx.Client.ListCiphers()
	if err != nil {
		return err
	}
	results := make([]CipherResult, 0, len(ciphers))
	for _, c := range ciphers {
		results = append(results, CipherResult{
			ID:   c.ID(),
			Name: c.Name(),
			Type: cipherTypeName(c.Type()),
		})
	}
	printList(results)
	return nil
}

func runCipherGet(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	id := cmd.Args().First()
	if id == "" {
		return fmt.Errorf("cipher ID is required")
	}
	c, err := appCtx.Client.GetCipher(id)
	if err != nil {
		return err
	}
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
	return nil
}

func runCipherCreate(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	v := appCtx.Client
	c, err := vault.NewCipher(cmd.Int("type"), cmd.String("name"), v.SymmetricKey())
	if err != nil {
		return err
	}
	if cmd.IsSet("notes") {
		if err := c.SetNotes(cmd.String("notes")); err != nil {
			return err
		}
	}
	if cmd.IsSet("login-username") {
		if err := c.SetLoginUsername(cmd.String("login-username")); err != nil {
			return err
		}
	}
	if cmd.IsSet("login-password") {
		if err := c.SetLoginPassword(cmd.String("login-password")); err != nil {
			return err
		}
	}
	if cmd.IsSet("url") {
		if err := c.SetLoginURLs(cmd.StringSlice("url")); err != nil {
			return err
		}
	}
	if cmd.IsSet("field") {
		for _, field := range cmd.StringSlice("field") {
			parts := strings.SplitN(field, "=", 2)
			if len(parts) == 2 {
				if err := c.AddField(parts[0], parts[1], 0); err != nil {
					return err
				}
			}
		}
	}
	if err := v.CreateCipher(c); err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Created cipher: %s", c.ID()), ID: c.ID()})
	return nil
}

func runCipherUpdate(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	v := appCtx.Client
	id := cmd.String("id")
	c, err := v.GetCipher(id)
	if err != nil {
		return err
	}
	if cmd.IsSet("name") {
		if err := c.SetName(cmd.String("name")); err != nil {
			return err
		}
	}
	if cmd.IsSet("notes") {
		if err := c.SetNotes(cmd.String("notes")); err != nil {
			return err
		}
	}
	if cmd.IsSet("login-username") {
		if err := c.SetLoginUsername(cmd.String("login-username")); err != nil {
			return err
		}
	}
	if cmd.IsSet("login-password") {
		if err := c.SetLoginPassword(cmd.String("login-password")); err != nil {
			return err
		}
	}
	if cmd.IsSet("url") {
		if err := c.SetLoginURLs(cmd.StringSlice("url")); err != nil {
			return err
		}
	}
	if cmd.IsSet("field") {
		for _, field := range cmd.StringSlice("field") {
			parts := strings.SplitN(field, "=", 2)
			if len(parts) == 2 {
				if err := c.AddField(parts[0], parts[1], 0); err != nil {
					return err
				}
			}
		}
	}
	if err := v.UpdateCipher(c); err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Updated cipher: %s", c.ID()), ID: c.ID()})
	return nil
}

func runCipherDelete(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	id := cmd.Args().First()
	if id == "" {
		return fmt.Errorf("cipher ID is required")
	}
	if err := appCtx.Client.DeleteCipher(id); err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Deleted cipher: %s", id), ID: id})
	return nil
}
