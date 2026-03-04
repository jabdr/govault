package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jabdr/govault/pkg/vault"
	"github.com/urfave/cli/v3"
)

func publicCmd() *cli.Command {
	return &cli.Command{
		Name:  "public",
		Usage: "Bitwarden/Vaultwarden Public API operations (uses organization API key)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "client-id",
				Usage:    "Organization client ID (format: organization.<org_uuid>)",
				Sources:  cli.EnvVars("GOVAULT_ORG_CLIENT_ID"),
				Required: true,
			},
			&cli.StringFlag{
				Name:     "client-secret",
				Usage:    "Organization client secret (API key)",
				Sources:  cli.EnvVars("GOVAULT_ORG_CLIENT_SECRET"),
				Required: true,
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "import",
				Usage: "Bulk import members (and optionally groups) into the organization",
				Flags: []cli.Flag{
					&cli.StringSliceFlag{Name: "member", Usage: "Member to import (format: email:externalId or just email)"},
					&cli.StringFlag{Name: "members-json", Usage: `JSON array of members [{"email":"...","externalId":"...","deleted":false}]`},
					&cli.StringFlag{Name: "groups-json", Usage: `JSON array of groups [{"name":"...","externalId":"...","memberExternalIds":["..."]}]`},
					&cli.BoolFlag{Name: "overwrite", Usage: "Remove members not in the import list"},
				},
				Action: runPublicImport,
			},
		},
	}
}

func runPublicImport(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	if appCtx.Server == "" {
		return fmt.Errorf("server is required")
	}

	pubClientID := cmd.String("client-id")
	pubClientSecret := cmd.String("client-secret")

	pub, err := vault.NewPublic(appCtx.Server, pubClientID, pubClientSecret, appCtx.Insecure, appCtx.Logger)
	if err != nil {
		return err
	}

	var members []vault.ImportMember
	var groups []vault.ImportGroup

	for _, m := range cmd.StringSlice("member") {
		parts := strings.SplitN(m, ":", 2)
		email := parts[0]
		extID := email
		if len(parts) == 2 {
			extID = parts[1]
		}
		members = append(members, vault.ImportMember{Email: email, ExternalID: extID})
	}

	if jsonStr := cmd.String("members-json"); jsonStr != "" {
		var jsonMembers []vault.ImportMember
		if err := json.Unmarshal([]byte(jsonStr), &jsonMembers); err != nil {
			return fmt.Errorf("invalid --members-json: %w", err)
		}
		members = append(members, jsonMembers...)
	}

	if jsonStr := cmd.String("groups-json"); jsonStr != "" {
		var jsonGroups []vault.ImportGroup
		if err := json.Unmarshal([]byte(jsonStr), &jsonGroups); err != nil {
			return fmt.Errorf("invalid --groups-json: %w", err)
		}
		groups = append(groups, jsonGroups...)
	}

	if len(members) == 0 {
		return fmt.Errorf("at least one member is required (use --member or --members-json)")
	}

	if err := pub.Import(members, groups, cmd.Bool("overwrite")); err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Imported %d members and %d groups", len(members), len(groups))})
	return nil
}
