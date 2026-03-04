package main

import (
	"context"
	"fmt"

	"github.com/jabdr/govault/pkg/vault"
	"github.com/urfave/cli/v3"
)

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
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

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
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

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
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

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
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

					actionGroupDelete(vClient, cmd.String("org-id"), cmd.String("id"))
					return nil
				},
			},
		},
	}
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
