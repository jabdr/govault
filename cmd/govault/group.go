package main

import (
	"context"
	"fmt"

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
				Action: runGroupList,
			},
			{
				Name:  "create",
				Usage: "Create a group",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "org-id", Required: true, Usage: "Organization ID"},
					&cli.StringFlag{Name: "name", Required: true, Usage: "Group Name"},
					&cli.BoolFlag{Name: "access-all", Usage: "Access all collections"},
				},
				Action: runGroupCreate,
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
				Action: runGroupUpdate,
			},
			{
				Name:  "delete",
				Usage: "Delete a group",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "org-id", Required: true, Usage: "Organization ID"},
					&cli.StringFlag{Name: "id", Required: true, Usage: "Group ID or Name"},
				},
				Action: runGroupDelete,
			},
		},
	}
}

func runGroupList(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	groups, err := appCtx.Client.ListGroups(cmd.String("org-id"))
	if err != nil {
		return err
	}
	results := make([]GroupResult, 0, len(groups))
	for _, g := range groups {
		results = append(results, GroupResult{ID: g.ID, Name: g.Name, AccessAll: g.AccessAll})
	}
	if len(results) == 0 {
		printOutput(MessageResult{Message: "No groups found."})
		return nil
	}
	printList(results)
	return nil
}

func runGroupCreate(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	grp, err := appCtx.Client.CreateGroup(cmd.String("org-id"), cmd.String("name"), cmd.Bool("access-all"))
	if err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Created Group: %s (ID: %s)", grp.Name, grp.ID), ID: grp.ID})
	return nil
}

func runGroupUpdate(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	v := appCtx.Client
	orgID := cmd.String("org-id")
	idOrName := cmd.String("id")

	groups, err := v.ListGroups(orgID)
	if err != nil {
		return err
	}
	groupID := idOrName
	for _, g := range groups {
		if g.Name == idOrName {
			groupID = g.ID
			break
		}
	}

	if err := v.UpdateGroup(orgID, groupID, cmd.String("name"), cmd.Bool("access-all")); err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Updated Group: %s", groupID), ID: groupID})
	return nil
}

func runGroupDelete(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	v := appCtx.Client
	orgID := cmd.String("org-id")
	idOrName := cmd.String("id")

	groups, err := v.ListGroups(orgID)
	if err != nil {
		return err
	}
	groupID := idOrName
	for _, g := range groups {
		if g.Name == idOrName {
			groupID = g.ID
			break
		}
	}

	if err := v.DeleteGroup(orgID, groupID); err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Deleted Group: %s", groupID), ID: groupID})
	return nil
}
