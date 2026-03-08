package main

import (
	"context"
	"fmt"
	"strings"

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
					&cli.StringFlag{Name: "email", Usage: "Member email(s) to add (comma-separated)"},
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
					&cli.StringFlag{Name: "email", Usage: "Set member email(s) (comma-separated, replaces existing)"},
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
			{
				Name:  "members",
				Usage: "List members of a group",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "org-id", Required: true, Usage: "Organization ID"},
					&cli.StringFlag{Name: "id", Required: true, Usage: "Group ID or Name"},
				},
				Action: runGroupMembers,
			},
			{
				Name:  "add-member",
				Usage: "Add members to a group by email",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "org-id", Required: true, Usage: "Organization ID"},
					&cli.StringFlag{Name: "id", Required: true, Usage: "Group ID or Name"},
					&cli.StringFlag{Name: "email", Required: true, Usage: "Email(s) to add (comma-separated)"},
				},
				Action: runGroupAddMember,
			},
			{
				Name:  "remove-member",
				Usage: "Remove a member from a group",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "org-id", Required: true, Usage: "Organization ID"},
					&cli.StringFlag{Name: "id", Required: true, Usage: "Group ID or Name"},
					&cli.StringFlag{Name: "member-id", Required: true, Usage: "Member ID or email"},
				},
				Action: runGroupRemoveMember,
			},
		},
	}
}

// resolveGroupID resolves a group ID or name to a group ID.
func resolveGroupID(ctx context.Context, cmd *cli.Command) (appCtx *AppContext, orgID, groupID string, err error) {
	appCtx, err = GetAppCtx(ctx)
	if err != nil {
		return nil, "", "", err
	}
	orgID = cmd.String("org-id")
	idOrName := cmd.String("id")

	groups, err := appCtx.Client.ListGroups(orgID)
	if err != nil {
		return nil, "", "", err
	}
	groupID = idOrName
	for _, g := range groups {
		if g.Name == idOrName {
			groupID = g.ID
			break
		}
	}
	return appCtx, orgID, groupID, nil
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
	var memberEmails []string
	if emailStr := cmd.String("email"); emailStr != "" {
		for _, e := range strings.Split(emailStr, ",") {
			memberEmails = append(memberEmails, strings.TrimSpace(e))
		}
	}
	grp, err := appCtx.Client.CreateGroup(cmd.String("org-id"), cmd.String("name"), cmd.Bool("access-all"), memberEmails)
	if err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Created Group: %s (ID: %s)", grp.Name, grp.ID), ID: grp.ID})
	return nil
}

func runGroupUpdate(ctx context.Context, cmd *cli.Command) error {
	appCtx, orgID, groupID, err := resolveGroupID(ctx, cmd)
	if err != nil {
		return err
	}
	// nil means "preserve existing members"; non-nil (even empty) means "replace"
	var memberEmails []string
	if emailStr := cmd.String("email"); emailStr != "" {
		memberEmails = make([]string, 0)
		for _, e := range strings.Split(emailStr, ",") {
			memberEmails = append(memberEmails, strings.TrimSpace(e))
		}
	}
	if err := appCtx.Client.UpdateGroup(orgID, groupID, cmd.String("name"), cmd.Bool("access-all"), memberEmails); err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Updated Group: %s", groupID), ID: groupID})
	return nil
}

func runGroupDelete(ctx context.Context, cmd *cli.Command) error {
	appCtx, orgID, groupID, err := resolveGroupID(ctx, cmd)
	if err != nil {
		return err
	}
	if err := appCtx.Client.DeleteGroup(orgID, groupID); err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Deleted Group: %s", groupID), ID: groupID})
	return nil
}

func runGroupMembers(ctx context.Context, cmd *cli.Command) error {
	appCtx, orgID, groupID, err := resolveGroupID(ctx, cmd)
	if err != nil {
		return err
	}
	members, err := appCtx.Client.ListGroupMembers(orgID, groupID)
	if err != nil {
		return err
	}
	if len(members) == 0 {
		printOutput(MessageResult{Message: "No members in group."})
		return nil
	}
	results := make([]GroupMemberResult, 0, len(members))
	for _, m := range members {
		results = append(results, GroupMemberResult{ID: m.ID, Email: m.Email})
	}
	printList(results)
	return nil
}

func runGroupAddMember(ctx context.Context, cmd *cli.Command) error {
	appCtx, orgID, groupID, err := resolveGroupID(ctx, cmd)
	if err != nil {
		return err
	}
	emailList := strings.Split(cmd.String("email"), ",")
	for i, e := range emailList {
		emailList[i] = strings.TrimSpace(e)
	}
	if err := appCtx.Client.AddGroupMembers(orgID, groupID, emailList); err != nil {
		return err
	}
	printOutput(MessageResult{
		Message: fmt.Sprintf("Added %d member(s) to group %s", len(emailList), groupID),
		ID:      groupID,
	})
	return nil
}

func runGroupRemoveMember(ctx context.Context, cmd *cli.Command) error {
	appCtx, orgID, groupID, err := resolveGroupID(ctx, cmd)
	if err != nil {
		return err
	}
	memberIDOrEmail := cmd.String("member-id")

	// If the value contains '@', treat it as an email and resolve to member ID
	memberID := memberIDOrEmail
	if strings.Contains(memberIDOrEmail, "@") {
		orgMembers, err := appCtx.Client.ListOrgMembers(orgID)
		if err != nil {
			return err
		}
		found := false
		for _, m := range orgMembers {
			if m.Email == memberIDOrEmail {
				memberID = m.ID
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("member with email %q not found in organization", memberIDOrEmail)
		}
	}

	if err := appCtx.Client.RemoveGroupMember(orgID, groupID, memberID); err != nil {
		return err
	}
	printOutput(MessageResult{
		Message: fmt.Sprintf("Removed member %s from group %s", memberID, groupID),
		ID:      memberID,
	})
	return nil
}
