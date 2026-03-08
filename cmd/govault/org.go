package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/jabdr/govault/pkg/vault"
	"github.com/urfave/cli/v3"
)

func orgCmd() *cli.Command {
	return &cli.Command{
		Name:  "org",
		Usage: "Manage organizations",
		Commands: []*cli.Command{
			{Name: "list", Usage: "List accessible organizations", Action: runOrgList},
			{
				Name:  "create",
				Usage: "Create an organization",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true, Usage: "Organization name"},
					&cli.StringFlag{Name: "billing-email", Required: true, Usage: "Billing email address"},
					&cli.StringFlag{Name: "collection-name", Value: "Default Collection", Usage: "Name of the default collection"},
				},
				Action: runOrgCreate,
			},
			{
				Name:  "invite",
				Usage: "Invite an email to an organization",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Required: true, Usage: "Organization ID"},
					&cli.StringFlag{Name: "email", Required: true, Usage: "Email(s) to invite (comma-separated)"},
					&cli.StringFlag{Name: "type", Value: "user", Usage: "Member role: owner, admin, user, manager"},
				},
				Action: runOrgInvite,
			},
			{
				Name:  "confirm",
				Usage: "Confirm an organization invitation",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Required: true, Usage: "Organization ID"},
					&cli.StringFlag{Name: "member-id", Required: true, Usage: "Member ID"},
				},
				Action: runOrgConfirm,
			},
			{
				Name:  "get-api-key",
				Usage: "Get the organization API key for use with the Public API",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Required: true, Usage: "Organization ID"},
				},
				Action: runOrgGetAPIKey,
			},
			{
				Name:  "member",
				Usage: "Manage organization members",
				Commands: []*cli.Command{
					{
						Name:  "list",
						Usage: "List organization members",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "id", Required: true, Usage: "Organization ID"},
						},
						Action: runOrgMembers,
					},
					{
						Name:  "edit",
						Usage: "Edit an organization member's role",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "id", Required: true, Usage: "Organization ID"},
							&cli.StringFlag{Name: "member-id", Required: true, Usage: "Member ID or email"},
							&cli.StringFlag{Name: "type", Required: true, Usage: "Member role: owner, admin, user, manager"},
						},
						Action: runOrgEditMember,
					},
					{
						Name:  "remove",
						Usage: "Remove a member from an organization",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "id", Required: true, Usage: "Organization ID"},
							&cli.StringFlag{Name: "member-id", Required: true, Usage: "Member ID or email"},
						},
						Action: runOrgRemoveMember,
					},
				},
			},
		},
	}
}

func runOrgList(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	orgs, err := appCtx.Client.ListOrganizations()
	if err != nil {
		return err
	}
	results := make([]OrgResult, 0, len(orgs))
	for _, o := range orgs {
		results = append(results, OrgResult{ID: o.ID, Name: o.Name})
	}
	printList(results)
	return nil
}

func runOrgCreate(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	orgID, err := appCtx.Client.CreateOrganization(cmd.String("name"), cmd.String("billing-email"), cmd.String("collection-name"))
	if err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Created organization: %s", orgID), ID: orgID})
	return nil
}

func runOrgMembers(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	members, err := appCtx.Client.ListOrgMembers(cmd.String("id"))
	if err != nil {
		return err
	}
	results := make([]OrgMemberResult, 0, len(members))
	for _, m := range members {
		results = append(results, OrgMemberResult{
			ID:       m.ID,
			Email:    m.Email,
			Status:   m.Status,
			Type:     m.Type,
			RoleName: vault.MemberTypeName(m.Type),
		})
	}
	printList(results)
	return nil
}

func runOrgInvite(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	emailList := strings.Split(cmd.String("email"), ",")
	for i, e := range emailList {
		emailList[i] = strings.TrimSpace(e)
	}
	memberType, err := vault.ParseMemberType(cmd.String("type"))
	if err != nil {
		return err
	}
	if err := appCtx.Client.InviteToOrganization(cmd.String("id"), emailList, memberType); err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Invited %d user(s) to org %s as %s", len(emailList), cmd.String("id"), vault.MemberTypeName(memberType))})
	return nil
}

func runOrgConfirm(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	orgID := cmd.String("id")
	memberID := cmd.String("member-id")
	if err := appCtx.Client.ConfirmMember(orgID, memberID); err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Confirmed member %s in org %s", memberID, orgID), ID: memberID})
	return nil
}

func runOrgGetAPIKey(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	clientID, secret, err := appCtx.Client.GetOrgAPIKey(cmd.String("id"))
	if err != nil {
		return err
	}
	printOutput(APIKeyResult{ClientID: clientID, ClientSecret: secret})
	return nil
}

func runOrgEditMember(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	orgID := cmd.String("id")
	memberIDOrEmail := cmd.String("member-id")
	memberType, err := vault.ParseMemberType(cmd.String("type"))
	if err != nil {
		return err
	}

	// Resolve email to member ID if needed
	memberID := memberIDOrEmail
	if strings.Contains(memberIDOrEmail, "@") {
		members, err := appCtx.Client.ListOrgMembers(orgID)
		if err != nil {
			return err
		}
		found := false
		for _, m := range members {
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

	if err := appCtx.Client.EditMember(orgID, memberID, memberType); err != nil {
		return err
	}
	printOutput(MessageResult{
		Message: fmt.Sprintf("Updated member %s to role %s in org %s", memberID, vault.MemberTypeName(memberType), orgID),
		ID:      memberID,
	})
	return nil
}

func runOrgRemoveMember(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	orgID := cmd.String("id")
	memberIDOrEmail := cmd.String("member-id")

	// Resolve email to member ID if needed
	memberID := memberIDOrEmail
	if strings.Contains(memberIDOrEmail, "@") {
		members, err := appCtx.Client.ListOrgMembers(orgID)
		if err != nil {
			return err
		}
		found := false
		for _, m := range members {
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

	if err := appCtx.Client.RemoveMember(orgID, memberID); err != nil {
		return err
	}
	printOutput(MessageResult{
		Message: fmt.Sprintf("Removed member %s from org %s", memberID, orgID),
		ID:      memberID,
	})
	return nil
}
