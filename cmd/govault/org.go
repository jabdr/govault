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
			{
				Name:  "list",
				Usage: "List accessible organizations",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

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
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

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
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

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
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

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
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

					actionOrgConfirm(vClient, cmd.String("id"), cmd.String("member-id"))
					return nil
				},
			},
			{
				Name:  "get-api-key",
				Usage: "Get the organization API key for use with the Public API",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Required: true, Usage: "Organization ID"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

					clientID, secret, err := vClient.GetOrgAPIKey(cmd.String("id"))
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
