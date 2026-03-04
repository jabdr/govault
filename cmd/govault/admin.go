package main

import (
	"context"
	"fmt"

	"github.com/jabdr/govault/pkg/vault"
	"github.com/urfave/cli/v3"
)

func adminCmd() *cli.Command {
	return &cli.Command{
		Name:  "admin",
		Usage: "Vaultwarden admin API operations (uses admin token, not user credentials)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "admin-token",
				Usage:    "Vaultwarden admin token",
				Sources:  cli.EnvVars("GOVAULT_ADMIN_TOKEN"),
				Required: true,
			},
		},
		Commands: []*cli.Command{
			adminUserCmd(),
			adminOrgCmd(),
		},
	}
}

func newAdminClient(ctx context.Context, cmd *cli.Command) (*vault.Admin, error) {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return nil, err
	}
	if appCtx.Server == "" {
		return nil, fmt.Errorf("server is required")
	}
	adminToken := cmd.String("admin-token")
	return vault.NewAdmin(appCtx.Server, adminToken, appCtx.Insecure, appCtx.Logger)
}

func adminUserCmd() *cli.Command {
	return &cli.Command{
		Name:  "user",
		Usage: "Manage users via admin API",
		Commands: []*cli.Command{
			{Name: "list", Usage: "List all users", Action: runAdminUserList},
			{Name: "get", Usage: "Get a user by ID", Action: runAdminUserGet},
			{
				Name: "invite", Usage: "Invite a user by email",
				Flags:  []cli.Flag{&cli.StringFlag{Name: "email", Required: true, Usage: "Email to invite"}},
				Action: runAdminUserInvite,
			},
			{
				Name: "reinvite", Usage: "Re-send invitation email for a user",
				Flags:  []cli.Flag{&cli.StringFlag{Name: "id", Required: true, Usage: "User ID"}},
				Action: runAdminUserReinvite,
			},
			{
				Name: "disable", Usage: "Disable a user",
				Flags:  []cli.Flag{&cli.StringFlag{Name: "id", Required: true, Usage: "User ID"}},
				Action: runAdminUserDisable,
			},
			{
				Name: "enable", Usage: "Enable a user",
				Flags:  []cli.Flag{&cli.StringFlag{Name: "id", Required: true, Usage: "User ID"}},
				Action: runAdminUserEnable,
			},
			{
				Name: "deauth", Usage: "Deauthorize all sessions for a user",
				Flags:  []cli.Flag{&cli.StringFlag{Name: "id", Required: true, Usage: "User ID"}},
				Action: runAdminUserDeauth,
			},
			{
				Name: "remove-2fa", Usage: "Remove two-factor authentication for a user",
				Flags:  []cli.Flag{&cli.StringFlag{Name: "id", Required: true, Usage: "User ID"}},
				Action: runAdminUserRemove2FA,
			},
			{
				Name: "delete", Usage: "Delete a user",
				Flags:  []cli.Flag{&cli.StringFlag{Name: "id", Required: true, Usage: "User ID"}},
				Action: runAdminUserDelete,
			},
		},
	}
}

func adminOrgCmd() *cli.Command {
	return &cli.Command{
		Name:  "org",
		Usage: "Manage organizations via admin API",
		Commands: []*cli.Command{
			{Name: "list", Usage: "List all organizations", Action: runAdminOrgList},
			{
				Name: "delete", Usage: "Delete an organization",
				Flags:  []cli.Flag{&cli.StringFlag{Name: "id", Required: true, Usage: "Organization ID"}},
				Action: runAdminOrgDelete,
			},
		},
	}
}

func runAdminUserList(ctx context.Context, cmd *cli.Command) error {
	adm, err := newAdminClient(ctx, cmd)
	if err != nil {
		return err
	}
	users, err := adm.ListUsers()
	if err != nil {
		return err
	}
	results := make([]AdminUserResult, 0, len(users))
	for _, u := range users {
		results = append(results, AdminUserResult{
			ID: u.ID, Email: u.Email, Name: u.Name,
			Enabled: u.Enabled, EmailVerified: u.EmailVerified,
			TwoFactorEnabled: u.TwoFactorEnabled,
			CreatedAt:        u.CreatedAt, LastActive: u.LastActive,
		})
	}
	printList(results)
	return nil
}

func runAdminUserGet(ctx context.Context, cmd *cli.Command) error {
	id := cmd.Args().First()
	if id == "" {
		return fmt.Errorf("user ID is required")
	}
	adm, err := newAdminClient(ctx, cmd)
	if err != nil {
		return err
	}
	u, err := adm.GetUser(id)
	if err != nil {
		return err
	}
	printOutput(AdminUserResult{
		ID: u.ID, Email: u.Email, Name: u.Name,
		Enabled: u.Enabled, EmailVerified: u.EmailVerified,
		TwoFactorEnabled: u.TwoFactorEnabled,
		CreatedAt:        u.CreatedAt, LastActive: u.LastActive,
	})
	return nil
}

func runAdminUserInvite(ctx context.Context, cmd *cli.Command) error {
	adm, err := newAdminClient(ctx, cmd)
	if err != nil {
		return err
	}
	email := cmd.String("email")
	if err := adm.InviteUser(email); err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Invited %s", email)})
	return nil
}

func runAdminUserReinvite(ctx context.Context, cmd *cli.Command) error {
	adm, err := newAdminClient(ctx, cmd)
	if err != nil {
		return err
	}
	if err := adm.ResendInvite(cmd.String("id")); err != nil {
		return err
	}
	printOutput(MessageResult{Message: "Invitation re-sent"})
	return nil
}

func runAdminUserDisable(ctx context.Context, cmd *cli.Command) error {
	adm, err := newAdminClient(ctx, cmd)
	if err != nil {
		return err
	}
	if err := adm.DisableUser(cmd.String("id")); err != nil {
		return err
	}
	printOutput(MessageResult{Message: "User disabled"})
	return nil
}

func runAdminUserEnable(ctx context.Context, cmd *cli.Command) error {
	adm, err := newAdminClient(ctx, cmd)
	if err != nil {
		return err
	}
	if err := adm.EnableUser(cmd.String("id")); err != nil {
		return err
	}
	printOutput(MessageResult{Message: "User enabled"})
	return nil
}

func runAdminUserDeauth(ctx context.Context, cmd *cli.Command) error {
	adm, err := newAdminClient(ctx, cmd)
	if err != nil {
		return err
	}
	if err := adm.DeauthUser(cmd.String("id")); err != nil {
		return err
	}
	printOutput(MessageResult{Message: "User deauthorized"})
	return nil
}

func runAdminUserRemove2FA(ctx context.Context, cmd *cli.Command) error {
	adm, err := newAdminClient(ctx, cmd)
	if err != nil {
		return err
	}
	if err := adm.Remove2FA(cmd.String("id")); err != nil {
		return err
	}
	printOutput(MessageResult{Message: "2FA removed"})
	return nil
}

func runAdminUserDelete(ctx context.Context, cmd *cli.Command) error {
	adm, err := newAdminClient(ctx, cmd)
	if err != nil {
		return err
	}
	if err := adm.DeleteUser(cmd.String("id")); err != nil {
		return err
	}
	printOutput(MessageResult{Message: "User deleted"})
	return nil
}

func runAdminOrgList(ctx context.Context, cmd *cli.Command) error {
	adm, err := newAdminClient(ctx, cmd)
	if err != nil {
		return err
	}
	orgs, err := adm.ListOrganizations()
	if err != nil {
		return err
	}
	results := make([]AdminOrgResult, 0, len(orgs))
	for _, o := range orgs {
		results = append(results, AdminOrgResult{ID: o.ID, Name: o.Name, BillingEmail: o.BillingEmail})
	}
	printList(results)
	return nil
}

func runAdminOrgDelete(ctx context.Context, cmd *cli.Command) error {
	adm, err := newAdminClient(ctx, cmd)
	if err != nil {
		return err
	}
	if err := adm.DeleteOrganization(cmd.String("id")); err != nil {
		return err
	}
	printOutput(MessageResult{Message: "Organization deleted"})
	return nil
}
