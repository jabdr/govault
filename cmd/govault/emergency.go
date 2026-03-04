package main

import (
	"context"
	"fmt"

	"github.com/jabdr/govault/pkg/vault"
	"github.com/urfave/cli/v3"
)

func emergencyCmd() *cli.Command {
	return &cli.Command{
		Name:  "emergency",
		Usage: "Manage emergency access",
		Commands: []*cli.Command{
			{
				Name:  "trusted",
				Usage: "List trusted emergency contacts",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

					actionEmergencyTrusted(vClient)
					return nil
				},
			},
			{
				Name:  "granted",
				Usage: "List granted emergency contacts",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

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
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

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
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

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
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

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
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

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
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

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
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

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
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

					actionEmergencyTakeover(vClient, cmd.String("id"), cmd.String("new-password"))
					return nil
				},
			},
		},
	}
}

func actionEmergencyTrusted(v *vault.Vault) {
	contacts, err := v.ListTrustedEmergencyAccess()
	exitOnErr(err)
	results := make([]EmergencyContactResult, 0, len(contacts))
	for _, c := range contacts {
		results = append(results, EmergencyContactResult{ID: c.ID, Email: c.Email, Status: c.Status, Type: c.Type})
	}
	printList(results)
}

func actionEmergencyGranted(v *vault.Vault) {
	granted, err := v.ListGrantedEmergencyAccess()
	exitOnErr(err)
	results := make([]EmergencyContactResult, 0, len(granted))
	for _, g := range granted {
		results = append(results, EmergencyContactResult{ID: g.ID, Email: g.Email, Status: g.Status, Type: g.Type})
	}
	printList(results)
}

func actionEmergencyInvite(v *vault.Vault, email string, accessType, waitDays int) {
	err := v.InviteEmergencyAccess(email, accessType, waitDays)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Invited %s as emergency contact", email)})
}

func actionEmergencyConfirm(v *vault.Vault, id string) {
	err := v.ConfirmEmergencyAccess(id)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Confirmed emergency contact %s", id), ID: id})
}

func actionEmergencyInitiate(v *vault.Vault, id string) {
	err := v.InitiateEmergencyAccess(id)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Initiated emergency access for %s", id), ID: id})
}

func actionEmergencyApprove(v *vault.Vault, id string) {
	err := v.ApproveEmergencyAccess(id)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Approved emergency access request %s", id), ID: id})
}

func actionEmergencyReject(v *vault.Vault, id string) {
	err := v.RejectEmergencyAccess(id)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Rejected emergency access request %s", id), ID: id})
}

func actionEmergencyView(v *vault.Vault, id string) {
	ciphers, err := v.ViewEmergencyVault(id)
	exitOnErr(err)
	results := make([]CipherResult, 0, len(ciphers))
	for _, c := range ciphers {
		results = append(results, CipherResult{ID: c.ID(), Name: c.Name(), Type: cipherTypeName(c.Type())})
	}
	printList(results)
}

func actionEmergencyTakeover(v *vault.Vault, id, newPassword string) {
	err := v.TakeoverEmergencyAccess(id, newPassword)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Emergency takeover successful for %s. New master password is set.", id), ID: id})
}
