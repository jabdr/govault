package main

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"
)

func emergencyCmd() *cli.Command {
	return &cli.Command{
		Name:  "emergency",
		Usage: "Manage emergency access",
		Commands: []*cli.Command{
			{Name: "trusted", Usage: "List trusted emergency contacts", Action: runEmergencyTrusted},
			{Name: "granted", Usage: "List granted emergency contacts", Action: runEmergencyGranted},
			{
				Name:  "invite",
				Usage: "Invite an emergency contact",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "email", Required: true, Usage: "Contact email"},
					&cli.IntFlag{Name: "type", Value: 0, Usage: "Access type (0=view, 1=takeover)"},
					&cli.IntFlag{Name: "wait", Value: 7, Usage: "Wait time in days"},
				},
				Action: runEmergencyInvite,
			},
			{
				Name: "confirm", Usage: "Confirm an emergency contact invitation",
				Flags:  []cli.Flag{&cli.StringFlag{Name: "id", Required: true, Usage: "Emergency Contact ID"}},
				Action: runEmergencyConfirm,
			},
			{
				Name: "initiate", Usage: "Initiate emergency access",
				Flags:  []cli.Flag{&cli.StringFlag{Name: "id", Required: true, Usage: "Emergency Contact ID"}},
				Action: runEmergencyInitiate,
			},
			{
				Name: "approve", Usage: "Approve emergency access request",
				Flags:  []cli.Flag{&cli.StringFlag{Name: "id", Required: true, Usage: "Emergency Contact ID"}},
				Action: runEmergencyApprove,
			},
			{
				Name: "reject", Usage: "Reject emergency access request",
				Flags:  []cli.Flag{&cli.StringFlag{Name: "id", Required: true, Usage: "Emergency Contact ID"}},
				Action: runEmergencyReject,
			},
			{
				Name: "view", Usage: "View ciphers from granted emergency access",
				Flags:  []cli.Flag{&cli.StringFlag{Name: "id", Required: true, Usage: "Emergency Contact ID"}},
				Action: runEmergencyView,
			},
			{
				Name:  "takeover",
				Usage: "Takeover an account via emergency access",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Required: true, Usage: "Emergency Contact ID"},
					&cli.StringFlag{Name: "new-password", Required: true, Usage: "New master password"},
				},
				Action: runEmergencyTakeover,
			},
		},
	}
}

func runEmergencyTrusted(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	contacts, err := appCtx.Client.ListTrustedEmergencyAccess()
	if err != nil {
		return err
	}
	results := make([]EmergencyContactResult, 0, len(contacts))
	for _, c := range contacts {
		results = append(results, EmergencyContactResult{ID: c.ID, Email: c.Email, Status: c.Status, Type: c.Type})
	}
	printList(results)
	return nil
}

func runEmergencyGranted(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	granted, err := appCtx.Client.ListGrantedEmergencyAccess()
	if err != nil {
		return err
	}
	results := make([]EmergencyContactResult, 0, len(granted))
	for _, g := range granted {
		results = append(results, EmergencyContactResult{ID: g.ID, Email: g.Email, Status: g.Status, Type: g.Type})
	}
	printList(results)
	return nil
}

func runEmergencyInvite(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	email := cmd.String("email")
	if err := appCtx.Client.InviteEmergencyAccess(email, int(cmd.Int("type")), int(cmd.Int("wait"))); err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Invited %s as emergency contact", email)})
	return nil
}

func runEmergencyConfirm(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	id := cmd.String("id")
	if err := appCtx.Client.ConfirmEmergencyAccess(id); err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Confirmed emergency contact %s", id), ID: id})
	return nil
}

func runEmergencyInitiate(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	id := cmd.String("id")
	if err := appCtx.Client.InitiateEmergencyAccess(id); err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Initiated emergency access for %s", id), ID: id})
	return nil
}

func runEmergencyApprove(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	id := cmd.String("id")
	if err := appCtx.Client.ApproveEmergencyAccess(id); err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Approved emergency access request %s", id), ID: id})
	return nil
}

func runEmergencyReject(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	id := cmd.String("id")
	if err := appCtx.Client.RejectEmergencyAccess(id); err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Rejected emergency access request %s", id), ID: id})
	return nil
}

func runEmergencyView(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	id := cmd.String("id")
	ciphers, err := appCtx.Client.ViewEmergencyVault(id)
	if err != nil {
		return err
	}
	results := make([]CipherResult, 0, len(ciphers))
	for _, c := range ciphers {
		results = append(results, CipherResult{ID: c.ID(), Name: c.Name(), Type: cipherTypeName(c.Type())})
	}
	printList(results)
	return nil
}

func runEmergencyTakeover(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	id := cmd.String("id")
	if err := appCtx.Client.TakeoverEmergencyAccess(id, cmd.String("new-password")); err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Emergency takeover successful for %s. New master password is set.", id), ID: id})
	return nil
}
