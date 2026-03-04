package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jabdr/govault/pkg/vault"
	"github.com/urfave/cli/v3"
)

func sendCmd() *cli.Command {
	return &cli.Command{
		Name:  "send",
		Usage: "Manage sends",
		Commands: []*cli.Command{
			{
				Name:  "list",
				Usage: "List sends",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

					actionSends(vClient)
					return nil
				},
			},
			{
				Name:  "create",
				Usage: "Create a send",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Usage: "Send name (defaults to file name or 'Text Send')"},
					&cli.StringFlag{Name: "text", Usage: "Send text content"},
					&cli.StringFlag{Name: "file", Usage: "Path to file to upload"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

					actionSendCreate(vClient, cmd.String("name"), cmd.String("text"), cmd.String("file"))
					return nil
				},
			},
			{
				Name:  "get",
				Usage: "Get a send by ID",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

					id := cmd.Args().First()
					if id == "" {
						return fmt.Errorf("send ID is required")
					}
					actionSendGet(vClient, id)
					return nil
				},
			},
			{
				Name:  "delete",
				Usage: "Delete a send",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

					id := cmd.Args().First()
					if id == "" {
						return fmt.Errorf("send ID is required")
					}
					actionSendDelete(vClient, id)
					return nil
				},
			},
		},
	}
}

func actionSends(v *vault.Vault) {
	sends, err := v.ListSends()
	exitOnErr(err)
	results := make([]SendResult, 0, len(sends))
	for _, s := range sends {
		results = append(results, SendResult{
			ID:             s.ID,
			Name:           s.Name,
			FileName:       s.FileName,
			URL:            s.URL,
			AccessCount:    s.AccessCount,
			MaxAccessCount: s.MaxAccessCount,
		})
	}
	printList(results)
}

func actionSendCreate(v *vault.Vault, name, text, filePath string) {
	if text == "" && filePath == "" {
		exitOnErr(fmt.Errorf("either --text or --file must be provided"))
	}

	var s *vault.Send
	var accessURL string
	var err error

	if filePath != "" {
		data, err := os.ReadFile(filePath)
		exitOnErr(err)
		fileName := filepath.Base(filePath)
		if name == "" {
			name = fileName
		}
		s, accessURL, err = v.CreateFileSend(name, fileName, data, vault.SendOptions{})
		exitOnErr(err)
	} else {
		if name == "" {
			name = "Text Send"
		}
		s, accessURL, err = v.CreateTextSend(name, text, vault.SendOptions{})
		exitOnErr(err)
	}

	printOutput(MessageResult{Message: fmt.Sprintf("Created send: %s", s.ID), ID: s.ID, URL: accessURL})
}

func actionSendGet(v *vault.Vault, id string) {
	sends, err := v.ListSends()
	exitOnErr(err)
	var send *vault.Send
	for _, s := range sends {
		if s.ID == id {
			send = s
			break
		}
	}
	if send == nil {
		printOutput(MessageResult{Message: fmt.Sprintf("Send not found: %s", id)})
		return
	}
	result := SendResult{
		ID:          send.ID,
		Name:        send.Name,
		FileName:    send.FileName,
		URL:         send.URL,
		AccessCount: send.AccessCount,
	}
	if send.Type == vault.SendTypeText {
		result.Text = send.Text
	}
	printOutput(result)
}

func actionSendDelete(v *vault.Vault, id string) {
	err := v.DeleteSend(id)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Deleted send: %s", id), ID: id})
}
