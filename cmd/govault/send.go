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
			{Name: "list", Usage: "List sends", Action: runSendList},
			{
				Name:  "create",
				Usage: "Create a send",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Usage: "Send name (defaults to file name or 'Text Send')"},
					&cli.StringFlag{Name: "text", Usage: "Send text content"},
					&cli.StringFlag{Name: "file", Usage: "Path to file to upload"},
				},
				Action: runSendCreate,
			},
			{Name: "get", Usage: "Get a send by ID", Action: runSendGet},
			{Name: "delete", Usage: "Delete a send", Action: runSendDelete},
		},
	}
}

func runSendList(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	sends, err := appCtx.Client.ListSends()
	if err != nil {
		return err
	}
	results := make([]SendResult, 0, len(sends))
	for _, s := range sends {
		results = append(results, SendResult{
			ID: s.ID, Name: s.Name, FileName: s.FileName, URL: s.URL,
			AccessCount: s.AccessCount, MaxAccessCount: s.MaxAccessCount,
		})
	}
	printList(results)
	return nil
}

func runSendCreate(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	v := appCtx.Client
	text := cmd.String("text")
	filePath := cmd.String("file")
	name := cmd.String("name")

	if text == "" && filePath == "" {
		return fmt.Errorf("either --text or --file must be provided")
	}

	var s *vault.Send
	var accessURL string

	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return err
		}
		fileName := filepath.Base(filePath)
		if name == "" {
			name = fileName
		}
		s, accessURL, err = v.CreateFileSend(name, fileName, data, vault.SendOptions{})
		if err != nil {
			return err
		}
	} else {
		if name == "" {
			name = "Text Send"
		}
		s, accessURL, err = v.CreateTextSend(name, text, vault.SendOptions{})
		if err != nil {
			return err
		}
	}

	printOutput(MessageResult{Message: fmt.Sprintf("Created send: %s", s.ID), ID: s.ID, URL: accessURL})
	return nil
}

func runSendGet(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	id := cmd.Args().First()
	if id == "" {
		return fmt.Errorf("send ID is required")
	}
	sends, err := appCtx.Client.ListSends()
	if err != nil {
		return err
	}
	var send *vault.Send
	for _, s := range sends {
		if s.ID == id {
			send = s
			break
		}
	}
	if send == nil {
		printOutput(MessageResult{Message: fmt.Sprintf("Send not found: %s", id)})
		return nil
	}
	result := SendResult{
		ID: send.ID, Name: send.Name, FileName: send.FileName,
		URL: send.URL, AccessCount: send.AccessCount,
	}
	if send.Type == vault.SendTypeText {
		result.Text = send.Text
	}
	printOutput(result)
	return nil
}

func runSendDelete(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	id := cmd.Args().First()
	if id == "" {
		return fmt.Errorf("send ID is required")
	}
	if err := appCtx.Client.DeleteSend(id); err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Deleted send: %s", id), ID: id})
	return nil
}
