package main

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"
)

func folderCmd() *cli.Command {
	return &cli.Command{
		Name:  "folder",
		Usage: "Manage folders",
		Commands: []*cli.Command{
			{Name: "list", Usage: "List folders", Action: runFolderList},
			{
				Name:  "create",
				Usage: "Create a folder",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true, Usage: "Folder name"},
				},
				Action: runFolderCreate,
			},
			{
				Name:  "update",
				Usage: "Rename a folder",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Required: true, Usage: "Folder ID"},
					&cli.StringFlag{Name: "name", Required: true, Usage: "New folder name"},
				},
				Action: runFolderUpdate,
			},
			{Name: "delete", Usage: "Delete a folder", Action: runFolderDelete},
		},
	}
}

func runFolderList(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	folders, err := appCtx.Client.ListFolders()
	if err != nil {
		return err
	}
	results := make([]FolderResult, 0, len(folders))
	for _, f := range folders {
		results = append(results, FolderResult{ID: f.ID, Name: f.Name})
	}
	if len(results) == 0 {
		printOutput(MessageResult{Message: "No folders found."})
		return nil
	}
	printList(results)
	return nil
}

func runFolderCreate(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	f, err := appCtx.Client.CreateFolder(cmd.String("name"))
	if err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Created folder: %s", cmd.String("name")), ID: f.ID})
	return nil
}

func runFolderUpdate(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	f, err := appCtx.Client.UpdateFolder(cmd.String("id"), cmd.String("name"))
	if err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Renamed folder to: %s", cmd.String("name")), ID: f.ID})
	return nil
}

func runFolderDelete(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	id := cmd.Args().First()
	if id == "" {
		return fmt.Errorf("folder ID is required")
	}
	if err := appCtx.Client.DeleteFolder(id); err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Deleted folder: %s", id), ID: id})
	return nil
}
