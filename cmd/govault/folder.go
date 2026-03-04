package main

import (
	"context"
	"fmt"

	"github.com/jabdr/govault/pkg/vault"
	"github.com/urfave/cli/v3"
)

func folderCmd() *cli.Command {
	return &cli.Command{
		Name:  "folder",
		Usage: "Manage folders",
		Commands: []*cli.Command{
			{
				Name:  "list",
				Usage: "List folders",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

					actionFolderList(vClient)
					return nil
				},
			},
			{
				Name:  "create",
				Usage: "Create a folder",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true, Usage: "Folder name"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

					actionFolderCreate(vClient, cmd.String("name"))
					return nil
				},
			},
			{
				Name:  "update",
				Usage: "Rename a folder",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Required: true, Usage: "Folder ID"},
					&cli.StringFlag{Name: "name", Required: true, Usage: "New folder name"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

					actionFolderUpdate(vClient, cmd.String("id"), cmd.String("name"))
					return nil
				},
			},
			{
				Name:  "delete",
				Usage: "Delete a folder",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					appCtx, err := GetAppCtx(ctx)
					if err != nil {
						return err
					}
					vClient := appCtx.Client

					id := cmd.Args().First()
					if id == "" {
						return fmt.Errorf("folder ID is required")
					}
					actionFolderDelete(vClient, id)
					return nil
				},
			},
		},
	}
}

func actionFolderList(v *vault.Vault) {
	folders, err := v.ListFolders()
	exitOnErr(err)
	results := make([]FolderResult, 0, len(folders))
	for _, f := range folders {
		results = append(results, FolderResult{ID: f.ID, Name: f.Name})
	}
	if len(results) == 0 {
		printOutput(MessageResult{Message: "No folders found."})
		return
	}
	printList(results)
}

func actionFolderCreate(v *vault.Vault, name string) {
	f, err := v.CreateFolder(name)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Created folder: %s", name), ID: f.ID})
}

func actionFolderUpdate(v *vault.Vault, id, name string) {
	f, err := v.UpdateFolder(id, name)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Renamed folder to: %s", name), ID: f.ID})
}

func actionFolderDelete(v *vault.Vault, id string) {
	err := v.DeleteFolder(id)
	exitOnErr(err)
	printOutput(MessageResult{Message: fmt.Sprintf("Deleted folder: %s", id), ID: id})
}
