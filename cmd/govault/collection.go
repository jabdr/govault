package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/jabdr/govault/pkg/api"
	"github.com/urfave/cli/v3"
)

func collectionCmd() *cli.Command {
	return &cli.Command{
		Name:  "collection",
		Usage: "Manage collections",
		Commands: []*cli.Command{
			{
				Name:  "list",
				Usage: "List collections in an organization",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "org-id", Required: true, Usage: "Organization ID"},
				},
				Action: runCollectionList,
			},
			{
				Name:  "create",
				Usage: "Create a collection",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "org-id", Required: true, Usage: "Organization ID"},
					&cli.StringFlag{Name: "name", Required: true, Usage: "Collection Name"},
				},
				Action: runCollectionCreate,
			},
			{
				Name:  "update",
				Usage: "Update a collection",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "org-id", Required: true, Usage: "Organization ID"},
					&cli.StringFlag{Name: "id", Required: true, Usage: "Collection ID or Name"},
					&cli.StringFlag{Name: "users", Usage: "JSON array of user access for collection"},
					&cli.StringFlag{Name: "groups", Usage: "JSON array of group access for collection"},
				},
				Action: runCollectionUpdate,
			},
			{
				Name:  "delete",
				Usage: "Delete a collection",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "org-id", Required: true, Usage: "Organization ID"},
					&cli.StringFlag{Name: "id", Required: true, Usage: "Collection ID"},
				},
				Action: runCollectionDelete,
			},
		},
	}
}

func runCollectionList(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	cols, err := appCtx.Client.ListCollections(cmd.String("org-id"))
	if err != nil {
		return err
	}
	results := make([]CollectionResult, 0, len(cols))
	for _, c := range cols {
		results = append(results, CollectionResult{ID: c.ID, Name: c.Name})
	}
	printList(results)
	return nil
}

func runCollectionCreate(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	col, err := appCtx.Client.CreateCollection(cmd.String("org-id"), cmd.String("name"))
	if err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Created: %s", col.ID), ID: col.ID})
	return nil
}

func runCollectionUpdate(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	v := appCtx.Client
	orgID := cmd.String("org-id")

	cols, err := v.ListCollections(orgID)
	if err != nil {
		return err
	}

	collectionID := cmd.String("id")
	for _, c := range cols {
		if c.Name == collectionID {
			collectionID = c.ID
			break
		}
	}

	var parsedUsers []map[string]interface{}
	var parsedGroups []map[string]interface{}

	if reqUsers := cmd.String("users"); reqUsers != "" {
		if err := json.Unmarshal([]byte(reqUsers), &parsedUsers); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing --users JSON: %v\n", err)
			os.Exit(1)
		}
	}
	if reqGroups := cmd.String("groups"); reqGroups != "" {
		if err := json.Unmarshal([]byte(reqGroups), &parsedGroups); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing --groups JSON: %v\n", err)
			os.Exit(1)
		}
	}

	members, err := v.ListOrgMembers(orgID)
	if err != nil {
		return err
	}
	memberMap := make(map[string]string)
	for _, m := range members {
		memberMap[m.Email] = m.ID
	}

	groups, _ := v.ListGroups(orgID)
	groupMap := make(map[string]string)
	for _, g := range groups {
		groupMap[g.Name] = g.ID
	}

	var users []api.CollectionUserAccess
	var groupsAccess []api.CollectionGroupAccess

	for _, pu := range parsedUsers {
		id := pu["id"].(string)
		if email, ok := pu["email"].(string); ok && email != "" {
			if matchedID, found := memberMap[email]; found {
				id = matchedID
			}
		} else if emailOrID, ok := pu["id"].(string); ok {
			if matchedID, found := memberMap[emailOrID]; found {
				id = matchedID
			}
		}
		ro, _ := pu["readOnly"].(bool)
		hp, _ := pu["hidePasswords"].(bool)
		mng, _ := pu["manage"].(bool)
		users = append(users, api.CollectionUserAccess{ID: id, ReadOnly: ro, HidePasswords: hp, Manage: mng})
	}

	for _, pg := range parsedGroups {
		id := pg["id"].(string)
		if name, ok := pg["name"].(string); ok && name != "" {
			if matchedID, found := groupMap[name]; found {
				id = matchedID
			}
		} else if nameOrID, ok := pg["id"].(string); ok {
			if matchedID, found := groupMap[nameOrID]; found {
				id = matchedID
			}
		}
		ro, _ := pg["readOnly"].(bool)
		hp, _ := pg["hidePasswords"].(bool)
		mng, _ := pg["manage"].(bool)
		groupsAccess = append(groupsAccess, api.CollectionGroupAccess{ID: id, ReadOnly: ro, HidePasswords: hp, Manage: mng})
	}

	if err := v.UpdateCollectionPermissions(orgID, collectionID, groupsAccess, users); err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Collection permissions updated for %s", collectionID), ID: collectionID})
	return nil
}

func runCollectionDelete(ctx context.Context, cmd *cli.Command) error {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}
	orgID := cmd.String("org-id")
	collectionID := cmd.String("id")
	if err := appCtx.Client.DeleteCollection(orgID, collectionID); err != nil {
		return err
	}
	printOutput(MessageResult{Message: fmt.Sprintf("Deleted collection: %s", collectionID), ID: collectionID})
	return nil
}
