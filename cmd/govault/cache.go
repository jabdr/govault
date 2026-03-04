package main

import (
	"context"
	"fmt"

	"github.com/jabdr/govault/pkg/vault"
	"github.com/urfave/cli/v3"
)

func cacheCmd() *cli.Command {
	return &cli.Command{
		Name:  "cache",
		Usage: "Manage and query the local cache file",
		Commands: []*cli.Command{
			{Name: "sync", Usage: "Authenticate, sync the vault, and write to the cache file", Action: runCacheSync},
			{
				Name:  "cipher",
				Usage: "Query cached ciphers (offline)",
				Commands: []*cli.Command{
					{Name: "list", Usage: "List ciphers from cache", Action: runCacheCipherList},
					{Name: "get", Usage: "Get a specific cipher by ID from cache", Action: runCacheCipherGet},
				},
			},
			{
				Name:  "collection",
				Usage: "Query cached collections (offline)",
				Commands: []*cli.Command{
					{
						Name:  "list",
						Usage: "List collections in an organization from cache",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "org-id", Required: true, Usage: "Organization ID"},
						},
						Action: runCacheCollectionList,
					},
				},
			},
			{
				Name:  "org",
				Usage: "Query cached organizations (offline)",
				Commands: []*cli.Command{
					{Name: "list", Usage: "List accessible organizations from cache", Action: runCacheOrgList},
				},
			},
		},
	}
}

// getCacheFile resolves the --cache-file flag from the root command.
func getCacheFile(cmd *cli.Command) (string, error) {
	cacheFile := cmd.Root().String("cache-file")
	if cacheFile == "" {
		return "", fmt.Errorf("global --cache-file must be specified for cache operations")
	}
	return cacheFile, nil
}

// getOfflineClient builds an offline vault from the cache file.
func getOfflineClient(ctx context.Context, cmd *cli.Command) (*vault.Vault, error) {
	cacheFile, err := getCacheFile(cmd)
	if err != nil {
		return nil, err
	}
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return nil, err
	}
	if appCtx.Email == "" || appCtx.Password == "" {
		return nil, fmt.Errorf("email and password are required for offline cache access")
	}
	return vault.LoadCache(cacheFile, appCtx.Email, appCtx.Password, appCtx.Insecure, appCtx.Logger)
}

func runCacheSync(ctx context.Context, cmd *cli.Command) error {
	cacheFile, err := getCacheFile(cmd)
	if err != nil {
		return err
	}
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return err
	}

	// The cache sync command needs a live vault connection, so we login here.
	var v *vault.Vault
	clientID := cmd.Root().String("client-id")
	clientSecret := cmd.Root().String("client-secret")

	if clientID != "" && clientSecret != "" {
		v, err = vault.LoginAPIKey(appCtx.Server, clientID, clientSecret, appCtx.Email, appCtx.Password, appCtx.Insecure, appCtx.Logger)
	} else if appCtx.Email != "" && appCtx.Password != "" {
		v, err = vault.Login(appCtx.Server, appCtx.Email, appCtx.Password, appCtx.Insecure, appCtx.Logger)
	} else {
		return fmt.Errorf("credentials are required for cache sync")
	}
	if err != nil {
		return err
	}

	if err := v.SaveCache(cacheFile); err != nil {
		return fmt.Errorf("failed to save cache: %w", err)
	}
	printOutput(MessageResult{Message: "Cache saved successfully"})
	return nil
}

func runCacheCipherList(ctx context.Context, cmd *cli.Command) error {
	cachedVault, err := getOfflineClient(ctx, cmd)
	if err != nil {
		return err
	}
	ciphers, err := cachedVault.ListCiphers()
	if err != nil {
		return err
	}
	results := make([]CipherResult, 0, len(ciphers))
	for _, c := range ciphers {
		results = append(results, CipherResult{
			ID:   c.ID(),
			Name: c.Name(),
			Type: cipherTypeName(c.Type()),
		})
	}
	printList(results)
	return nil
}

func runCacheCipherGet(ctx context.Context, cmd *cli.Command) error {
	id := cmd.Args().First()
	if id == "" {
		return fmt.Errorf("cipher ID is required")
	}
	cachedVault, err := getOfflineClient(ctx, cmd)
	if err != nil {
		return err
	}
	c, err := cachedVault.GetCipher(id)
	if err != nil {
		return err
	}
	result := CipherResult{
		ID:   c.ID(),
		Name: c.Name(),
		Type: cipherTypeName(c.Type()),
	}
	if c.Type() == vault.CipherTypeLogin {
		if u, p, err := c.GetLogin(); err == nil {
			result.Username = u
			result.Password = p
		}
		if urls, err := c.GetLoginURLs(); err == nil && len(urls) > 0 {
			result.URLs = urls
		}
	}
	if notes := c.Notes(); notes != "" {
		result.Notes = notes
	}
	printOutput(result)
	return nil
}

func runCacheCollectionList(ctx context.Context, cmd *cli.Command) error {
	cachedVault, err := getOfflineClient(ctx, cmd)
	if err != nil {
		return err
	}
	orgID := cmd.String("org-id")
	cols, err := cachedVault.ListCollections(orgID)
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

func runCacheOrgList(ctx context.Context, cmd *cli.Command) error {
	cachedVault, err := getOfflineClient(ctx, cmd)
	if err != nil {
		return err
	}
	orgs, err := cachedVault.ListOrganizations()
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
