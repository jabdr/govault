package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jabdr/govault/pkg/vault"
)

type appContextKey struct{}

// AppContext holds the Vault client and any other global-level state
type AppContext struct {
	Client   *vault.Vault
	Password string
	Server   string
	Insecure bool
	Logger   *slog.Logger
}

// GetAppCtx retrieves the full AppContext from the context.
func GetAppCtx(ctx context.Context) (*AppContext, error) {
	if appCtx, ok := ctx.Value(appContextKey{}).(*AppContext); ok {
		return appCtx, nil
	}
	return nil, fmt.Errorf("app context not found")
}

// GetAppClient directly retrieves the Vault client from context.
func GetAppClient(ctx context.Context) (*vault.Vault, error) {
	appCtx, err := GetAppCtx(ctx)
	if err != nil {
		return nil, err
	}
	return appCtx.Client, nil
}

// SetAppCtx stores the AppContext into the given context.
func SetAppCtx(ctx context.Context, appCtx *AppContext) context.Context {
	return context.WithValue(ctx, appContextKey{}, appCtx)
}
