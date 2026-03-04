package vault

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/jabdr/govault/pkg/api"
	"github.com/jabdr/govault/pkg/crypto"
)

// CacheFile is the on-disk representation of a cached vault session.
// It stores the access/refresh tokens, KDF parameters, and optionally
// the full sync payload.
type CacheFile struct {
	AccessToken    string            `json:"accessToken"`
	RefreshToken   string            `json:"refreshToken"`
	Kdf            int               `json:"kdf"`
	KdfIterations  int               `json:"kdfIterations"`
	KdfMemory      *int              `json:"kdfMemory,omitempty"`
	KdfParallelism *int              `json:"kdfParallelism,omitempty"`
	SyncData       *api.SyncResponse `json:"syncData,omitempty"`
}

// SaveCache writes the current vault session to a file.
// The file contains the access/refresh tokens and the sync payload.
func (v *Vault) SaveCache(path string) error {
	accessToken, refreshToken := v.client.GetTokens()
	cf := CacheFile{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		SyncData:     v.syncData,
	}
	data, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return fmt.Errorf("vault: marshal cache: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("vault: write cache: %w", err)
	}
	return nil
}

// LoadCacheTokens reads a cache file and applies only the access/refresh
// tokens to an existing (fully logged-in) vault client, so subsequent API
// calls can use the cached session instead of re-authenticating.
func (v *Vault) LoadCacheTokens(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("vault: read cache: %w", err)
	}
	var cf CacheFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return fmt.Errorf("vault: unmarshal cache: %w", err)
	}
	v.client.SetTokens(cf.AccessToken, cf.RefreshToken)
	return nil
}

// LoadCache reads a cache file and constructs an offline vault from it.
// The returned vault has the sync data loaded and encryption keys set up
// but cannot make API calls (it has no server connection).
func LoadCache(path, email, password string, insecure bool, logger *slog.Logger) (*Vault, error) {
	if logger == nil {
		logger = slog.Default()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("vault: read cache: %w", err)
	}
	var cf CacheFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("vault: unmarshal cache: %w", err)
	}
	if cf.SyncData == nil {
		return nil, fmt.Errorf("vault: cache file has no sync data")
	}

	// Derive the master key from credentials using stored KDF params
	prelogin := &api.PreloginResponse{
		Kdf:            cf.Kdf,
		KdfIterations:  cf.KdfIterations,
		KdfMemory:      cf.KdfMemory,
		KdfParallelism: cf.KdfParallelism,
	}
	masterKey, passwordHash, err := deriveKeys(password, email, prelogin)
	if err != nil {
		return nil, err
	}

	// Build the vault from cached sync data
	client := api.NewClient("", logger)
	client.SetInsecureSkipVerify(insecure)
	client.SetTokens(cf.AccessToken, cf.RefreshToken)

	return newVault(client, email, masterKey, passwordHash,
		cf.SyncData.Profile.Key, cf.SyncData.Profile.PrivateKey,
		cf.SyncData, logger)
}

// LoadCacheListOnly reads a cache file and constructs a vault clone that
// uses the sync data from the cache but the encryption keys from the
// current vault instance.
func (v *Vault) LoadCacheListOnly(path string) (*Vault, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("vault: read cache: %w", err)
	}
	var cf CacheFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("vault: unmarshal cache: %w", err)
	}
	if cf.SyncData == nil {
		return nil, fmt.Errorf("vault: cache file has no sync data")
	}

	// Reuse the encryption material from the existing vault
	clone := &Vault{
		client:       v.client,
		symKey:       v.symKey,
		privateKey:   v.privateKey,
		email:        v.email,
		masterKey:    v.masterKey,
		passwordHash: v.passwordHash,
		orgKeys:      make(map[string]*crypto.SymmetricKey),
		syncData:     cf.SyncData,
		logger:       v.logger,
	}

	// Decrypt org keys for the cached sync data
	for _, org := range cf.SyncData.Profile.Organizations {
		if org.Key == "" {
			continue
		}
		orgKey, err := clone.decryptOrgKey(org.Key)
		if err != nil {
			clone.logger.Warn("failed to decrypt org key", "orgID", org.ID, "error", err)
			continue
		}
		clone.orgKeys[org.ID] = orgKey
	}

	return clone, nil
}
