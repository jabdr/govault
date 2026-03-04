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
// All sensitive data is encrypted with a random symmetric key, which
// itself is encrypted by the stretched master key. Only the KDF
// parameters are stored in plaintext (they are needed to re-derive
// the master key from the user's password).
type CacheFile struct {
	// KDF parameters — stored in plaintext so the master key can be derived.
	Kdf            int  `json:"kdf"`
	KdfIterations  int  `json:"kdfIterations"`
	KdfMemory      *int `json:"kdfMemory,omitempty"`
	KdfParallelism *int `json:"kdfParallelism,omitempty"`

	// EncKey is the randomly-generated symmetric key, encrypted by the
	// stretched master key. Stored as a Bitwarden EncString.
	EncKey string `json:"encKey"`

	// Encrypted fields — each is an EncString produced by encrypting
	// the plaintext value with the random key above.
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	SyncData     string `json:"syncData,omitempty"`
}

// encryptField encrypts a string value with the given key and returns
// the EncString representation.
func encryptField(plaintext string, key *crypto.SymmetricKey) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	enc, err := crypto.EncryptToEncString([]byte(plaintext), key)
	if err != nil {
		return "", err
	}
	return enc.String(), nil
}

// decryptField decrypts an EncString field with the given key and returns
// the plaintext string.
func decryptField(encStr string, key *crypto.SymmetricKey) (string, error) {
	if encStr == "" {
		return "", nil
	}
	enc, err := crypto.ParseEncString(encStr)
	if err != nil {
		return "", err
	}
	plaintext, err := enc.Decrypt(key)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// decryptCacheKey decrypts the cache encryption key using the given
// stretched master key (as a SymmetricKey).
func decryptCacheKey(encKeyStr string, kek *crypto.SymmetricKey) (*crypto.SymmetricKey, error) {
	encCacheKey, err := crypto.ParseEncString(encKeyStr)
	if err != nil {
		return nil, fmt.Errorf("vault: parse cache enc key: %w", err)
	}
	cacheKeyBytes, err := encCacheKey.Decrypt(kek)
	if err != nil {
		return nil, fmt.Errorf("vault: decrypt cache key: %w", err)
	}
	cacheKey, err := crypto.MakeSymmetricKey(cacheKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("vault: make cache key: %w", err)
	}
	return cacheKey, nil
}

// kekFromMasterKey stretches a 32-byte master key into a SymmetricKey
// suitable for encrypting/decrypting the cache key.
func kekFromMasterKey(masterKey []byte) (*crypto.SymmetricKey, error) {
	stretched, err := crypto.StretchKey(masterKey)
	if err != nil {
		return nil, fmt.Errorf("vault: stretch master key: %w", err)
	}
	kek, err := crypto.MakeSymmetricKey(stretched)
	if err != nil {
		return nil, fmt.Errorf("vault: make KEK: %w", err)
	}
	return kek, nil
}

// SaveCache writes the current vault session to an encrypted cache file.
//
// A random symmetric key is generated and used to encrypt the access
// token, refresh token, and sync payload. The random key itself is then
// encrypted with the user's stretched master key.
func (v *Vault) SaveCache(path string) error {
	// Fetch KDF parameters via prelogin
	prelogin, err := v.client.Prelogin(v.email)
	if err != nil {
		return fmt.Errorf("vault: prelogin for cache: %w", err)
	}

	// Stretch the master key to get the key-encryption-key
	kek, err := kekFromMasterKey(v.masterKey)
	if err != nil {
		return err
	}

	// Generate a random symmetric key for encrypting the cache payload
	cacheKey, err := crypto.GenerateSymmetricKey()
	if err != nil {
		return fmt.Errorf("vault: generate cache key: %w", err)
	}

	// Encrypt the random key with the stretched master key
	encCacheKey, err := crypto.EncryptToEncString(cacheKey.Bytes(), kek)
	if err != nil {
		return fmt.Errorf("vault: encrypt cache key: %w", err)
	}

	// Encrypt the access and refresh tokens
	accessToken, refreshToken := v.client.GetTokens()
	encAccessToken, err := encryptField(accessToken, cacheKey)
	if err != nil {
		return fmt.Errorf("vault: encrypt access token: %w", err)
	}
	encRefreshToken, err := encryptField(refreshToken, cacheKey)
	if err != nil {
		return fmt.Errorf("vault: encrypt refresh token: %w", err)
	}

	// Encrypt the sync data
	var encSyncData string
	if v.syncData != nil {
		syncJSON, err := json.Marshal(v.syncData)
		if err != nil {
			return fmt.Errorf("vault: marshal sync data: %w", err)
		}
		encSyncData, err = encryptField(string(syncJSON), cacheKey)
		if err != nil {
			return fmt.Errorf("vault: encrypt sync data: %w", err)
		}
	}

	cf := CacheFile{
		Kdf:            prelogin.Kdf,
		KdfIterations:  prelogin.KdfIterations,
		KdfMemory:      prelogin.KdfMemory,
		KdfParallelism: prelogin.KdfParallelism,
		EncKey:         encCacheKey.String(),
		AccessToken:    encAccessToken,
		RefreshToken:   encRefreshToken,
		SyncData:       encSyncData,
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

// readCacheFile reads and parses only the JSON envelope of a cache file.
func readCacheFile(path string) (*CacheFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("vault: read cache: %w", err)
	}
	cf := &CacheFile{}
	if err := json.Unmarshal(data, cf); err != nil {
		return nil, fmt.Errorf("vault: unmarshal cache: %w", err)
	}
	return cf, nil
}

// decryptCacheFields decrypts all encrypted fields in the cache file
// using the given cache-payload key.
func decryptCacheFields(cf *CacheFile, cacheKey *crypto.SymmetricKey) (accessToken, refreshToken string, syncData *api.SyncResponse, err error) {
	accessToken, err = decryptField(cf.AccessToken, cacheKey)
	if err != nil {
		return "", "", nil, fmt.Errorf("vault: decrypt access token: %w", err)
	}
	refreshToken, err = decryptField(cf.RefreshToken, cacheKey)
	if err != nil {
		return "", "", nil, fmt.Errorf("vault: decrypt refresh token: %w", err)
	}
	if cf.SyncData != "" {
		syncJSON, err := decryptField(cf.SyncData, cacheKey)
		if err != nil {
			return "", "", nil, fmt.Errorf("vault: decrypt sync data: %w", err)
		}
		syncData = &api.SyncResponse{}
		if err := json.Unmarshal([]byte(syncJSON), syncData); err != nil {
			return "", "", nil, fmt.Errorf("vault: unmarshal sync data: %w", err)
		}
	}
	return accessToken, refreshToken, syncData, nil
}

// LoadCacheTokens reads an encrypted cache file and applies only the
// access/refresh tokens to an existing vault client. It uses the vault's
// existing master key (no password required).
func (v *Vault) LoadCacheTokens(path string) error {
	cf, err := readCacheFile(path)
	if err != nil {
		return err
	}

	kek, err := kekFromMasterKey(v.masterKey)
	if err != nil {
		return err
	}
	cacheKey, err := decryptCacheKey(cf.EncKey, kek)
	if err != nil {
		return err
	}

	accessToken, refreshToken, _, err := decryptCacheFields(cf, cacheKey)
	if err != nil {
		return err
	}
	v.client.SetTokens(accessToken, refreshToken)
	return nil
}

// LoadCache reads an encrypted cache file and constructs an offline vault
// from it. The returned vault has the sync data loaded and encryption
// keys set up but cannot make API calls (it has no server connection).
func LoadCache(path, email, password string, insecure bool, logger *slog.Logger) (*Vault, error) {
	if logger == nil {
		logger = slog.Default()
	}

	cf, err := readCacheFile(path)
	if err != nil {
		return nil, err
	}

	// Derive the master key from the user's credentials
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

	// Decrypt the cache
	kek, err := kekFromMasterKey(masterKey)
	if err != nil {
		return nil, err
	}
	cacheKey, err := decryptCacheKey(cf.EncKey, kek)
	if err != nil {
		return nil, err
	}
	accessToken, refreshToken, syncData, err := decryptCacheFields(cf, cacheKey)
	if err != nil {
		return nil, err
	}
	if syncData == nil {
		return nil, fmt.Errorf("vault: cache file has no sync data")
	}

	// Build the vault from cached sync data
	client := api.NewClient("", logger)
	client.SetInsecureSkipVerify(insecure)
	client.SetTokens(accessToken, refreshToken)

	return newVault(client, email, masterKey, passwordHash,
		syncData.Profile.Key, syncData.Profile.PrivateKey,
		syncData, logger)
}

// LoadCacheListOnly reads an encrypted cache file and constructs a vault
// clone that uses the sync data from the cache but the encryption keys
// from the current vault instance.
func (v *Vault) LoadCacheListOnly(path string) (*Vault, error) {
	cf, err := readCacheFile(path)
	if err != nil {
		return nil, err
	}

	kek, err := kekFromMasterKey(v.masterKey)
	if err != nil {
		return nil, err
	}
	cacheKey, err := decryptCacheKey(cf.EncKey, kek)
	if err != nil {
		return nil, err
	}
	_, _, syncData, err := decryptCacheFields(cf, cacheKey)
	if err != nil {
		return nil, err
	}
	if syncData == nil {
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
		syncData:     syncData,
		logger:       v.logger,
	}

	// Decrypt org keys for the cached sync data
	for _, org := range syncData.Profile.Organizations {
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
