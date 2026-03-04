// Package vault provides high-level operations for interacting with a
// Bitwarden/Vaultwarden vault. It ties together the crypto and api packages
// to provide a simple interface for login, cipher management, organization
// operations, sends, emergency access, and key rotation.
package vault

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jabdr/govault/pkg/api"
	"github.com/jabdr/govault/pkg/crypto"
)

// Vault is the high-level client for managing a Bitwarden vault.
type Vault struct {
	client       *api.Client
	symKey       *crypto.SymmetricKey
	privateKey   []byte // DER-encoded RSA private key
	email        string
	masterKey    []byte
	passwordHash string
	orgKeys      map[string]*crypto.SymmetricKey // orgID → decrypted org key
	syncData     *api.SyncResponse
	logger       *slog.Logger
}

// --------------------------------------------------------------------------
// Option pattern
// --------------------------------------------------------------------------

// VaultOption configures how the vault is constructed.
type VaultOption func(*options)

type options struct {
	serverURL    string
	email        string
	password     string
	clientID     string
	clientSecret string
	insecure     bool
	logger       *slog.Logger
	cacheFile    string
	useSyncData  bool // if true, load sync data from cache for offline use
}

// WithServer sets the Bitwarden/Vaultwarden server URL.
func WithServer(url string) VaultOption {
	return func(o *options) { o.serverURL = url }
}

// WithCredentials sets the user email and master password.
func WithCredentials(email, password string) VaultOption {
	return func(o *options) {
		o.email = email
		o.password = password
	}
}

// WithAPIKey sets the API key credentials (client ID and secret).
func WithAPIKey(clientID, clientSecret string) VaultOption {
	return func(o *options) {
		o.clientID = clientID
		o.clientSecret = clientSecret
	}
}

// WithInsecure sets whether to skip TLS verification.
func WithInsecure(skip bool) VaultOption {
	return func(o *options) { o.insecure = skip }
}

// WithLogger sets the logger for the vault.
func WithLogger(l *slog.Logger) VaultOption {
	return func(o *options) { o.logger = l }
}

// WithCacheFile sets the path to an encrypted cache file. The cache
// file's access/refresh tokens will be preferred over a fresh login.
func WithCacheFile(path string) VaultOption {
	return func(o *options) { o.cacheFile = path }
}

// WithSyncData tells the vault to load sync data from the cache file
// and operate offline. Only meaningful when WithCacheFile is also set.
func WithSyncData() VaultOption {
	return func(o *options) { o.useSyncData = true }
}

// New constructs a Vault using functional options.
//
// The authentication strategy is:
//  1. If a cache file is set, try to use its tokens (access → refresh → re-login).
//  2. If API key credentials are provided, try API key login.
//  3. Otherwise, perform a password-based login.
//
// In all cases the master key and password hash are derived so the vault
// holds the encryption material needed for cipher operations.
func New(opts ...VaultOption) (*Vault, error) {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}

	if o.logger == nil {
		o.logger = slog.Default()
	}
	logger := o.logger

	if o.email == "" || o.password == "" {
		return nil, fmt.Errorf("vault: email and password are required")
	}
	email := strings.ToLower(strings.TrimSpace(o.email))

	client := api.NewClient(o.serverURL, logger)
	client.SetInsecureSkipVerify(o.insecure)

	// ── 1. Derive master key and password hash ──────────────────────────
	//
	// In offline mode (useSyncData), the KDF parameters come from the
	// cache file so no server round-trip is needed. In online mode they
	// come from a prelogin call.
	var prelogin *api.PreloginResponse

	if o.cacheFile != "" && o.useSyncData {
		// Read KDF params from the cache file header
		cf, err := readCacheFile(o.cacheFile)
		if err != nil {
			return nil, err
		}
		prelogin = &api.PreloginResponse{
			Kdf:            cf.Kdf,
			KdfIterations:  cf.KdfIterations,
			KdfMemory:      cf.KdfMemory,
			KdfParallelism: cf.KdfParallelism,
		}
	} else {
		var err error
		prelogin, err = client.Prelogin(email)
		if err != nil {
			return nil, fmt.Errorf("vault: prelogin: %w", err)
		}
	}
	logger.Info("prelogin complete", "kdf", prelogin.Kdf, "iterations", prelogin.KdfIterations)

	masterKey, passwordHash, err := deriveKeys(o.password, email, prelogin)
	if err != nil {
		return nil, err
	}

	// ── 2. Authenticate — prefer cache tokens, then API key, then login ─
	authenticated := false

	if o.cacheFile != "" {
		if tokErr := applyCacheTokens(client, o.cacheFile, masterKey, logger); tokErr != nil {
			logger.Warn("cache tokens not usable, will login normally", "error", tokErr)
		} else {
			authenticated = true
			logger.Info("using tokens from cache file")
		}
	}

	if !authenticated && !o.useSyncData {
		if o.clientID != "" && o.clientSecret != "" {
			if _, err := client.LoginWithAPIKey(o.clientID, o.clientSecret, "govault-device"); err != nil {
				return nil, fmt.Errorf("vault: login api key: %w", err)
			}
			logger.Info("login with api key successful")
		} else {
			if _, err := client.Login(email, passwordHash, "govault-device"); err != nil {
				return nil, fmt.Errorf("vault: login: %w", err)
			}
			logger.Info("login successful")
		}
	}

	// ── 3. Set up re-authentication callback on the API client ──────────
	if !o.useSyncData {
		client.SetReauthFunc(func() error {
			logger.Info("re-authenticating")
			// Try refresh token first
			if refreshErr := client.RefreshAccessToken(); refreshErr == nil {
				logger.Info("re-authenticated via refresh token")
				return nil
			}
			// Fall back to full login
			if o.clientID != "" && o.clientSecret != "" {
				if _, err := client.LoginWithAPIKey(o.clientID, o.clientSecret, "govault-device"); err != nil {
					return fmt.Errorf("vault: re-login api key: %w", err)
				}
			} else {
				if _, err := client.Login(email, passwordHash, "govault-device"); err != nil {
					return fmt.Errorf("vault: re-login: %w", err)
				}
			}
			logger.Info("re-authenticated via full login")
			return nil
		})
	}

	// ── 4. Load sync data ───────────────────────────────────────────────
	var syncData *api.SyncResponse

	if o.cacheFile != "" && o.useSyncData {
		// Offline mode: load sync data from the cache file
		syncData, err = loadCacheSyncData(o.cacheFile, masterKey)
		if err != nil {
			return nil, fmt.Errorf("vault: load cached sync data: %w", err)
		}
		logger.Info("loaded sync data from cache")
	} else {
		// Online: sync from server
		syncData, err = client.Sync()
		if err != nil {
			return nil, fmt.Errorf("vault: sync: %w", err)
		}
	}

	return newVault(client, email, masterKey, passwordHash,
		syncData.Profile.Key, syncData.Profile.PrivateKey,
		syncData, logger)
}

// Login authenticates with the server and sets up the vault.
// This is a convenience wrapper around New.
func Login(serverURL, email, password string, insecure bool, logger *slog.Logger) (*Vault, error) {
	return New(
		WithServer(serverURL),
		WithCredentials(email, password),
		WithInsecure(insecure),
		WithLogger(logger),
	)
}

// LoginAPIKey authenticates with the server using an API key and sets up the vault.
// This is a convenience wrapper around New.
func LoginAPIKey(serverURL, clientID, clientSecret, email, password string, insecure bool, logger *slog.Logger) (*Vault, error) {
	return New(
		WithServer(serverURL),
		WithCredentials(email, password),
		WithAPIKey(clientID, clientSecret),
		WithInsecure(insecure),
		WithLogger(logger),
	)
}

// Register self-registers a new account on the server.
func Register(serverURL, email, password string, kdf, iterations, memory, parallelism int, insecure bool, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	client := api.NewClient(serverURL, logger)
	client.SetInsecureSkipVerify(insecure)
	email = strings.ToLower(strings.TrimSpace(email))

	// 1. Derive Master Key
	masterKey, err := crypto.DeriveKey(
		[]byte(password), []byte(email),
		kdf, iterations, &memory, &parallelism,
	)
	if err != nil {
		return fmt.Errorf("vault: derive master key: %w", err)
	}

	// 2. Derive Master Password Hash for login
	masterPasswordHash := crypto.HashPassword(password, masterKey)

	// 3. Derive Stretched Master Key (used to encrypt the symmetric user key)
	stretched, err := crypto.StretchKey(masterKey)
	if err != nil {
		return fmt.Errorf("vault: stretch key: %w", err)
	}
	stretchedKey, err := crypto.MakeSymmetricKey(stretched)
	if err != nil {
		return fmt.Errorf("vault: make stretched symmetric key: %w", err)
	}

	// 4. Generate random user encryption key (the actual key for vault items)
	userKey, err := crypto.GenerateSymmetricKey()
	if err != nil {
		return fmt.Errorf("vault: generate user key: %w", err)
	}

	// 5. Encrypt user key with stretched master key (Protected Symmetric Key)
	protectedKey, err := crypto.EncryptToEncString(userKey.Bytes(), stretchedKey)
	if err != nil {
		return fmt.Errorf("vault: encrypt user key: %w", err)
	}

	// 6. Generate RSA key pair for organization sharing / emergency access
	pubDER, privDER, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		return fmt.Errorf("vault: generate RSA key pair: %w", err)
	}

	// 7. Encrypt the RSA private key with the user key
	encPrivKey, err := crypto.EncryptToEncString(privDER, userKey)
	if err != nil {
		return fmt.Errorf("vault: encrypt RSA private key: %w", err)
	}

	// 8. Call API to register
	req := &api.RegisterRequest{
		Email:              email,
		MasterPasswordHash: masterPasswordHash,
		Key:                protectedKey.String(),
		Keys: &api.UserKeyData{
			EncryptedPrivateKey: encPrivKey.String(),
			PublicKey:           base64.StdEncoding.EncodeToString(pubDER),
		},
		Kdf:            kdf,
		KdfIterations:  iterations,
		KdfMemory:      memory,
		KdfParallelism: parallelism,
	}

	if err := client.Register(req); err != nil {
		return fmt.Errorf("vault: register api call: %w", err)
	}

	logger.Info("registration successful", "email", email)
	return nil
}

// deriveKeys performs PBKDF2 to derive the user's master key and login password hash.
func deriveKeys(password, email string, prelogin *api.PreloginResponse) ([]byte, string, error) {
	masterKey, err := crypto.DeriveKey(
		[]byte(password), []byte(email),
		prelogin.Kdf, prelogin.KdfIterations,
		prelogin.KdfMemory, prelogin.KdfParallelism,
	)
	if err != nil {
		return nil, "", fmt.Errorf("vault: derive master key: %w", err)
	}
	passwordHash := crypto.HashPassword(password, masterKey)
	return masterKey, passwordHash, nil
}

// newVault processes the encrypted keys, builds the Vault object, and conditionally sets up initial syncData.
func newVault(client *api.Client, email string, masterKey []byte, passwordHash, protectedKeyStr, privateKeyStr string, syncData *api.SyncResponse, logger *slog.Logger) (*Vault, error) {
	stretched, err := crypto.StretchKey(masterKey)
	if err != nil {
		return nil, fmt.Errorf("vault: stretch key: %w", err)
	}

	protectedKey, err := crypto.ParseEncString(protectedKeyStr)
	if err != nil {
		return nil, fmt.Errorf("vault: parse protected key: %w", err)
	}

	symKey, err := crypto.DecryptSymmetricKey(protectedKey, stretched)
	if err != nil {
		return nil, fmt.Errorf("vault: decrypt symmetric key: %w", err)
	}
	logger.Info("symmetric key decrypted")

	var privateKey []byte
	if privateKeyStr != "" {
		encPrivKey, err := crypto.ParseEncString(privateKeyStr)
		if err != nil {
			return nil, fmt.Errorf("vault: parse private key: %w", err)
		}
		privateKey, err = crypto.DecryptPrivateKey(encPrivKey, symKey)
		if err != nil {
			return nil, fmt.Errorf("vault: decrypt private key: %w", err)
		}
		logger.Info("RSA private key decrypted")
	}

	v := &Vault{
		client:       client,
		symKey:       symKey,
		privateKey:   privateKey,
		email:        email,
		masterKey:    masterKey,
		passwordHash: passwordHash,
		orgKeys:      make(map[string]*crypto.SymmetricKey),
		syncData:     syncData,
		logger:       logger,
	}

	if syncData != nil {
		for _, org := range syncData.Profile.Organizations {
			if org.Key == "" {
				continue
			}
			orgKey, err := v.decryptOrgKey(org.Key)
			if err != nil {
				v.logger.Warn("failed to decrypt org key", "orgID", org.ID, "error", err)
				continue
			}
			v.orgKeys[org.ID] = orgKey
		}
	}

	return v, nil
}

// Client returns the underlying API client.
func (v *Vault) Client() *api.Client {
	return v.client
}

// SymmetricKey returns the vault's symmetric encryption key.
func (v *Vault) SymmetricKey() *crypto.SymmetricKey {
	return v.symKey
}

// Sync performs a full vault sync and caches the result.
func (v *Vault) Sync() error {
	resp, err := v.client.Sync()
	if err != nil {
		return fmt.Errorf("vault: sync: %w", err)
	}
	v.syncData = resp

	// Decrypt organization keys from sync profile
	for _, org := range resp.Profile.Organizations {
		if org.Key == "" {
			continue
		}
		orgKey, err := v.decryptOrgKey(org.Key)
		if err != nil {
			v.logger.Warn("failed to decrypt org key", "orgID", org.ID, "error", err)
			continue
		}
		v.orgKeys[org.ID] = orgKey
	}

	v.logger.Info("sync complete",
		"ciphers", len(resp.Ciphers),
		"folders", len(resp.Folders),
		"orgs", len(resp.Profile.Organizations),
	)
	return nil
}

// decryptOrgKey decrypts an organization key using our RSA private key.
func (v *Vault) decryptOrgKey(encKeyStr string) (*crypto.SymmetricKey, error) {
	if v.privateKey == nil {
		return nil, fmt.Errorf("vault: no RSA private key available")
	}

	encKey, err := crypto.ParseEncString(encKeyStr)
	if err != nil {
		return nil, fmt.Errorf("vault: parse org key: %w", err)
	}

	var decrypted []byte
	switch encKey.Type {
	case 4:
		decrypted, err = crypto.RSADecryptEncString(encKey, v.privateKey)
	case 2:
		decrypted, err = encKey.Decrypt(v.symKey)
	default:
		return nil, fmt.Errorf("vault: unsupported org key type %d", encKey.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("vault: decrypt org key: %w", err)
	}

	return crypto.MakeSymmetricKey(decrypted)
}

// GetOrgKey returns the decrypted symmetric key for an organization.
func (v *Vault) GetOrgKey(orgID string) (*crypto.SymmetricKey, error) {
	key, ok := v.orgKeys[orgID]
	if !ok {
		return nil, fmt.Errorf("vault: org key not found for %s (sync first?)", orgID)
	}
	return key, nil
}

// ListCiphers returns all ciphers from the last sync as Cipher wrappers.
func (v *Vault) ListCiphers() ([]*Cipher, error) {
	if v.syncData == nil {
		if err := v.Sync(); err != nil {
			return nil, err
		}
	}

	ciphers := make([]*Cipher, 0, len(v.syncData.Ciphers))
	for _, raw := range v.syncData.Ciphers {
		key := v.keyForCipher(raw)
		ciphers = append(ciphers, NewCipherFromMap(raw, key))
	}
	return ciphers, nil
}

// GetCipher fetches and returns a single cipher by ID.
func (v *Vault) GetCipher(id string) (*Cipher, error) {
	raw, err := v.client.GetCipher(id)
	if err != nil {
		return nil, fmt.Errorf("vault: get cipher: %w", err)
	}
	key := v.keyForCipher(raw)
	return NewCipherFromMap(raw, key), nil
}

// CreateCipher encrypts and creates a new cipher.
func (v *Vault) CreateCipher(c *Cipher) error {
	encrypted, err := c.Encrypt(v.symKey)
	if err != nil {
		return fmt.Errorf("vault: encrypt cipher: %w", err)
	}
	resp, err := v.client.CreateCipher(encrypted)
	if err != nil {
		return fmt.Errorf("vault: create cipher: %w", err)
	}
	c.data = resp
	return nil
}

// UpdateCipher encrypts and updates an existing cipher.
func (v *Vault) UpdateCipher(c *Cipher) error {
	key := v.keyForCipher(c.data)
	encrypted, err := c.Encrypt(key)
	if err != nil {
		return fmt.Errorf("vault: encrypt cipher: %w", err)
	}
	resp, err := v.client.UpdateCipher(c.ID(), encrypted)
	if err != nil {
		return fmt.Errorf("vault: update cipher: %w", err)
	}
	c.data = resp
	return nil
}

// DeleteCipher deletes a cipher by ID.
func (v *Vault) DeleteCipher(id string) error {
	return v.client.DeleteCipher(id)
}

// keyForCipher returns the appropriate encryption key for a cipher.
func (v *Vault) keyForCipher(raw map[string]any) *crypto.SymmetricKey {
	orgID, _ := raw["organizationId"].(string)
	if orgID != "" {
		if key, ok := v.orgKeys[orgID]; ok {
			return key
		}
	}
	return v.symKey
}

// ChangePassword changes the master password without rotating the encryption key.
func (v *Vault) ChangePassword(currentPassword, newPassword string, kdf, kdfIter, kdfMem, kdfParal int) error {
	// Derive new master key
	newMasterKey, err := crypto.DeriveKey([]byte(newPassword), []byte(v.email), kdf, kdfIter, &kdfMem, &kdfParal)
	if err != nil {
		return fmt.Errorf("vault: derive new master key: %w", err)
	}

	newStretched, err := crypto.StretchKey(newMasterKey)
	if err != nil {
		return fmt.Errorf("vault: stretch new key: %w", err)
	}

	// Re-encrypt symmetric key with new stretched key
	stretchedKey, err := crypto.MakeSymmetricKey(newStretched)
	if err != nil {
		return fmt.Errorf("vault: make stretched key: %w", err)
	}

	newProtectedKey, err := crypto.EncryptToEncString(v.symKey.Bytes(), stretchedKey)
	if err != nil {
		return fmt.Errorf("vault: encrypt symmetric key: %w", err)
	}

	newPasswordHash := crypto.HashPassword(newPassword, newMasterKey)

	err = v.client.ChangePassword(&api.ChangePasswordRequest{
		MasterPasswordHash:    v.passwordHash,
		NewMasterPasswordHash: newPasswordHash,
		Key:                   newProtectedKey.String(),
		Kdf:                   kdf,
		KdfIterations:         kdfIter,
		KdfMemory:             kdfMem,
		KdfParallelism:        kdfParal,
	})
	if err != nil {
		return fmt.Errorf("vault: change password: %w", err)
	}

	v.masterKey = newMasterKey
	v.passwordHash = newPasswordHash
	v.logger.Info("password changed successfully")
	return nil
}

// GetAPIKey retrieves the API client ID and secret for the user.
// It returns (clientID, clientSecret, error).
func (v *Vault) GetAPIKey() (string, string, error) {
	if v.syncData == nil {
		if err := v.Sync(); err != nil {
			return "", "", err
		}
	}

	secret, err := v.client.GetAPIKey(v.passwordHash)
	if err != nil {
		return "", "", err
	}

	clientID := "user." + v.syncData.Profile.ID
	return clientID, secret, nil
}

// ChangeName updates the account display name.
func (v *Vault) ChangeName(name string) error {
	err := v.client.UpdateProfile(&api.UpdateProfileRequest{
		Name: name,
	})
	if err != nil {
		return fmt.Errorf("vault: change name: %w", err)
	}
	v.logger.Info("name changed successfully", "name", name)
	return nil
}

// RequestEmailChange initiates the email change process by requesting a
// verification token to be sent to the new email address.
func (v *Vault) RequestEmailChange(newEmail string) error {
	err := v.client.RequestEmailChange(&api.RequestEmailChangeRequest{
		NewEmail:           strings.ToLower(newEmail),
		MasterPasswordHash: v.passwordHash,
	})
	if err != nil {
		return fmt.Errorf("vault: request email change: %w", err)
	}
	v.logger.Info("email change token requested", "newEmail", newEmail)
	return nil
}

// ChangeEmail changes the account email address.
// The token parameter is the verification token sent to the new email.
// This re-derives the master key with the new email as salt, re-encrypts
// the protected symmetric key, and submits the change to the server.
func (v *Vault) ChangeEmail(newEmail, masterPassword, token string, kdf, kdfIter, kdfMem, kdfParal int) error {
	// Derive new master key using the new email as salt
	newMasterKey, err := crypto.DeriveKey([]byte(masterPassword), []byte(strings.ToLower(newEmail)), kdf, kdfIter, &kdfMem, &kdfParal)
	if err != nil {
		return fmt.Errorf("vault: derive new master key: %w", err)
	}

	newStretched, err := crypto.StretchKey(newMasterKey)
	if err != nil {
		return fmt.Errorf("vault: stretch new key: %w", err)
	}

	// Re-encrypt symmetric key with new stretched key
	stretchedKey, err := crypto.MakeSymmetricKey(newStretched)
	if err != nil {
		return fmt.Errorf("vault: make stretched key: %w", err)
	}

	newProtectedKey, err := crypto.EncryptToEncString(v.symKey.Bytes(), stretchedKey)
	if err != nil {
		return fmt.Errorf("vault: encrypt symmetric key: %w", err)
	}

	newPasswordHash := crypto.HashPassword(masterPassword, newMasterKey)

	err = v.client.ChangeEmail(&api.ChangeEmailRequest{
		NewEmail:              strings.ToLower(newEmail),
		MasterPasswordHash:    v.passwordHash,
		NewMasterPasswordHash: newPasswordHash,
		Token:                 token,
		Key:                   newProtectedKey.String(),
	})
	if err != nil {
		return fmt.Errorf("vault: change email: %w", err)
	}

	v.email = strings.ToLower(newEmail)
	v.masterKey = newMasterKey
	v.passwordHash = newPasswordHash
	v.logger.Info("email changed successfully", "email", v.email)
	return nil
}
