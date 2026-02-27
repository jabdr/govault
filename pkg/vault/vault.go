// Package vault provides high-level operations for interacting with a
// Bitwarden/Vaultwarden vault. It ties together the crypto and api packages
// to provide a simple interface for login, cipher management, organization
// operations, sends, emergency access, and key rotation.
package vault

import (
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

// Login authenticates with the server and sets up the vault.
func Login(serverURL, email, password string, insecure bool, logger *slog.Logger) (*Vault, error) {
	if logger == nil {
		logger = slog.Default()
	}

	client := api.NewClient(serverURL, logger)
	client.SetInsecureSkipVerify(insecure)
	email = strings.ToLower(strings.TrimSpace(email))

	prelogin, err := client.Prelogin(email)
	if err != nil {
		return nil, fmt.Errorf("vault: prelogin: %w", err)
	}
	logger.Info("prelogin complete", "kdf", prelogin.Kdf, "iterations", prelogin.KdfIterations)

	masterKey, passwordHash, err := deriveKeys(password, email, prelogin)
	if err != nil {
		return nil, err
	}

	deviceID := "govault-device"
	loginResp, err := client.Login(email, passwordHash, deviceID)
	if err != nil {
		return nil, fmt.Errorf("vault: login: %w", err)
	}
	logger.Info("login successful")

	syncData, err := client.Sync()
	if err != nil {
		return nil, fmt.Errorf("vault: sync: %w", err)
	}

	return newVault(client, email, masterKey, passwordHash, loginResp.Key, loginResp.PrivateKey, syncData, logger)
}

// LoginAPIKey authenticates with the server using an API key and sets up the vault.
func LoginAPIKey(serverURL, clientID, clientSecret, email, password string, insecure bool, logger *slog.Logger) (*Vault, error) {
	if logger == nil {
		logger = slog.Default()
	}

	client := api.NewClient(serverURL, logger)
	client.SetInsecureSkipVerify(insecure)
	email = strings.ToLower(strings.TrimSpace(email))

	prelogin, err := client.Prelogin(email)
	if err != nil {
		return nil, fmt.Errorf("vault: prelogin: %w", err)
	}
	logger.Info("prelogin complete", "kdf", prelogin.Kdf, "iterations", prelogin.KdfIterations)

	masterKey, passwordHash, err := deriveKeys(password, email, prelogin)
	if err != nil {
		return nil, err
	}

	deviceID := "govault-device"
	_, err = client.LoginWithAPIKey(clientID, clientSecret, deviceID)
	if err != nil {
		return nil, fmt.Errorf("vault: login api key: %w", err)
	}
	logger.Info("login with api key successful")

	// API key login does not return user encryption keys, so a sync is required immediately
	syncData, err := client.Sync()
	if err != nil {
		return nil, fmt.Errorf("vault: sync for keys: %w", err)
	}

	return newVault(client, email, masterKey, passwordHash, syncData.Profile.Key, syncData.Profile.PrivateKey, syncData, logger)
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
