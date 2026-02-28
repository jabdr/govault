package api

import (
	"fmt"
	"net/http"
)

// ChangePasswordRequest is the request body for POST /api/accounts/password.
type ChangePasswordRequest struct {
	MasterPasswordHash    string `json:"masterPasswordHash"`
	NewMasterPasswordHash string `json:"newMasterPasswordHash"`
	MasterPasswordHint    string `json:"masterPasswordHint,omitempty"`
	Key                   string `json:"key"`
	Kdf                   int    `json:"kdf"`
	KdfIterations         int    `json:"kdfIterations"`
	KdfMemory             int    `json:"kdfMemory,omitempty"`
	KdfParallelism        int    `json:"kdfParallelism,omitempty"`
}

// UserKeyData holds the user RSA key pair.
type UserKeyData struct {
	EncryptedPrivateKey string `json:"encryptedPrivateKey"`
	PublicKey           string `json:"publicKey"`
}

// RegisterRequest is the request body for POST /api/accounts.
type RegisterRequest struct {
	Email              string       `json:"email"`
	MasterPasswordHash string       `json:"masterPasswordHash"`
	MasterPasswordHint string       `json:"masterPasswordHint,omitempty"`
	Key                string       `json:"key"`
	Keys               *UserKeyData `json:"keys,omitempty"`
	Kdf                int          `json:"kdf"`
	KdfIterations      int          `json:"kdfIterations"`
	KdfMemory          int          `json:"kdfMemory,omitempty"`
	KdfParallelism     int          `json:"kdfParallelism,omitempty"`
}

// ChangePassword changes the master password and re-encrypted symmetric key.
func (c *Client) ChangePassword(req *ChangePasswordRequest) error {
	c.logger.Info("changing password")
	err := c.doRequest(http.MethodPost, "/api/accounts/password", req, nil)
	if err != nil {
		return fmt.Errorf("api: change password: %w", err)
	}
	return nil
}

// RotateKeyRequest is the request body for POST /api/accounts/key.
type RotateKeyRequest struct {
	MasterPasswordHash  string                     `json:"masterPasswordHash"`
	Key                 string                     `json:"key"`
	PrivateKey          string                     `json:"privateKey"`
	Ciphers             []map[string]any           `json:"ciphers"`
	Folders             []map[string]any           `json:"folders,omitempty"`
	Sends               []map[string]any           `json:"sends,omitempty"`
	EmergencyAccessKeys []EmergencyAccessKeyUpdate `json:"emergencyAccessKeys,omitempty"`
	ResetPasswordKeys   []ResetPasswordKeyUpdate   `json:"resetPasswordKeys,omitempty"`
}

// EmergencyAccessKeyUpdate contains re-encrypted keys for emergency access.
type EmergencyAccessKeyUpdate struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

// ResetPasswordKeyUpdate contains re-encrypted keys for org password reset.
type ResetPasswordKeyUpdate struct {
	OrganizationID string `json:"organizationId"`
	Key            string `json:"resetPasswordKey"`
}

// RotateKey rotates the account encryption key.
func (c *Client) RotateKey(req *RotateKeyRequest) error {
	c.logger.Info("rotating encryption key")
	err := c.doRequest(http.MethodPost, "/api/accounts/key", req, nil)
	if err != nil {
		return fmt.Errorf("api: rotate key: %w", err)
	}
	return nil
}

// GetAPIKey returns the API key for the account.
func (c *Client) GetAPIKey(masterPasswordHash string) (string, error) {
	c.logger.Info("fetching API key")
	req := map[string]string{
		"masterPasswordHash": masterPasswordHash,
	}
	var resp struct {
		APIKey string `json:"apiKey"`
	}
	if err := c.doRequest(http.MethodPost, "/api/accounts/api-key", req, &resp); err != nil {
		return "", fmt.Errorf("api: get api key: %w", err)
	}
	return resp.APIKey, nil
}

// VerifyEmail requests a new verification email.
func (c *Client) VerifyEmail() error {
	c.logger.Info("requesting verify email")
	if err := c.doRequest(http.MethodPost, "/api/accounts/verify-email", nil, nil); err != nil {
		return fmt.Errorf("api: verify email request: %w", err)
	}
	return nil
}

// VerifyEmailToken sends the verification token to the server.
func (c *Client) VerifyEmailToken(userID, token string) error {
	c.logger.Info("verifying email token")
	req := map[string]string{
		"userId": userID,
		"token":  token,
	}
	if err := c.doRequest(http.MethodPost, "/api/accounts/verify-email-token", req, nil); err != nil {
		return fmt.Errorf("api: verify email token: %w", err)
	}
	return nil
}

// Register creates a new account.
func (c *Client) Register(req *RegisterRequest) error {
	c.logger.Info("registering new account", "email", req.Email)
	err := c.doRequest(http.MethodPost, "/identity/accounts/register", req, nil)
	if err != nil {
		return fmt.Errorf("api: register: %w", err)
	}
	return nil
}
