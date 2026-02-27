package vault

import (
	"fmt"
	"time"

	"github.com/jabdr/govault/pkg/api"
	"github.com/jabdr/govault/pkg/crypto"
)

// SendType constants.
const (
	SendTypeText = 0
	SendTypeFile = 1
)

// SendOptions configures optional Send parameters.
type SendOptions struct {
	Password       string
	MaxAccessCount *int
	ExpirationDate *time.Time
	DeletionDate   time.Time // Required, defaults to 7 days
	HideEmail      bool
}

// Send represents a decrypted Bitwarden Send.
type Send struct {
	ID             string
	AccessID       string
	Type           int
	Name           string
	Text           string
	FileName       string
	Notes          string
	AccessCount    int
	MaxAccessCount *int
	Disabled       bool
	DeletionDate   string
	ExpirationDate string
}

// CreateTextSend creates a new text Send and returns it along with the access URL.
func (v *Vault) CreateTextSend(name, text string, opts SendOptions) (*Send, string, error) {
	// Generate send secret and derive key
	secret, err := crypto.GenerateSendSecret()
	if err != nil {
		return nil, "", fmt.Errorf("vault: generate send secret: %w", err)
	}

	sendKey, err := crypto.DeriveSendKey(secret)
	if err != nil {
		return nil, "", fmt.Errorf("vault: derive send key: %w", err)
	}

	// Encrypt send data
	encName, err := crypto.EncryptToEncString([]byte(name), sendKey)
	if err != nil {
		return nil, "", fmt.Errorf("vault: encrypt send name: %w", err)
	}

	encText, err := crypto.EncryptToEncString([]byte(text), sendKey)
	if err != nil {
		return nil, "", fmt.Errorf("vault: encrypt send text: %w", err)
	}

	// Encrypt the send secret (seed) with the vault symmetric key.
	// Bitwarden clients expect the seed here, not the derived 64-byte key.
	encSendKey, err := crypto.EncryptToEncString(secret, v.symKey)
	if err != nil {
		return nil, "", fmt.Errorf("vault: encrypt send key: %w", err)
	}

	// Set deletion date
	deletionDate := opts.DeletionDate
	if deletionDate.IsZero() {
		deletionDate = time.Now().Add(7 * 24 * time.Hour)
	}

	req := &api.SendRequest{
		Type:         SendTypeText,
		Key:          encSendKey.String(),
		Name:         encName.String(),
		DeletionDate: deletionDate.UTC().Format(time.RFC3339),
		Text: &api.SendTextData{
			Text:   encText.String(),
			Hidden: false,
		},
	}

	if opts.Password != "" {
		req.Password = &opts.Password
	}
	if opts.MaxAccessCount != nil {
		req.MaxAccessCount = opts.MaxAccessCount
	}
	if opts.ExpirationDate != nil {
		s := opts.ExpirationDate.UTC().Format(time.RFC3339)
		req.ExpirationDate = &s
	}
	if opts.HideEmail {
		req.HideEmail = &opts.HideEmail
	}

	resp, err := v.client.CreateSend(req)
	if err != nil {
		return nil, "", fmt.Errorf("vault: create send: %w", err)
	}

	// Build access URL
	accessURL := fmt.Sprintf("%s/#/send/%s/%s",
		v.client.BaseURL(),
		resp.AccessID,
		crypto.EncodeSendSecret(secret),
	)

	send := &Send{
		ID:           resp.ID,
		AccessID:     resp.AccessID,
		Type:         resp.Type,
		Name:         name,
		Text:         text,
		DeletionDate: resp.DeletionDate,
	}

	v.logger.Info("send created", "id", resp.ID, "accessURL", accessURL)
	return send, accessURL, nil
}

// CreateFileSend creates a new file Send and returns it along with the access URL.
func (v *Vault) CreateFileSend(name, fileName string, data []byte, opts SendOptions) (*Send, string, error) {
	// Generate send secret and derive key
	secret, err := crypto.GenerateSendSecret()
	if err != nil {
		return nil, "", fmt.Errorf("vault: generate send secret: %w", err)
	}

	sendKey, err := crypto.DeriveSendKey(secret)
	if err != nil {
		return nil, "", fmt.Errorf("vault: derive send key: %w", err)
	}

	// Encrypt send data
	encName, err := crypto.EncryptToEncString([]byte(name), sendKey)
	if err != nil {
		return nil, "", fmt.Errorf("vault: encrypt send name: %w", err)
	}

	encFileName, err := crypto.EncryptToEncString([]byte(fileName), sendKey)
	if err != nil {
		return nil, "", fmt.Errorf("vault: encrypt send file name: %w", err)
	}

	encFileData, err := crypto.EncryptToEncString(data, sendKey)
	if err != nil {
		return nil, "", fmt.Errorf("vault: encrypt send file data: %w", err)
	}
	fileBytes := encFileData.ToBytes()

	// Encrypt the send secret (seed) with the vault symmetric key.
	encSendKey, err := crypto.EncryptToEncString(secret, v.symKey)
	if err != nil {
		return nil, "", fmt.Errorf("vault: encrypt send key: %w", err)
	}

	// Set deletion date
	deletionDate := opts.DeletionDate
	if deletionDate.IsZero() {
		deletionDate = time.Now().Add(7 * 24 * time.Hour)
	}

	fileLen := len(fileBytes)

	req := &api.SendRequest{
		Type:         SendTypeFile,
		Key:          encSendKey.String(),
		Name:         encName.String(),
		DeletionDate: deletionDate.UTC().Format(time.RFC3339),
		File: map[string]any{
			"fileName": encFileName.String(),
		},
		FileLength: &fileLen,
	}

	if opts.Password != "" {
		req.Password = &opts.Password
	}
	if opts.MaxAccessCount != nil {
		req.MaxAccessCount = opts.MaxAccessCount
	}
	if opts.ExpirationDate != nil {
		s := opts.ExpirationDate.UTC().Format(time.RFC3339)
		req.ExpirationDate = &s
	}
	if opts.HideEmail {
		req.HideEmail = &opts.HideEmail
	}

	resp, err := v.client.CreateFileSend(req)
	if err != nil {
		return nil, "", fmt.Errorf("vault: create send metadata: %w", err)
	}

	// Get file Id from response
	var fileID string
	if resp.File != nil {
		if id, ok := resp.File["id"].(string); ok {
			fileID = id
		}
	}

	if fileID != "" {
		_, err = v.client.UploadSendFile(resp.ID, fileID, encFileName.String(), fileBytes)
		if err != nil {
			_ = v.client.DeleteSend(resp.ID)
			return nil, "", fmt.Errorf("vault: upload send file: %w", err)
		}
	} else {
		v.logger.Warn("file id not returned in metadata response, assuming no file upload endpoint required or different format")
	}

	// Build access URL
	accessURL := fmt.Sprintf("%s/#/send/%s/%s",
		v.client.BaseURL(),
		resp.AccessID,
		crypto.EncodeSendSecret(secret),
	)

	send := &Send{
		ID:           resp.ID,
		AccessID:     resp.AccessID,
		Type:         resp.Type,
		Name:         name,
		FileName:     fileName,
		DeletionDate: resp.DeletionDate,
	}

	v.logger.Info("file send created", "id", resp.ID, "accessURL", accessURL)
	return send, accessURL, nil
}

// ListSends returns all sends with decrypted names.
func (v *Vault) ListSends() ([]*Send, error) {
	apiSends, err := v.client.ListSends()
	if err != nil {
		return nil, fmt.Errorf("vault: list sends: %w", err)
	}

	sends := make([]*Send, 0, len(apiSends))
	for _, s := range apiSends {
		send := &Send{
			ID:           s.ID,
			AccessID:     s.AccessID,
			Type:         s.Type,
			AccessCount:  s.AccessCount,
			Disabled:     s.Disabled,
			DeletionDate: s.DeletionDate,
		}

		// Try to decrypt the name
		if s.Key != "" {
			sendKey := v.decryptSendKey(s.Key)
			if sendKey != nil {
				send.Name = decryptString(s.Name, sendKey)
				if s.Text != nil {
					send.Text = decryptString(s.Text.Text, sendKey)
				}
				if s.File != nil {
					if fn, ok := s.File["fileName"].(string); ok {
						send.FileName = decryptString(fn, sendKey)
					}
				}
			}
		}

		sends = append(sends, send)
	}
	return sends, nil
}

// DeleteSend deletes a Send.
func (v *Vault) DeleteSend(id string) error {
	return v.client.DeleteSend(id)
}

// RemoveSendPassword removes the password from a Send.
func (v *Vault) RemoveSendPassword(id string) error {
	return v.client.RemoveSendPassword(id)
}

func (v *Vault) decryptSendKey(encKeyStr string) *crypto.SymmetricKey {
	enc, err := crypto.ParseEncString(encKeyStr)
	if err != nil {
		return nil
	}
	decrypted, err := enc.Decrypt(v.symKey)
	if err != nil {
		return nil
	}
	// The decrypted value is the 16-byte seed, derive the 64-byte key from it
	key, err := crypto.DeriveSendKey(decrypted)
	if err != nil {
		return nil
	}
	return key
}
