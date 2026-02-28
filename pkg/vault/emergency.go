package vault

import (
	"encoding/base64"
	"fmt"

	"github.com/jabdr/govault/pkg/api"
	"github.com/jabdr/govault/pkg/crypto"
)

// EmergencyAccessInfo holds emergency access details.
type EmergencyAccessInfo struct {
	ID           string
	GrantorID    string
	GranteeID    string
	Email        string
	Name         string
	Type         int // 0=View, 1=Takeover
	Status       int
	WaitTimeDays int
}

func emergencyFromAPI(ea api.EmergencyAccessResponse) EmergencyAccessInfo {
	return EmergencyAccessInfo{
		ID:           ea.ID,
		GrantorID:    ea.GrantorID,
		GranteeID:    ea.GranteeID,
		Email:        ea.Email,
		Name:         ea.Name,
		Type:         ea.Type,
		Status:       ea.Status,
		WaitTimeDays: ea.WaitTimeDays,
	}
}

// Grantor operations

// InviteEmergencyAccess invites a new emergency contact.
func (v *Vault) InviteEmergencyAccess(email string, accessType, waitTimeDays int) error {
	return v.client.InviteEmergencyAccess(&api.EmergencyAccessInviteRequest{
		Email:        email,
		Type:         accessType,
		WaitTimeDays: waitTimeDays,
	})
}

// ListTrustedEmergencyAccess lists your emergency contacts (grantor view).
func (v *Vault) ListTrustedEmergencyAccess() ([]EmergencyAccessInfo, error) {
	list, err := v.client.ListTrustedEmergencyAccess()
	if err != nil {
		return nil, err
	}
	result := make([]EmergencyAccessInfo, len(list))
	for i, ea := range list {
		result[i] = emergencyFromAPI(ea)
	}
	return result, nil
}

// ConfirmEmergencyAccess confirms a grantee by RSA-encrypting your
// symmetric key with their public key.
func (v *Vault) ConfirmEmergencyAccess(emergencyAccessID string) error {
	// Get the emergency access to find the grantee
	ea, err := v.client.GetEmergencyAccess(emergencyAccessID)
	if err != nil {
		return fmt.Errorf("vault: get emergency access: %w", err)
	}

	if ea.GranteeID == "" {
		return fmt.Errorf("vault: no grantee ID for emergency access %s", emergencyAccessID)
	}

	// Fetch grantee's public key
	pubKeyBase64, err := v.client.GetUserPublicKey(ea.GranteeID)
	if err != nil {
		return fmt.Errorf("vault: get grantee public key: %w", err)
	}

	pubKeyDER, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		return fmt.Errorf("vault: decode grantee public key: %w", err)
	}

	// RSA-encrypt our symmetric key with the grantee's public key
	encKeyStr, err := crypto.EncryptOrgKeyForMember(v.symKey, pubKeyDER)
	if err != nil {
		return fmt.Errorf("vault: rsa-encrypt for emergency access: %w", err)
	}

	return v.client.ConfirmEmergencyAccess(emergencyAccessID, &api.EmergencyAccessConfirmRequest{
		Key: encKeyStr,
	})
}

// ApproveEmergencyAccess approves an emergency access request.
func (v *Vault) ApproveEmergencyAccess(emergencyAccessID string) error {
	return v.client.ApproveEmergencyAccess(emergencyAccessID)
}

// RejectEmergencyAccess rejects an emergency access request.
func (v *Vault) RejectEmergencyAccess(emergencyAccessID string) error {
	return v.client.RejectEmergencyAccess(emergencyAccessID)
}

// RevokeEmergencyAccess revokes/deletes an emergency access grant.
func (v *Vault) RevokeEmergencyAccess(emergencyAccessID string) error {
	return v.client.DeleteEmergencyAccess(emergencyAccessID)
}

// Grantee operations

// ListGrantedEmergencyAccess lists who granted you access (grantee view).
func (v *Vault) ListGrantedEmergencyAccess() ([]EmergencyAccessInfo, error) {
	list, err := v.client.ListGrantedEmergencyAccess()
	if err != nil {
		return nil, err
	}
	result := make([]EmergencyAccessInfo, len(list))
	for i, ea := range list {
		result[i] = emergencyFromAPI(ea)
	}
	return result, nil
}

// AcceptEmergencyAccess accepts an emergency access invitation.
func (v *Vault) AcceptEmergencyAccess(emergencyAccessID, token string) error {
	return v.client.AcceptEmergencyAccess(emergencyAccessID, &api.EmergencyAccessAcceptRequest{
		Token: token,
	})
}

// InitiateEmergencyAccess starts the emergency access countdown.
func (v *Vault) InitiateEmergencyAccess(emergencyAccessID string) error {
	return v.client.InitiateEmergencyAccess(emergencyAccessID)
}

// ViewEmergencyVault retrieves and decrypts the grantor's vault ciphers
// after emergency access has been approved.
func (v *Vault) ViewEmergencyVault(emergencyAccessID string) ([]*Cipher, error) {
	resp, err := v.client.ViewEmergencyAccess(emergencyAccessID)
	if err != nil {
		return nil, fmt.Errorf("vault: view emergency vault: %w", err)
	}

	// Decrypt the grantor's symmetric key using our RSA private key
	grantorKey, err := v.decryptEmergencyKey(resp.KeyEncrypted)
	if err != nil {
		return nil, fmt.Errorf("vault: decrypt emergency key: %w", err)
	}

	ciphers := make([]*Cipher, 0, len(resp.Ciphers))
	for _, raw := range resp.Ciphers {
		ciphers = append(ciphers, NewCipherFromMap(raw, grantorKey))
	}
	return ciphers, nil
}

// TakeoverEmergencyAccess takes over a grantor's account, setting a new
// master password.
func (v *Vault) TakeoverEmergencyAccess(emergencyAccessID, newPassword string) error {
	// Get takeover data (KDF params + encrypted key)
	takeover, err := v.client.TakeoverEmergencyAccess(emergencyAccessID)
	if err != nil {
		return fmt.Errorf("vault: takeover: %w", err)
	}

	// Decrypt the grantor's symmetric key using our RSA private key
	grantorSymKey, err := v.decryptEmergencyKey(takeover.KeyEncrypted)
	if err != nil {
		return fmt.Errorf("vault: decrypt takeover key: %w", err)
	}

	// Derive new master key for the grantor using the new password
	// Note: we use the grantor's email as salt, but we don't have it here.
	// In practice, the emergency access response should provide the email,
	// or we derive from the emergency access details.
	ea, err := v.client.GetEmergencyAccess(emergencyAccessID)
	if err != nil {
		return fmt.Errorf("vault: get emergency access for takeover: %w", err)
	}

	newMasterKey, err := crypto.DeriveKey(
		[]byte(newPassword), []byte(ea.Email),
		takeover.Kdf, takeover.KdfIterations,
		takeover.KdfMemory, takeover.KdfParallelism,
	)
	if err != nil {
		return fmt.Errorf("vault: derive new master key: %w", err)
	}

	newStretched, err := crypto.StretchKey(newMasterKey)
	if err != nil {
		return fmt.Errorf("vault: stretch new key: %w", err)
	}

	stretchedKey, err := crypto.MakeSymmetricKey(newStretched)
	if err != nil {
		return fmt.Errorf("vault: make stretched key: %w", err)
	}

	// Re-encrypt the grantor's symmetric key with the new stretched key
	newProtectedKey, err := crypto.EncryptToEncString(grantorSymKey.Bytes(), stretchedKey)
	if err != nil {
		return fmt.Errorf("vault: encrypt new protected key: %w", err)
	}

	newPasswordHash := crypto.HashPassword(newPassword, newMasterKey)

	return v.client.SetEmergencyAccessPassword(emergencyAccessID, &api.EmergencyAccessPasswordRequest{
		NewMasterPasswordHash: newPasswordHash,
		Key:                   newProtectedKey.String(),
	})
}

func (v *Vault) decryptEmergencyKey(encKeyStr string) (*crypto.SymmetricKey, error) {
	if v.privateKey == nil {
		return nil, fmt.Errorf("vault: no RSA private key for emergency key decryption")
	}

	encKey, err := crypto.ParseEncString(encKeyStr)
	if err != nil {
		return nil, fmt.Errorf("vault: parse emergency key: %w", err)
	}

	var decrypted []byte
	if encKey.Type == 4 {
		decrypted, err = crypto.RSADecryptEncString(encKey, v.privateKey)
	} else {
		// Some implementations might use the member's public key differently
		keyBytes, err2 := base64.StdEncoding.DecodeString(encKeyStr)
		if err2 != nil {
			return nil, fmt.Errorf("vault: decode emergency key: %w", err2)
		}
		decrypted, err = crypto.RSADecrypt(keyBytes, v.privateKey)
	}
	if err != nil {
		return nil, fmt.Errorf("vault: decrypt emergency key: %w", err)
	}

	return crypto.MakeSymmetricKey(decrypted)
}
