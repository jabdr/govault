package vault

import (
	"encoding/base64"
	"fmt"

	"github.com/jabdr/govault/pkg/api"
	"github.com/jabdr/govault/pkg/crypto"
)

// OrgInfo holds basic organization information.
type OrgInfo struct {
	ID   string
	Name string
}

// CreateOrganization creates a new organization with the given name,
// generating the necessary encryption keys.
func (v *Vault) CreateOrganization(name, billingEmail, collectionName string) (string, error) {
	// Generate org symmetric key
	orgKey, err := crypto.GenerateSymmetricKey()
	if err != nil {
		return "", fmt.Errorf("vault: generate org key: %w", err)
	}

	// Generate RSA key pair for the org
	pubDER, privDER, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		return "", fmt.Errorf("vault: generate org RSA key pair: %w", err)
	}

	// Encrypt org symmetric key with our RSA public key (it will be stored
	// as the owner's org key, decryptable with our private key)
	encOrgKey, err := crypto.EncryptOrgKeyForMember(orgKey, pubDER)
	if err != nil {
		return "", fmt.Errorf("vault: encrypt org key: %w", err)
	}

	// Encrypt the org private key with the org symmetric key
	encPrivKey, err := crypto.EncryptToEncString(privDER, orgKey)
	if err != nil {
		return "", fmt.Errorf("vault: encrypt org private key: %w", err)
	}

	// Encode public key as base64
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubDER)

	resp, err := v.client.CreateOrganization(&api.CreateOrgRequest{
		Name:           name,
		BillingEmail:   billingEmail,
		CollectionName: collectionName,
		Key:            encOrgKey,
		Keys: &api.OrgKeyData{
			EncryptedPrivateKey: encPrivKey.String(),
			PublicKey:           pubKeyB64,
		},
		PlanType: 0,
	})
	if err != nil {
		return "", fmt.Errorf("vault: create organization: %w", err)
	}

	// Cache the org key
	v.orgKeys[resp.ID] = orgKey
	v.logger.Info("organization created", "id", resp.ID, "name", name)
	return resp.ID, nil
}

// ListOrganizations returns organizations from the last sync.
func (v *Vault) ListOrganizations() ([]OrgInfo, error) {
	if v.syncData == nil {
		if err := v.Sync(); err != nil {
			return nil, err
		}
	}

	orgs := make([]OrgInfo, 0, len(v.syncData.Profile.Organizations))
	for _, org := range v.syncData.Profile.Organizations {
		orgs = append(orgs, OrgInfo{ID: org.ID, Name: org.Name})
	}
	return orgs, nil
}

// InviteToOrganization invites email addresses to an organization.
func (v *Vault) InviteToOrganization(orgID string, emails []string, memberType int) error {
	return v.client.InviteToOrganization(orgID, &api.InviteRequest{
		Emails: emails,
		Type:   memberType,
	})
}

// ConfirmMember confirms a pending organization member by RSA-encrypting
// the org symmetric key with the member's public key.
func (v *Vault) ConfirmMember(orgID, memberID string) error {
	orgKey, err := v.GetOrgKey(orgID)
	if err != nil {
		return fmt.Errorf("vault: confirm member: %w", err)
	}

	// Get the member's public key
	pubKeys, err := v.client.GetOrgMemberPublicKeys(orgID, []string{memberID})
	if err != nil {
		return fmt.Errorf("vault: get member public key: %w", err)
	}

	if len(pubKeys) == 0 {
		return fmt.Errorf("vault: no public key found for member %s", memberID)
	}

	memberPubKeyDER, err := base64.StdEncoding.DecodeString(pubKeys[0].Key)
	if err != nil {
		return fmt.Errorf("vault: decode member public key: %w", err)
	}

	encKey, err := crypto.EncryptOrgKeyForMember(orgKey, memberPubKeyDER)
	if err != nil {
		return fmt.Errorf("vault: encrypt org key for member: %w", err)
	}

	return v.client.ConfirmOrgMember(orgID, memberID, &api.ConfirmMemberRequest{
		Key: encKey,
	})
}

// ListOrgMembers lists all members of an organization.
func (v *Vault) ListOrgMembers(orgID string) ([]api.OrgMember, error) {
	return v.client.ListOrgMembers(orgID)
}

// RemoveMember removes a member from an organization.
func (v *Vault) RemoveMember(orgID, memberID string) error {
	return v.client.RemoveOrgMember(orgID, memberID)
}

// ListOrgCiphers returns all ciphers for an organization, decrypted.
func (v *Vault) ListOrgCiphers(orgID string) ([]*Cipher, error) {
	orgKey, err := v.GetOrgKey(orgID)
	if err != nil {
		return nil, fmt.Errorf("vault: list org ciphers: %w", err)
	}

	rawCiphers, err := v.client.GetOrgCiphers(orgID)
	if err != nil {
		return nil, fmt.Errorf("vault: get org ciphers: %w", err)
	}

	ciphers := make([]*Cipher, 0, len(rawCiphers))
	for _, raw := range rawCiphers {
		ciphers = append(ciphers, NewCipherFromMap(raw, orgKey))
	}
	return ciphers, nil
}

// CreateOrgCipher creates a cipher in an organization.
func (v *Vault) CreateOrgCipher(orgID, collectionID string, c *Cipher) error {
	orgKey, err := v.GetOrgKey(orgID)
	if err != nil {
		return fmt.Errorf("vault: create org cipher: %w", err)
	}

	encrypted, err := c.Encrypt(orgKey)
	if err != nil {
		return fmt.Errorf("vault: encrypt org cipher: %w", err)
	}

	encrypted["organizationId"] = orgID
	if collectionID != "" {
		encrypted["collectionIds"] = []string{collectionID}
	}

	resp, err := v.client.CreateCipher(encrypted)
	if err != nil {
		return fmt.Errorf("vault: create org cipher: %w", err)
	}
	c.data = resp
	return nil
}
