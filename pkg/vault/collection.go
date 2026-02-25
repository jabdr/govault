package vault

import (
	"fmt"

	"github.com/jabdr/govault/pkg/api"
	"github.com/jabdr/govault/pkg/crypto"
)

// Collection represents a decrypted organization collection.
type Collection struct {
	ID             string
	OrganizationID string
	Name           string
	ExternalID     string
}

// ListCollections returns all collections for an organization with decrypted names.
func (v *Vault) ListCollections(orgID string) ([]Collection, error) {
	orgKey, err := v.GetOrgKey(orgID)
	if err != nil {
		return nil, fmt.Errorf("vault: list collections: %w", err)
	}

	apiCols, err := v.client.ListCollections(orgID)
	if err != nil {
		return nil, fmt.Errorf("vault: list collections: %w", err)
	}

	collections := make([]Collection, 0, len(apiCols))
	for _, col := range apiCols {
		name := decryptString(col.Name, orgKey)
		collections = append(collections, Collection{
			ID:             col.ID,
			OrganizationID: col.OrganizationID,
			Name:           name,
			ExternalID:     col.ExternalID,
		})
	}
	return collections, nil
}

// CreateCollection creates a new collection in an organization.
func (v *Vault) CreateCollection(orgID, name string) (*Collection, error) {
	orgKey, err := v.GetOrgKey(orgID)
	if err != nil {
		return nil, fmt.Errorf("vault: create collection: %w", err)
	}

	encName, err := crypto.EncryptToEncString([]byte(name), orgKey)
	if err != nil {
		return nil, fmt.Errorf("vault: encrypt collection name: %w", err)
	}

	resp, err := v.client.CreateCollection(orgID, &api.CreateCollectionRequest{
		Name: encName.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("vault: create collection: %w", err)
	}

	return &Collection{
		ID:             resp.ID,
		OrganizationID: resp.OrganizationID,
		Name:           name,
	}, nil
}

// UpdateCollection updates a collection's name.
func (v *Vault) UpdateCollection(orgID, collectionID, name string) error {
	orgKey, err := v.GetOrgKey(orgID)
	if err != nil {
		return fmt.Errorf("vault: update collection: %w", err)
	}

	encName, err := crypto.EncryptToEncString([]byte(name), orgKey)
	if err != nil {
		return fmt.Errorf("vault: encrypt collection name: %w", err)
	}

	_, err = v.client.UpdateCollection(orgID, collectionID, &api.CreateCollectionRequest{
		Name: encName.String(),
	})
	return err
}

// DeleteCollection deletes a collection from an organization.
func (v *Vault) DeleteCollection(orgID, collectionID string) error {
	return v.client.DeleteCollection(orgID, collectionID)
}

func decryptString(s string, key *crypto.SymmetricKey) string {
	if s == "" || key == nil {
		return s
	}
	enc, err := crypto.ParseEncString(s)
	if err != nil {
		return s
	}
	decrypted, err := enc.Decrypt(key)
	if err != nil {
		return s
	}
	return string(decrypted)
}
