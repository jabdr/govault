package vault

import (
	"fmt"
	"strings"

	"github.com/jabdr/govault/pkg/api"
	"github.com/jabdr/govault/pkg/crypto"
)

// Collection represents a decrypted organization collection.
type Collection struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organizationId"`
	Name           string `json:"name"`
	ExternalID     string `json:"externalId"`
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

// ListSyncCollections returns collections from the cached sync data for the
// given organization, without making any API calls.
func (v *Vault) ListSyncCollections(orgID string) ([]Collection, error) {
	if v.syncData == nil {
		return nil, fmt.Errorf("vault: no sync data available")
	}

	orgKey, err := v.GetOrgKey(orgID)
	if err != nil {
		return nil, fmt.Errorf("vault: list sync collections: %w", err)
	}

	var collections []Collection
	for _, raw := range v.syncData.Collections {
		// Match by organization ID (case-insensitive)
		colOrgID, _ := raw["organizationId"].(string)
		if !strings.EqualFold(colOrgID, orgID) {
			continue
		}

		colID, _ := raw["id"].(string)
		encName, _ := raw["name"].(string)
		extID, _ := raw["externalId"].(string)

		name := decryptString(encName, orgKey)
		collections = append(collections, Collection{
			ID:             colID,
			OrganizationID: colOrgID,
			Name:           name,
			ExternalID:     extID,
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
		Name:   encName.String(),
		Groups: make([]api.CollectionGroupAccess, 0),
		Users:  make([]api.CollectionUserAccess, 0),
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

// GetCollection returns a decrypted collection by ID.
func (v *Vault) GetCollection(orgID, collectionID string) (*Collection, error) {
	cols, err := v.ListCollections(orgID)
	if err != nil {
		return nil, err
	}
	for _, c := range cols {
		if c.ID == collectionID {
			return &c, nil
		}
	}
	return nil, fmt.Errorf("vault: collection not found")
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
		Name:   encName.String(),
		Groups: make([]api.CollectionGroupAccess, 0),
		Users:  make([]api.CollectionUserAccess, 0),
	})
	return err
}

// UpdateCollectionPermissions updates a collection's groups and users access.
func (v *Vault) UpdateCollectionPermissions(orgID, collectionID string, groups []api.CollectionGroupAccess, users []api.CollectionUserAccess) error {
	col, err := v.GetCollection(orgID, collectionID)
	if err != nil {
		return err
	}

	orgKey, err := v.GetOrgKey(orgID)
	if err != nil {
		return fmt.Errorf("vault: update collection perms org key: %w", err)
	}

	encName, err := crypto.EncryptToEncString([]byte(col.Name), orgKey)
	if err != nil {
		return fmt.Errorf("vault: encrypt collection name: %w", err)
	}

	if groups == nil {
		groups = make([]api.CollectionGroupAccess, 0)
	}
	if users == nil {
		users = make([]api.CollectionUserAccess, 0)
	}

	_, err = v.client.UpdateCollection(orgID, collectionID, &api.CreateCollectionRequest{
		Name:       encName.String(),
		ExternalID: col.ExternalID,
		Groups:     groups,
		Users:      users,
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
