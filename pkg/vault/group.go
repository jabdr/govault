package vault

import (
	"fmt"

	"github.com/jabdr/govault/pkg/api"
)

// Group represents an organization group.
type Group struct {
	ID             string
	OrganizationID string
	Name           string
	AccessAll      bool
	ExternalID     string
}

// ListGroups returns all groups for an organization.
func (v *Vault) ListGroups(orgID string) ([]Group, error) {
	apiGroups, err := v.client.ListGroups(orgID)
	if err != nil {
		return nil, fmt.Errorf("vault: list groups: %w", err)
	}

	groups := make([]Group, 0, len(apiGroups))
	for _, g := range apiGroups {
		groups = append(groups, Group{
			ID:             g.ID,
			OrganizationID: g.OrganizationID,
			Name:           g.Name,
			AccessAll:      g.AccessAll,
			ExternalID:     g.ExternalID,
		})
	}
	return groups, nil
}

// GetGroup returns a group by ID.
func (v *Vault) GetGroup(orgID, groupID string) (*Group, error) {
	groups, err := v.ListGroups(orgID)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if g.ID == groupID {
			return &g, nil
		}
	}
	return nil, fmt.Errorf("vault: group not found")
}

// CreateGroup creates a new group.
func (v *Vault) CreateGroup(orgID, name string, accessAll bool) (*Group, error) {
	req := &api.GroupRequest{
		Name:        name,
		AccessAll:   accessAll,
		Collections: make([]api.CollectionSelection, 0),
	}
	resp, err := v.client.CreateGroup(orgID, req)
	if err != nil {
		return nil, fmt.Errorf("vault: create group: %w", err)
	}

	return &Group{
		ID:             resp.ID,
		OrganizationID: resp.OrganizationID,
		Name:           resp.Name,
		AccessAll:      resp.AccessAll,
		ExternalID:     resp.ExternalID,
	}, nil
}

// UpdateGroup updates a group.
func (v *Vault) UpdateGroup(orgID, groupID, name string, accessAll bool) error {
	group, err := v.GetGroup(orgID, groupID)
	if err != nil {
		return err
	}

	req := &api.GroupRequest{
		Name:        name,
		AccessAll:   accessAll,
		ExternalID:  group.ExternalID,
		Collections: make([]api.CollectionSelection, 0),
	}

	_, err = v.client.UpdateGroup(orgID, groupID, req)
	return err
}

// DeleteGroup deletes a group.
func (v *Vault) DeleteGroup(orgID, groupID string) error {
	return v.client.DeleteGroup(orgID, groupID)
}
