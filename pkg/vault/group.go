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

// resolveEmailsToMemberIDs resolves a list of emails to their org membership IDs.
func (v *Vault) resolveEmailsToMemberIDs(orgID string, emails []string) ([]string, error) {
	orgMembers, err := v.client.ListOrgMembers(orgID)
	if err != nil {
		return nil, fmt.Errorf("vault: list org members: %w", err)
	}
	idByEmail := make(map[string]string, len(orgMembers))
	for _, m := range orgMembers {
		idByEmail[m.Email] = m.ID
	}

	ids := make([]string, 0, len(emails))
	for _, email := range emails {
		id, ok := idByEmail[email]
		if !ok {
			return nil, fmt.Errorf("vault: member %q not found in organization", email)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// CreateGroup creates a new group. If memberEmails is non-empty, those users
// are added to the group as part of creation.
func (v *Vault) CreateGroup(orgID, name string, accessAll bool, memberEmails []string) (*Group, error) {
	userIDs := make([]string, 0)
	if len(memberEmails) > 0 {
		var err error
		userIDs, err = v.resolveEmailsToMemberIDs(orgID, memberEmails)
		if err != nil {
			return nil, err
		}
	}

	req := &api.GroupRequest{
		Name:        name,
		AccessAll:   accessAll,
		Collections: make([]api.CollectionSelection, 0),
		Users:       userIDs,
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

// UpdateGroup updates a group. If memberEmails is nil, existing members are
// preserved. If memberEmails is non-nil (even if empty), it replaces the
// group's member list.
func (v *Vault) UpdateGroup(orgID, groupID, name string, accessAll bool, memberEmails []string) error {
	group, err := v.GetGroup(orgID, groupID)
	if err != nil {
		return err
	}

	var userIDs []string
	if memberEmails != nil {
		// Caller explicitly set members — resolve and replace.
		userIDs, err = v.resolveEmailsToMemberIDs(orgID, memberEmails)
		if err != nil {
			return err
		}
	} else {
		// No member change requested — preserve existing members.
		userIDs, err = v.client.ListGroupMembers(orgID, groupID)
		if err != nil {
			return fmt.Errorf("vault: list group members: %w", err)
		}
	}
	if userIDs == nil {
		userIDs = make([]string, 0)
	}

	req := &api.GroupRequest{
		Name:        name,
		AccessAll:   accessAll,
		ExternalID:  group.ExternalID,
		Collections: make([]api.CollectionSelection, 0),
		Users:       userIDs,
	}

	_, err = v.client.UpdateGroup(orgID, groupID, req)
	return err
}

// DeleteGroup deletes a group.
func (v *Vault) DeleteGroup(orgID, groupID string) error {
	return v.client.DeleteGroup(orgID, groupID)
}

// GroupMember represents a member within a group, enriched with email.
type GroupMember struct {
	ID    string // membership ID
	Email string
}

// ListGroupMembers returns the members of a group, enriched with emails.
func (v *Vault) ListGroupMembers(orgID, groupID string) ([]GroupMember, error) {
	memberIDs, err := v.client.ListGroupMembers(orgID, groupID)
	if err != nil {
		return nil, fmt.Errorf("vault: list group members: %w", err)
	}

	if len(memberIDs) == 0 {
		return nil, nil
	}

	// Resolve membership IDs to emails
	orgMembers, err := v.client.ListOrgMembers(orgID)
	if err != nil {
		return nil, fmt.Errorf("vault: list org members: %w", err)
	}
	emailByID := make(map[string]string, len(orgMembers))
	for _, m := range orgMembers {
		emailByID[m.ID] = m.Email
	}

	result := make([]GroupMember, 0, len(memberIDs))
	for _, id := range memberIDs {
		result = append(result, GroupMember{
			ID:    id,
			Email: emailByID[id],
		})
	}
	return result, nil
}

// AddGroupMembers adds members to a group by email. It resolves emails to
// membership IDs and merges them with the existing group members before
// sending the full replacement set.
func (v *Vault) AddGroupMembers(orgID, groupID string, emails []string) error {
	newIDs, err := v.resolveEmailsToMemberIDs(orgID, emails)
	if err != nil {
		return err
	}

	// Get existing group members and merge
	existingIDs, err := v.client.ListGroupMembers(orgID, groupID)
	if err != nil {
		return fmt.Errorf("vault: list group members: %w", err)
	}
	seen := make(map[string]bool, len(existingIDs)+len(newIDs))
	merged := make([]string, 0, len(existingIDs)+len(newIDs))
	for _, id := range existingIDs {
		if !seen[id] {
			seen[id] = true
			merged = append(merged, id)
		}
	}
	for _, id := range newIDs {
		if !seen[id] {
			seen[id] = true
			merged = append(merged, id)
		}
	}

	if err := v.client.SetGroupMembers(orgID, groupID, merged); err != nil {
		return fmt.Errorf("vault: set group members: %w", err)
	}
	return nil
}

// RemoveGroupMember removes a single member from a group by membership ID.
func (v *Vault) RemoveGroupMember(orgID, groupID, memberID string) error {
	if err := v.client.RemoveGroupMember(orgID, groupID, memberID); err != nil {
		return fmt.Errorf("vault: remove group member: %w", err)
	}
	return nil
}
