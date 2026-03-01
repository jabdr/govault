package vault

import (
	"log/slog"

	"github.com/jabdr/govault/pkg/api"
)

// Public provides high-level access to the Bitwarden/Vaultwarden Public API.
// It wraps the lower-level api.PublicClient.
type Public struct {
	client *api.PublicClient
}

// NewPublic creates and authenticates a new Public API client.
// The clientID must be in the format "organization.<org_uuid>",
// and clientSecret is the organization API key.
func NewPublic(serverURL, clientID, clientSecret string, insecureSkipVerify bool, logger *slog.Logger) (*Public, error) {
	c := api.NewPublicClient(serverURL, logger)
	if insecureSkipVerify {
		c.SetInsecureSkipVerify(true)
	}

	if err := c.Login(clientID, clientSecret); err != nil {
		return nil, err
	}

	return &Public{client: c}, nil
}

// ImportMember is a member to import into an organization.
type ImportMember struct {
	Email      string
	ExternalID string
	Deleted    bool
}

// ImportGroup is a group to import into an organization.
type ImportGroup struct {
	Name              string
	ExternalID        string
	MemberExternalIDs []string
}

// Import performs a bulk import of members (and optionally groups) into an organization.
// Members who don't have accounts will be created automatically.
// Members will be invited to the organization.
// If overwriteExisting is true, members not in the list will be removed.
func (p *Public) Import(members []ImportMember, groups []ImportGroup, overwriteExisting bool) error {
	apiMembers := make([]api.OrgImportMember, len(members))
	for i, m := range members {
		apiMembers[i] = api.OrgImportMember{
			Email:      m.Email,
			ExternalID: m.ExternalID,
			Deleted:    m.Deleted,
		}
	}

	apiGroups := make([]api.OrgImportGroup, len(groups))
	for i, g := range groups {
		apiGroups[i] = api.OrgImportGroup{
			Name:              g.Name,
			ExternalID:        g.ExternalID,
			MemberExternalIDs: g.MemberExternalIDs,
		}
	}

	return p.client.Import(&api.OrgImportRequest{
		Groups:            apiGroups,
		Members:           apiMembers,
		OverwriteExisting: overwriteExisting,
	})
}

// GetOrgAPIKey retrieves the organization API key for use with the Public API.
// This requires a logged-in Vault client (the caller must be an org owner).
// Returns the clientID ("organization.<org_id>") and the clientSecret (API key).
func (v *Vault) GetOrgAPIKey(orgID string) (string, string, error) {
	return v.client.GetOrgAPIKey(orgID, v.passwordHash)
}
