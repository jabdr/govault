package vault

import (
	"log/slog"

	"github.com/jabdr/govault/pkg/api"
)

// Admin provides high-level access to the Vaultwarden admin API.
// It wraps the lower-level api.AdminClient.
type Admin struct {
	client *api.AdminClient
}

// NewAdmin creates and authenticates a new Admin client.
func NewAdmin(serverURL, adminToken string, insecureSkipVerify bool, logger *slog.Logger) (*Admin, error) {
	c := api.NewAdminClient(serverURL, logger)
	if insecureSkipVerify {
		c.SetInsecureSkipVerify(true)
	}

	if err := c.Login(adminToken); err != nil {
		return nil, err
	}

	return &Admin{client: c}, nil
}

// Client returns the underlying AdminClient for direct API access.
func (a *Admin) Client() *api.AdminClient {
	return a.client
}

// ListUsers returns all users from the Vaultwarden instance.
func (a *Admin) ListUsers() ([]api.AdminUser, error) {
	return a.client.ListUsers()
}

// GetUser returns a specific user by ID.
func (a *Admin) GetUser(userID string) (*api.AdminUser, error) {
	return a.client.GetUser(userID)
}

// InviteUser sends an invitation to the given email address.
func (a *Admin) InviteUser(email string) error {
	return a.client.InviteUser(email)
}

// DeleteUser deletes a user by ID.
func (a *Admin) DeleteUser(userID string) error {
	return a.client.DeleteUser(userID)
}

// DisableUser disables a user by ID.
func (a *Admin) DisableUser(userID string) error {
	return a.client.DisableUser(userID)
}

// EnableUser enables a user by ID.
func (a *Admin) EnableUser(userID string) error {
	return a.client.EnableUser(userID)
}

// DeauthUser deauthenticates all sessions for a user by ID.
func (a *Admin) DeauthUser(userID string) error {
	return a.client.DeauthUser(userID)
}

// Remove2FA removes two-factor authentication for a user by ID.
func (a *Admin) Remove2FA(userID string) error {
	return a.client.Remove2FA(userID)
}

// ResendInvite re-sends the invitation email for a user by ID.
func (a *Admin) ResendInvite(userID string) error {
	return a.client.ResendInvite(userID)
}

// ListOrganizations returns all organizations from the Vaultwarden instance.
func (a *Admin) ListOrganizations() ([]api.AdminOrganization, error) {
	return a.client.ListOrganizations()
}

// DeleteOrganization deletes an organization by ID.
func (a *Admin) DeleteOrganization(orgID string) error {
	return a.client.DeleteOrganization(orgID)
}
