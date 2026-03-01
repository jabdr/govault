//go:build integration

package tests

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jabdr/govault/pkg/vault"
)

const testAdminToken = "test-admin-token"

// AdminLogin creates and returns an authenticated Admin client.
func AdminLogin(t *testing.T, serverURL string) *vault.Admin {
	t.Helper()
	adm, err := vault.NewAdmin(serverURL, testAdminToken, true, GetTestLogger())
	require.NoError(t, err, "admin login")
	return adm
}

func TestAdminListUsers(t *testing.T) {
	t.Parallel()
	email := fmt.Sprintf("admin-list-%d@example.com", time.Now().UnixNano())
	password := "test-password-123"

	// Register a user so there's at least one
	RegisterTestUser(t, testServer, email, password)

	adm := AdminLogin(t, testServer)

	users, err := adm.ListUsers()
	require.NoError(t, err, "ListUsers")
	require.NotEmpty(t, users, "Expected at least one user")

	found := false
	for _, u := range users {
		if u.Email == email {
			found = true
			assert.NotEmpty(t, u.ID, "User ID should not be empty")
			break
		}
	}
	assert.True(t, found, "Expected to find user %s in admin user list", email)
}

func TestAdminGetUser(t *testing.T) {
	t.Parallel()
	email := fmt.Sprintf("admin-get-%d@example.com", time.Now().UnixNano())
	password := "test-password-123"

	RegisterTestUser(t, testServer, email, password)

	adm := AdminLogin(t, testServer)

	users, err := adm.ListUsers()
	require.NoError(t, err)

	var userID string
	for _, u := range users {
		if u.Email == email {
			userID = u.ID
			break
		}
	}
	require.NotEmpty(t, userID, "User not found in list")

	user, err := adm.GetUser(userID)
	require.NoError(t, err, "GetUser")
	assert.Equal(t, email, user.Email, "Email mismatch")
	assert.Equal(t, userID, user.ID, "ID mismatch")
}

func TestAdminDisableEnableUser(t *testing.T) {
	t.Parallel()
	email := fmt.Sprintf("admin-disable-%d@example.com", time.Now().UnixNano())
	password := "test-password-123"

	RegisterTestUser(t, testServer, email, password)

	adm := AdminLogin(t, testServer)

	userID := findUserID(t, adm, email)

	// Disable the user
	err := adm.DisableUser(userID)
	require.NoError(t, err, "DisableUser")

	// Verify user is disabled
	user, err := adm.GetUser(userID)
	require.NoError(t, err, "GetUser after disable")
	assert.False(t, user.Enabled, "User should be disabled")

	// Verify login fails for disabled user
	_, err = vault.Login(testServer, email, password, true, GetTestLogger())
	require.Error(t, err, "Login should fail for disabled user")

	// Re-enable the user
	err = adm.EnableUser(userID)
	require.NoError(t, err, "EnableUser")

	// Verify user is enabled
	user, err = adm.GetUser(userID)
	require.NoError(t, err, "GetUser after enable")
	assert.True(t, user.Enabled, "User should be enabled")

	// Verify login succeeds again
	_, err = vault.Login(testServer, email, password, true, GetTestLogger())
	require.NoError(t, err, "Login should succeed for re-enabled user")
}

func TestAdminDeauthUser(t *testing.T) {
	t.Parallel()
	email := fmt.Sprintf("admin-deauth-%d@example.com", time.Now().UnixNano())
	password := "test-password-123"

	RegisterTestUser(t, testServer, email, password)

	adm := AdminLogin(t, testServer)

	userID := findUserID(t, adm, email)

	// Deauth the user (should not error)
	err := adm.DeauthUser(userID)
	require.NoError(t, err, "DeauthUser")

	// User should still be able to log in (deauth just revokes sessions, not access)
	_, err = vault.Login(testServer, email, password, true, GetTestLogger())
	require.NoError(t, err, "Login should succeed after deauth")
}

func TestAdminInviteUser(t *testing.T) {
	t.Parallel()
	email := fmt.Sprintf("admin-invite-%d@example.com", time.Now().UnixNano())

	adm := AdminLogin(t, testServer)

	err := adm.InviteUser(email)
	require.NoError(t, err, "InviteUser")

	// Verify the invited user shows up in the list
	users, err := adm.ListUsers()
	require.NoError(t, err)

	found := false
	for _, u := range users {
		if u.Email == email {
			found = true
			break
		}
	}
	assert.True(t, found, "Invited user %s should appear in user list", email)
}

func TestAdminDeleteUser(t *testing.T) {
	t.Parallel()
	email := fmt.Sprintf("admin-delete-%d@example.com", time.Now().UnixNano())
	password := "test-password-123"

	RegisterTestUser(t, testServer, email, password)

	adm := AdminLogin(t, testServer)

	userID := findUserID(t, adm, email)

	// Delete the user
	err := adm.DeleteUser(userID)
	require.NoError(t, err, "DeleteUser")

	// Verify user is gone
	users, err := adm.ListUsers()
	require.NoError(t, err)
	for _, u := range users {
		assert.NotEqual(t, email, u.Email, "Deleted user should not appear in list")
	}

	// Verify login fails
	_, err = vault.Login(testServer, email, password, true, GetTestLogger())
	require.Error(t, err, "Login should fail for deleted user")
}

func TestAdminListOrganizations(t *testing.T) {
	t.Parallel()
	email := fmt.Sprintf("admin-orgs-%d@example.com", time.Now().UnixNano())
	password := "test-password-123"

	RegisterTestUser(t, testServer, email, password)
	v := APILogin(t, testServer, email, password)

	orgName := fmt.Sprintf("Admin Test Org %d", time.Now().UnixNano())
	_, err := v.CreateOrganization(orgName, email, "Admin Collection")
	require.NoError(t, err, "CreateOrganization")

	adm := AdminLogin(t, testServer)

	orgs, err := adm.ListOrganizations()
	require.NoError(t, err, "ListOrganizations")
	require.NotEmpty(t, orgs, "Expected at least one organization")

	found := false
	for _, o := range orgs {
		if o.Name == orgName {
			found = true
			assert.NotEmpty(t, o.ID, "Org ID should not be empty")
			break
		}
	}
	assert.True(t, found, "Expected to find org %s in admin org list", orgName)
}

func TestAdminDeleteOrganization(t *testing.T) {
	t.Parallel()
	email := fmt.Sprintf("admin-delorg-%d@example.com", time.Now().UnixNano())
	password := "test-password-123"

	RegisterTestUser(t, testServer, email, password)
	v := APILogin(t, testServer, email, password)

	orgName := fmt.Sprintf("Admin Del Org %d", time.Now().UnixNano())
	orgID, err := v.CreateOrganization(orgName, email, "Del Collection")
	require.NoError(t, err, "CreateOrganization")

	adm := AdminLogin(t, testServer)

	// Delete the organization via admin API
	err = adm.DeleteOrganization(orgID)
	require.NoError(t, err, "DeleteOrganization")

	// Verify org is gone
	orgs, err := adm.ListOrganizations()
	require.NoError(t, err)
	for _, o := range orgs {
		assert.NotEqual(t, orgID, o.ID, "Deleted org should not appear in list")
	}
}

// findUserID is a test helper to look up a user's ID by email.
func findUserID(t *testing.T, adm *vault.Admin, email string) string {
	t.Helper()
	users, err := adm.ListUsers()
	require.NoError(t, err, "ListUsers")

	for _, u := range users {
		if u.Email == email {
			return u.ID
		}
	}
	t.Fatalf("user %s not found", email)
	return ""
}
