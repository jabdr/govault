//go:build integration

package tests

import (
	"testing"

	"github.com/jabdr/govault/pkg/api"
	"github.com/stretchr/testify/require"
)

func TestPermissions(t *testing.T) {
	email := "test-perms@example.com"
	password := "test-password-123"

	RegisterTestUser(t, testServer, email, password)
	v := APILogin(t, testServer, email, password)

	orgID, err := v.CreateOrganization("Test Org", email, "Test Col")
	require.NoError(t, err)

	col, err := v.CreateCollection(orgID, "Test Perms Collection")
	require.NoError(t, err)

	err = v.UpdateCollectionPermissions(orgID, col.ID, []api.CollectionGroupAccess{}, []api.CollectionUserAccess{})
	require.NoError(t, err, "UpdateCollectionPermissions empty slices")

	members, err := v.ListOrgMembers(orgID)
	require.NoError(t, err)
	require.NotEmpty(t, members)
	userID := members[0].ID

	var u []api.CollectionUserAccess
	u = []api.CollectionUserAccess{{
		ID:            userID,
		ReadOnly:      true,
		HidePasswords: false,
		Manage:        false,
	}}

	err = v.UpdateCollectionPermissions(orgID, col.ID, nil, u)
	require.NoError(t, err, "UpdateCollectionPermissions user access")
}
