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

func TestPublicAPIImportMembers(t *testing.T) {
	t.Parallel()
	// Setup: create an org owner and org
	ownerEmail := fmt.Sprintf("public-owner-%d@example.com", time.Now().UnixNano())
	password := "test-password-123"

	RegisterTestUser(t, testServer, ownerEmail, password)
	v := APILogin(t, testServer, ownerEmail, password)

	orgName := fmt.Sprintf("Public Test Org %d", time.Now().UnixNano())
	orgID, err := v.CreateOrganization(orgName, ownerEmail, "Default Collection")
	require.NoError(t, err, "CreateOrganization")

	// Get org API key
	clientID, clientSecret, err := v.GetOrgAPIKey(orgID)
	require.NoError(t, err, "GetOrgAPIKey")
	require.Equal(t, "organization."+orgID, clientID, "clientID format")
	require.NotEmpty(t, clientSecret, "clientSecret should not be empty")

	t.Logf("Org ID: %s, Client ID: %s", orgID, clientID)

	// Create a Public API client
	pub, err := vault.NewPublic(testServer, clientID, clientSecret, true, GetTestLogger())
	require.NoError(t, err, "NewPublic")

	// Import members
	importEmail1 := fmt.Sprintf("import-member1-%d@example.com", time.Now().UnixNano())
	importEmail2 := fmt.Sprintf("import-member2-%d@example.com", time.Now().UnixNano())

	members := []vault.ImportMember{
		{Email: importEmail1, ExternalID: "ext-1"},
		{Email: importEmail2, ExternalID: "ext-2"},
	}

	err = pub.Import(members, nil, false)
	require.NoError(t, err, "Import")

	// Verify the members appear in the org member list
	orgMembers, err := v.ListOrgMembers(orgID)
	require.NoError(t, err, "ListOrgMembers")

	foundEmails := make(map[string]bool)
	for _, m := range orgMembers {
		foundEmails[m.Email] = true
	}
	assert.True(t, foundEmails[importEmail1], "Expected %s in org members", importEmail1)
	assert.True(t, foundEmails[importEmail2], "Expected %s in org members", importEmail2)
}

func TestPublicAPIImportWithGroups(t *testing.T) {
	t.Parallel()
	ownerEmail := fmt.Sprintf("public-groups-%d@example.com", time.Now().UnixNano())
	password := "test-password-123"

	RegisterTestUser(t, testServer, ownerEmail, password)
	v := APILogin(t, testServer, ownerEmail, password)

	orgName := fmt.Sprintf("Public Groups Org %d", time.Now().UnixNano())
	orgID, err := v.CreateOrganization(orgName, ownerEmail, "Default Collection")
	require.NoError(t, err, "CreateOrganization")

	clientID, clientSecret, err := v.GetOrgAPIKey(orgID)
	require.NoError(t, err, "GetOrgAPIKey")

	pub, err := vault.NewPublic(testServer, clientID, clientSecret, true, GetTestLogger())
	require.NoError(t, err, "NewPublic")

	memberEmail := fmt.Sprintf("import-grp-member-%d@example.com", time.Now().UnixNano())

	members := []vault.ImportMember{
		{Email: memberEmail, ExternalID: "grp-ext-1"},
	}
	groups := []vault.ImportGroup{
		{
			Name:              "Test Import Group",
			ExternalID:        "grp-ext-id-1",
			MemberExternalIDs: []string{"grp-ext-1"},
		},
	}

	err = pub.Import(members, groups, false)
	require.NoError(t, err, "Import with groups")

	// Verify member is in org
	orgMembers, err := v.ListOrgMembers(orgID)
	require.NoError(t, err, "ListOrgMembers")

	found := false
	for _, m := range orgMembers {
		if m.Email == memberEmail {
			found = true
			break
		}
	}
	assert.True(t, found, "Expected %s in org members", memberEmail)
}

func TestPublicAPIImportOverwrite(t *testing.T) {
	t.Parallel()
	ownerEmail := fmt.Sprintf("public-overwrite-%d@example.com", time.Now().UnixNano())
	password := "test-password-123"

	RegisterTestUser(t, testServer, ownerEmail, password)
	v := APILogin(t, testServer, ownerEmail, password)

	orgName := fmt.Sprintf("Public Overwrite Org %d", time.Now().UnixNano())
	orgID, err := v.CreateOrganization(orgName, ownerEmail, "Default Collection")
	require.NoError(t, err, "CreateOrganization")

	clientID, clientSecret, err := v.GetOrgAPIKey(orgID)
	require.NoError(t, err, "GetOrgAPIKey")

	pub, err := vault.NewPublic(testServer, clientID, clientSecret, true, GetTestLogger())
	require.NoError(t, err, "NewPublic")

	// First import: add two members
	email1 := fmt.Sprintf("overwrite-m1-%d@example.com", time.Now().UnixNano())
	email2 := fmt.Sprintf("overwrite-m2-%d@example.com", time.Now().UnixNano())

	err = pub.Import([]vault.ImportMember{
		{Email: email1, ExternalID: "ow-ext-1"},
		{Email: email2, ExternalID: "ow-ext-2"},
	}, nil, false)
	require.NoError(t, err, "First import")

	// Verify both are present
	orgMembers, err := v.ListOrgMembers(orgID)
	require.NoError(t, err, "ListOrgMembers after first import")

	foundEmails := make(map[string]bool)
	for _, m := range orgMembers {
		foundEmails[m.Email] = true
	}
	require.True(t, foundEmails[email1], "email1 should be in org after first import")
	require.True(t, foundEmails[email2], "email2 should be in org after first import")

	// Second import with overwrite: only keep email1
	err = pub.Import([]vault.ImportMember{
		{Email: email1, ExternalID: "ow-ext-1"},
	}, nil, true)
	require.NoError(t, err, "Overwrite import")

	// Verify email2 is removed
	orgMembers, err = v.ListOrgMembers(orgID)
	require.NoError(t, err, "ListOrgMembers after overwrite")

	foundEmails = make(map[string]bool)
	for _, m := range orgMembers {
		foundEmails[m.Email] = true
	}
	assert.True(t, foundEmails[email1], "email1 should still be in org")
	assert.False(t, foundEmails[email2], "email2 should be removed after overwrite")
}

func TestPublicAPIImportDeleteMember(t *testing.T) {
	t.Parallel()
	ownerEmail := fmt.Sprintf("public-delete-%d@example.com", time.Now().UnixNano())
	password := "test-password-123"

	RegisterTestUser(t, testServer, ownerEmail, password)
	v := APILogin(t, testServer, ownerEmail, password)

	orgName := fmt.Sprintf("Public Delete Org %d", time.Now().UnixNano())
	orgID, err := v.CreateOrganization(orgName, ownerEmail, "Default Collection")
	require.NoError(t, err, "CreateOrganization")

	clientID, clientSecret, err := v.GetOrgAPIKey(orgID)
	require.NoError(t, err, "GetOrgAPIKey")

	pub, err := vault.NewPublic(testServer, clientID, clientSecret, true, GetTestLogger())
	require.NoError(t, err, "NewPublic")

	// Import a member
	memberEmail := fmt.Sprintf("delete-member-%d@example.com", time.Now().UnixNano())
	err = pub.Import([]vault.ImportMember{
		{Email: memberEmail, ExternalID: "del-ext-1"},
	}, nil, false)
	require.NoError(t, err, "Import member")

	// Verify member is in org
	orgMembers, err := v.ListOrgMembers(orgID)
	require.NoError(t, err, "ListOrgMembers")
	found := false
	for _, m := range orgMembers {
		if m.Email == memberEmail {
			found = true
			break
		}
	}
	require.True(t, found, "Member should be in org")

	// "Delete" the member (set deleted=true, which revokes them)
	err = pub.Import([]vault.ImportMember{
		{Email: memberEmail, ExternalID: "del-ext-1", Deleted: true},
	}, nil, false)
	require.NoError(t, err, "Import with deleted=true")
}

func TestGetOrgAPIKey(t *testing.T) {
	t.Parallel()
	email := fmt.Sprintf("org-apikey-%d@example.com", time.Now().UnixNano())
	password := "test-password-123"

	RegisterTestUser(t, testServer, email, password)
	v := APILogin(t, testServer, email, password)

	orgName := fmt.Sprintf("API Key Test Org %d", time.Now().UnixNano())
	orgID, err := v.CreateOrganization(orgName, email, "Default Collection")
	require.NoError(t, err, "CreateOrganization")

	clientID, clientSecret, err := v.GetOrgAPIKey(orgID)
	require.NoError(t, err, "GetOrgAPIKey")

	assert.Equal(t, "organization."+orgID, clientID, "clientID should have org prefix")
	assert.NotEmpty(t, clientSecret, "clientSecret should not be empty")

	t.Logf("Org API Key - Client ID: %s, Secret length: %d", clientID, len(clientSecret))
}
