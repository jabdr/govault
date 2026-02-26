//go:build integration

package tests

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jabdr/govault/pkg/vault"
)

var testServer string

func TestMain(m *testing.M) {
	url, teardown := SetupTestServer()
	testServer = url
	defer teardown()

	fmt.Printf("Running integration tests against Vaultwarden at %s\n", testServer)
	os.Exit(m.Run())
}

func TestCipherCRUDLifecycle(t *testing.T) {
	email := "test-crud@example.com"
	password := "test-password-123"

	// Register user
	RegisterTestUser(t, testServer, email, password)

	// Login
	v := APILogin(t, testServer, email, password)

	// Create
	c := vault.NewCipher(vault.CipherTypeLogin, "Integration Test Login")
	c.SetLogin("testuser", "testpass")
	err := v.CreateCipher(c)
	require.NoError(t, err, "CreateCipher")
	t.Logf("Created cipher: %s", c.ID())

	// Read
	fetched, err := v.GetCipher(c.ID())
	require.NoError(t, err, "GetCipher")
	assert.Equal(t, "Integration Test Login", fetched.Name(), "Name mismatch")

	// Update
	c.SetField("name", "Updated Login")
	err = v.UpdateCipher(c)
	require.NoError(t, err, "UpdateCipher")

	// Delete
	err = v.DeleteCipher(c.ID())
	require.NoError(t, err, "DeleteCipher")
	t.Log("Cipher CRUD lifecycle complete")
}

func TestSendLifecycle(t *testing.T) {
	email := "test-send@example.com"
	password := "test-password-123"

	// Register user
	RegisterTestUser(t, testServer, email, password)

	v := APILogin(t, testServer, email, password)

	// Create
	send, accessURL, err := v.CreateTextSend("Test Send", "secret content", vault.SendOptions{})
	require.NoError(t, err, "CreateTextSend")
	t.Logf("Created send: %s, URL: %s", send.ID, accessURL)

	// List
	sends, err := v.ListSends()
	require.NoError(t, err, "ListSends")
	found := false
	for _, s := range sends {
		if s.ID == send.ID {
			found = true
			break
		}
	}
	assert.True(t, found, "Created send not found in list")

	// Delete
	err = v.DeleteSend(send.ID)
	require.NoError(t, err, "DeleteSend")
	t.Log("Send lifecycle complete")
}

func TestEmergencyAccessLifecycle(t *testing.T) {
	email := "test-ea-grantor@example.com"
	password := "test-password-123"

	// Register user
	RegisterTestUser(t, testServer, email, password)

	v := APILogin(t, testServer, email, password)

	// List trusted (grantor view)
	trusted, err := v.ListTrustedEmergencyAccess()
	require.NoError(t, err, "ListTrustedEmergencyAccess")
	t.Logf("Trusted emergency contacts: %d", len(trusted))

	// Invite
	err = v.InviteEmergencyAccess("grantee@example.com", 0, 7)
	if err != nil {
		t.Logf("InviteEmergencyAccess: %v (may require mail)", err)
	}

	t.Log("Emergency access lifecycle test complete")
}

func TestAPIKeyLogin(t *testing.T) {
	email := "test-apikey@example.com"
	password := "test-password-123"

	// Register user
	RegisterTestUser(t, testServer, email, password)

	// Login with standard method
	v := APILogin(t, testServer, email, password)

	// Get API Key
	clientID, clientSecret, err := v.GetAPIKey()
	require.NoError(t, err, "GetAPIKey")
	require.NotEmpty(t, clientID, "Client ID should not be empty")
	require.NotEmpty(t, clientSecret, "Client Secret should not be empty")

	// Now try logging in with the API key
	v2, err := vault.LoginAPIKey(testServer, clientID, clientSecret, email, password, GetTestLogger())
	require.NoError(t, err, "API Key Login should succeed")

	c := vault.NewCipher(vault.CipherTypeLogin, "Integration Test Login API Key")
	c.SetLogin("testuser", "testpass")
	err = v2.CreateCipher(c)
	require.NoError(t, err, "CreateCipher with API key login")

	fetched, err := v2.GetCipher(c.ID())
	require.NoError(t, err, "GetCipher with API key login")
	assert.Equal(t, "Integration Test Login API Key", fetched.Name(), "Name mismatch")
}
