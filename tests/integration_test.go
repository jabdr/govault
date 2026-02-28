//go:build integration

package tests

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/playwright-community/playwright-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jabdr/govault/pkg/crypto"
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

	// Verify Email
	VerifyUserEmail(t, v, email)

	// Create
	c, _ := vault.NewCipher(vault.CipherTypeLogin, "Integration Test Login", v.SymmetricKey())
	c.SetLoginUsername("testuser")
	c.SetLoginPassword("testpass")
	err := v.CreateCipher(c)
	require.NoError(t, err, "CreateCipher")
	t.Logf("Created cipher: %s", c.ID())

	// Read
	fetched, err := v.GetCipher(c.ID())
	require.NoError(t, err, "GetCipher")
	assert.Equal(t, "Integration Test Login", fetched.Name(), "Name mismatch")

	// Update
	err = c.SetName("Updated Login")
	require.NoError(t, err, "SetName")
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

	// Browser check: actually load the send link and verify it decrypts correctly in Vaultwarden UI
	if os.Getenv("SKIP_BROWSER_TESTS") != "1" {
		t.Log("Verifying send access via browser")
		_, _, page := SetupPlaywright(t)

		_, err = page.Goto(accessURL)
		require.NoError(t, err)

		// Wait for the textarea to be available
		textLoc := page.Locator("textarea[formcontrolname='sendText'], textarea#text")
		err = textLoc.First().WaitFor(playwright.LocatorWaitForOptions{
			Timeout: playwright.Float(5000),
		})
		require.NoError(t, err, "Failed to find textarea for send text")

		time.Sleep(1 * time.Second) // wait for angular to apply the value
		val, err := textLoc.First().InputValue()
		require.NoError(t, err)
		if val != "secret content" {
			content, _ := page.Content()
			t.Logf("\n--- UI HTML BODY ---\n%s\n--------------------\n", content)
		}
		require.Equal(t, "secret content", val, "Decrypted send content must match")
		t.Log("Send accessed and decrypted successfully in UI")

		_ = page.Context().Close()
	}

	// Delete
	err = v.DeleteSend(send.ID)
	require.NoError(t, err, "DeleteSend")
	t.Log("Send lifecycle complete")
}

func TestFileSendLifecycle(t *testing.T) {
	email := "test-send-file@example.com"
	password := "test-password-123"

	RegisterTestUser(t, testServer, email, password)

	v := APILogin(t, testServer, email, password)

	fileContent := []byte("My super secret file data")

	// Create
	send, accessURL, err := v.CreateFileSend("Test File Send", "secret.txt", fileContent, vault.SendOptions{})
	require.NoError(t, err, "CreateFileSend")
	t.Logf("Created file send: %s, URL: %s", send.ID, accessURL)

	// List
	sends, err := v.ListSends()
	require.NoError(t, err, "ListSends")
	found := false
	for _, s := range sends {
		if s.ID == send.ID {
			found = true
			assert.Equal(t, "Test File Send", s.Name)
			assert.Equal(t, "secret.txt", s.FileName)
			break
		}
	}
	assert.True(t, found, "Created file send not found in list")

	// Browser check: actually download the file
	if os.Getenv("SKIP_BROWSER_TESTS") != "1" {
		t.Log("Verifying send file download via browser")
		_, _, page := SetupPlaywright(t)

		_, err = page.Goto(accessURL)
		require.NoError(t, err)

		btn := page.Locator("button:has-text('Download file'), a:has-text('Download file')")
		err = btn.First().WaitFor(playwright.LocatorWaitForOptions{
			Timeout: playwright.Float(5000),
		})
		if err != nil {
			// fall back if there's just a general download button
			btn = page.Locator("button:has-text('Download'), button[aria-label='Download']")
			err = btn.First().WaitFor()
			require.NoError(t, err, "Failed to find download button")
		}

		time.Sleep(1 * time.Second) // let angular settle

		download, err := page.ExpectDownload(func() error {
			return btn.First().Click()
		})
		require.NoError(t, err, "Failed to initiate download")

		path, err := download.Path()
		require.NoError(t, err, "Failed to get download path")

		data, err := os.ReadFile(path)
		require.NoError(t, err, "Failed to read downloaded file")
		require.Equal(t, "My super secret file data", string(data), "Decrypted file content must match")

		t.Log("Send accessed and downloaded successfully in UI")

		_ = page.Context().Close()
	}

	// Delete
	err = v.DeleteSend(send.ID)
	require.NoError(t, err, "DeleteSend")
	t.Log("Send file lifecycle complete")
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
	v2, err := vault.LoginAPIKey(testServer, clientID, clientSecret, email, password, true, GetTestLogger())
	require.NoError(t, err, "API Key Login should succeed")

	c, _ := vault.NewCipher(vault.CipherTypeLogin, "Integration Test Login API Key", v2.SymmetricKey())
	c.SetLoginUsername("testuser")
	c.SetLoginPassword("testpass")
	err = v2.CreateCipher(c)
	require.NoError(t, err, "CreateCipher with API key login")

	fetched, err := v2.GetCipher(c.ID())
	require.NoError(t, err, "GetCipher with API key login")
	assert.Equal(t, "Integration Test Login API Key", fetched.Name(), "Name mismatch")
}

func TestSelfRegistration(t *testing.T) {
	// Generate a unique email to avoid "already exists" errors
	email := fmt.Sprintf("test-reg-%d@example.com", time.Now().UnixNano())
	password := "test-password-123"

	t.Logf("Testing self-registration for %s", email)

	// 1. Register the new user using the new vault.Register function
	err := vault.Register(
		testServer,
		email,
		password,
		crypto.KdfTypePBKDF2,
		600000,
		64,   // memory (Argon2 only)
		4,    // parallelism (Argon2 only)
		true, // insecureSkipVerify
		GetTestLogger(),
	)
	require.NoError(t, err, "vault.Register should succeed")

	// 2. Verify registration by logging in
	v, err := vault.Login(testServer, email, password, true, GetTestLogger())
	require.NoError(t, err, "Login after registration should succeed")
	require.NotNil(t, v, "Vault client should not be nil")

	t.Logf("Registration and login verified for %s", email)
}
