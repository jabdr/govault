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

func TestChangeEmail(t *testing.T) {
	oldEmail := fmt.Sprintf("test-chgemail-%d@example.com", time.Now().UnixNano())
	newEmail := fmt.Sprintf("test-newemail-%d@example.com", time.Now().UnixNano())
	password := "test-password-123"

	// 1. Register and login
	RegisterTestUser(t, testServer, oldEmail, password)
	v := APILogin(t, testServer, oldEmail, password)

	// 2. Create a cipher before the email change so we can verify data survives
	c, err := vault.NewCipher(vault.CipherTypeLogin, "Pre-Email-Change Cipher", v.SymmetricKey())
	require.NoError(t, err, "NewCipher")
	require.NoError(t, c.SetLoginUsername("myuser"), "SetLoginUsername")
	require.NoError(t, c.SetLoginPassword("mypass"), "SetLoginPassword")
	err = v.CreateCipher(c)
	require.NoError(t, err, "CreateCipher before email change")
	cipherID := c.ID()
	t.Logf("Created cipher %s before email change", cipherID)

	// 3. Request email change token (sent to new email via Mailpit)
	token := GetEmailChangeToken(t, v, newEmail)
	t.Logf("Got email change token: %s", token)

	// 4. Change email with the token
	err = v.ChangeEmail(newEmail, password, token, crypto.KdfTypePBKDF2, 600000, 64, 4)
	require.NoError(t, err, "ChangeEmail should succeed")
	t.Logf("Changed email from %s to %s", oldEmail, newEmail)

	// 5. Verify old email can no longer login
	_, err = vault.Login(testServer, oldEmail, password, true, GetTestLogger())
	require.Error(t, err, "Login with old email should fail after email change")
	t.Log("Confirmed old email login fails")

	// 6. Verify new email can login
	v2, err := vault.Login(testServer, newEmail, password, true, GetTestLogger())
	require.NoError(t, err, "Login with new email should succeed")
	require.NotNil(t, v2, "Vault client should not be nil")
	t.Log("Confirmed new email login succeeds")

	// 7. Verify the cipher data survived the email change
	fetched, err := v2.GetCipher(cipherID)
	require.NoError(t, err, "GetCipher after email change")
	assert.Equal(t, "Pre-Email-Change Cipher", fetched.Name(), "Cipher name should survive email change")
	u, p, err := fetched.GetLogin()
	require.NoError(t, err, "GetLogin after email change")
	assert.Equal(t, "myuser", u, "Username should survive email change")
	assert.Equal(t, "mypass", p, "Password should survive email change")
	t.Log("Cipher data verified after email change")
}

func TestFolderCRUDLifecycle(t *testing.T) {
	email := fmt.Sprintf("test-folders-%d@example.com", time.Now().UnixNano())
	password := "test-password-123"

	RegisterTestUser(t, testServer, email, password)
	v := APILogin(t, testServer, email, password)

	// 1. Initially no folders
	folders, err := v.ListFolders()
	require.NoError(t, err, "ListFolders (empty)")
	assert.Empty(t, folders, "Expected no folders initially")

	// 2. Create a folder
	f, err := v.CreateFolder("Work")
	require.NoError(t, err, "CreateFolder")
	assert.NotEmpty(t, f.ID, "Folder ID should not be empty")
	assert.Equal(t, "Work", f.Name, "Folder name mismatch")
	t.Logf("Created folder %q with ID %s", f.Name, f.ID)

	// 3. List folders — should see the new one
	folders, err = v.ListFolders()
	require.NoError(t, err, "ListFolders after create")
	require.Len(t, folders, 1, "Expected exactly one folder")
	assert.Equal(t, f.ID, folders[0].ID)
	assert.Equal(t, "Work", folders[0].Name)

	// 4. Get folder by ID
	fetched, err := v.GetFolder(f.ID)
	require.NoError(t, err, "GetFolder")
	assert.Equal(t, "Work", fetched.Name, "GetFolder name mismatch")

	// 5. Rename the folder
	updated, err := v.UpdateFolder(f.ID, "Personal")
	require.NoError(t, err, "UpdateFolder")
	assert.Equal(t, "Personal", updated.Name, "UpdateFolder name mismatch")

	// 6. Verify new name persists
	folders, err = v.ListFolders()
	require.NoError(t, err, "ListFolders after update")
	require.Len(t, folders, 1)
	assert.Equal(t, "Personal", folders[0].Name)

	// 7. Create a cipher assigned to the folder
	c, err := vault.NewCipher(vault.CipherTypeLogin, "Folder Cipher", v.SymmetricKey())
	require.NoError(t, err, "NewCipher")
	require.NoError(t, c.SetLoginUsername("user1"), "SetLoginUsername")
	require.NoError(t, c.SetLoginPassword("pass1"), "SetLoginPassword")
	require.NoError(t, c.SetFolderID(f.ID), "SetFolderID")
	require.NoError(t, v.CreateCipher(c), "CreateCipher in folder")
	t.Logf("Created cipher %s in folder %s", c.ID(), f.ID)

	// 8. Verify the cipher's folder assignment
	fetched2, err := v.GetCipher(c.ID())
	require.NoError(t, err, "GetCipher")
	assert.Equal(t, f.ID, fetched2.FolderID(), "Cipher should be in the created folder")

	// 9. Delete the folder
	require.NoError(t, v.DeleteFolder(f.ID), "DeleteFolder")

	// 10. Confirm folder list is now empty
	folders, err = v.ListFolders()
	require.NoError(t, err, "ListFolders after delete")
	assert.Empty(t, folders, "Folder list should be empty after delete")
}

func TestEmergencyAccessLifecycle(t *testing.T) {
	grantorEmail := fmt.Sprintf("ea-grantor-%d@example.com", time.Now().UnixNano())
	granteeEmail := fmt.Sprintf("ea-grantee-%d@example.com", time.Now().UnixNano())
	password := "test-password-123"

	// 1. Register and login both users
	RegisterTestUser(t, testServer, grantorEmail, password)
	RegisterTestUser(t, testServer, granteeEmail, password)

	grantorVault := APILogin(t, testServer, grantorEmail, password)
	granteeVault := APILogin(t, testServer, granteeEmail, password)

	// Create a cipher in grantor's vault to verify access later
	c, err := vault.NewCipher(vault.CipherTypeLogin, "Grantor Secret", grantorVault.SymmetricKey())
	require.NoError(t, err)
	require.NoError(t, c.SetLoginUsername("grantoruser"))
	require.NoError(t, grantorVault.CreateCipher(c))

	// 2. Grantor invites Grantee
	// Type 0 = View, WaitTimeDays = 0 (for testing)
	err = grantorVault.InviteEmergencyAccess(granteeEmail, 0, 0)
	require.NoError(t, err, "InviteEmergencyAccess")
	t.Logf("Grantor (%s) invited grantee (%s)", grantorEmail, granteeEmail)

	// Check grantor's trusted list first
	trusted, err := grantorVault.ListTrustedEmergencyAccess()
	require.NoError(t, err)
	t.Logf("Grantor trusted list size: %d", len(trusted))
	require.NotEmpty(t, trusted, "Grantor should see the invited contact")
	eaID := trusted[0].ID
	t.Logf("Emergency Access ID: %s", eaID)

	// 4. Grantee gets token and accepts
	token := GetInviteToken(t, granteeEmail)
	require.NotEmpty(t, token, "GetInviteToken")
	err = granteeVault.AcceptEmergencyAccess(eaID, token)
	require.NoError(t, err, "AcceptEmergencyAccess")
	t.Log("Grantee accepted invitation")

	// Now grantee should see it in their granted list
	granted, err := granteeVault.ListGrantedEmergencyAccess()
	require.NoError(t, err)
	t.Logf("Grantee granted list size: %d", len(granted))
	require.Len(t, granted, 1, "Grantee should now see the granted access")
	assert.Equal(t, 1, granted[0].Status, "Expected status ACCEPTED (1)")

	// 5. Grantor confirms Grantee
	// Wait for status to update to ACCEPTED
	for i := 0; i < 5; i++ {
		trusted, err := grantorVault.ListTrustedEmergencyAccess()
		require.NoError(t, err)
		if trusted[0].Status == 1 { // ACCEPTED
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	err = grantorVault.ConfirmEmergencyAccess(eaID)
	require.NoError(t, err, "ConfirmEmergencyAccess")
	t.Log("Grantor confirmed grantee")

	// 6. Grantee initiates access
	// Wait for status to update to CONFIRMED
	for i := 0; i < 5; i++ {
		granted, err = granteeVault.ListGrantedEmergencyAccess()
		require.NoError(t, err)
		if granted[0].Status == 2 { // CONFIRMED
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	err = granteeVault.InitiateEmergencyAccess(eaID)
	require.NoError(t, err, "InitiateEmergencyAccess")
	t.Log("Grantee initiated access")

	// 7. Grantor approves access early (to skip wait time)
	err = grantorVault.ApproveEmergencyAccess(eaID)
	require.NoError(t, err, "ApproveEmergencyAccess")
	t.Log("Grantor approved access early")

	// 8. Grantee views Grantor's vault
	// Wait for status to update to APPROVED
	for i := 0; i < 5; i++ {
		granted, err = granteeVault.ListGrantedEmergencyAccess()
		require.NoError(t, err)
		if granted[0].Status == 4 { // RECOVERY_APPROVED
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	grantorCiphers, err := granteeVault.ViewEmergencyVault(eaID)
	require.NoError(t, err, "ViewEmergencyVault")
	require.NotEmpty(t, grantorCiphers, "Should see grantor's ciphers")

	foundSecret := false
	for _, gc := range grantorCiphers {
		if gc.Name() == "Grantor Secret" {
			foundSecret = true
			break
		}
	}
	assert.True(t, foundSecret, "Grantee should find grantor's secret cipher")
	t.Log("Grantee successfully viewed grantor's vault")
}
