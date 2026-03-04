//go:build integration

package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	cliBinPath string
	buildOnce  sync.Once
)

func getCLIBin(t *testing.T) string {
	buildOnce.Do(func() {
		dir := os.TempDir()
		cliBinPath = filepath.Join(dir, "govault.testbin")
		cmd := exec.Command("go", "build", "-o", cliBinPath, "../cmd/govault")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "failed to build govault CLI: %s", string(out))
	})
	return cliBinPath
}

// runCLI executes the govault CLI binary with --output=json and returns stdout.
// It requires the command to succeed (exit 0).
func runCLI(t *testing.T, email, password string, args ...string) []byte {
	t.Helper()
	bin := getCLIBin(t)
	cmdArgs := []string{"--server", testServer, "--insecure-skip-verify", "--output=json"}
	if email != "" {
		cmdArgs = append(cmdArgs, "--email", email, "--password", password)
	}
	cmdArgs = append(cmdArgs, args...)

	t.Logf("CLI: govault %s", strings.Join(cmdArgs, " "))
	cmd := exec.Command(bin, cmdArgs...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "CLI command failed: %v\nOutput: %s", cmdArgs, string(out))
	return out
}

// runCLIExpectError executes the govault CLI binary and expects it to fail (non-zero exit).
func runCLIExpectError(t *testing.T, email, password string, args ...string) []byte {
	t.Helper()
	bin := getCLIBin(t)
	cmdArgs := []string{"--server", testServer, "--insecure-skip-verify", "--output=json"}
	if email != "" {
		cmdArgs = append(cmdArgs, "--email", email, "--password", password)
	}
	cmdArgs = append(cmdArgs, args...)

	t.Logf("CLI (expect error): govault %s", strings.Join(cmdArgs, " "))
	cmd := exec.Command(bin, cmdArgs...)
	out, _ := cmd.CombinedOutput()
	return out
}

// runCLIRaw executes the govault CLI binary with arbitrary args (no email/pass prepended).
func runCLIRaw(t *testing.T, args ...string) []byte {
	t.Helper()
	bin := getCLIBin(t)
	t.Logf("CLI raw: govault %s", strings.Join(args, " "))
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "CLI raw command failed: %v\nOutput: %s", args, string(out))
	return out
}

// --------------------------------------------------------------------------
// JSON result types for parsing CLI output
// --------------------------------------------------------------------------

type cliMessage struct {
	Message string `json:"message"`
	ID      string `json:"id"`
	URL     string `json:"url"`
}

type cliCipher struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	URLs     []string `json:"urls"`
	Notes    string   `json:"notes"`
}

type cliCipherList struct {
	Items []cliCipher `json:"items"`
}

type cliOrg struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cliOrgList struct {
	Items []cliOrg `json:"items"`
}

type cliOrgMember struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type cliOrgMemberList struct {
	Items []cliOrgMember `json:"items"`
}

type cliCollection struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cliCollectionList struct {
	Items []cliCollection `json:"items"`
}

type cliGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cliGroupList struct {
	Items []cliGroup `json:"items"`
}

type cliFolder struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cliFolderList struct {
	Items []cliFolder `json:"items"`
}

type cliSend struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cliSendList struct {
	Items []cliSend `json:"items"`
}

type cliEmergencyContact struct {
	ID     string `json:"id"`
	Email  string `json:"email"`
	Status int    `json:"status"`
	Type   int    `json:"type"`
}

type cliEmergencyList struct {
	Items []cliEmergencyContact `json:"items"`
}

type cliAPIKey struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type cliAdminUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

type cliAdminUserList struct {
	Items []cliAdminUser `json:"items"`
}

type cliAdminOrg struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cliAdminOrgList struct {
	Items []cliAdminOrg `json:"items"`
}

// --------------------------------------------------------------------------
// Helper to set up a fresh user for CLI tests
// --------------------------------------------------------------------------

func setupCLIUser(t *testing.T) (email, password string) {
	t.Helper()
	email = fmt.Sprintf("test-cli-%d@example.com", time.Now().UnixNano())
	password = "cli-pass-123"
	RegisterTestUser(t, testServer, email, password)
	v := APILogin(t, testServer, email, password)
	VerifyUserEmail(t, v, email)
	return
}

// ==========================================================================
// CIPHER TESTS
// ==========================================================================

func TestCLICipherLifecycle(t *testing.T) {
	t.Parallel()
	email, password := setupCLIUser(t)

	// 1. Create cipher with notes and URL
	t.Log("Step: cipher create")
	out := runCLI(t, email, password, "cipher", "create",
		"--name", "CLI Test Login",
		"--type", "1",
		"--login-username", "user1",
		"--login-password", "pass1",
		"--notes", "my secret notes",
		"--url", "https://example.com",
	)
	var createMsg cliMessage
	require.NoError(t, json.Unmarshal(out, &createMsg), "parse create output: %s", string(out))
	require.NotEmpty(t, createMsg.ID, "cipher ID")
	cipherID := createMsg.ID
	t.Logf("Created cipher: %s", cipherID)

	// 2. Get cipher and verify all fields
	t.Log("Step: cipher get")
	out = runCLI(t, email, password, "cipher", "get", cipherID)
	var got cliCipher
	require.NoError(t, json.Unmarshal(out, &got), "parse get output: %s", string(out))
	assert.Equal(t, cipherID, got.ID)
	assert.Equal(t, "CLI Test Login", got.Name)
	assert.Equal(t, "Login", got.Type)
	assert.Equal(t, "user1", got.Username)
	assert.Equal(t, "pass1", got.Password)
	assert.Equal(t, "my secret notes", got.Notes)
	assert.Contains(t, got.URLs, "https://example.com")

	// 3. Update cipher
	t.Log("Step: cipher update")
	runCLI(t, email, password, "cipher", "update",
		"--id", cipherID,
		"--name", "Updated Login",
		"--login-username", "user2",
		"--login-password", "pass2",
	)

	// 4. Verify update
	out = runCLI(t, email, password, "cipher", "get", cipherID)
	require.NoError(t, json.Unmarshal(out, &got))
	assert.Equal(t, "Updated Login", got.Name)
	assert.Equal(t, "user2", got.Username)
	assert.Equal(t, "pass2", got.Password)

	// 5. List ciphers
	t.Log("Step: cipher list")
	out = runCLI(t, email, password, "cipher", "list")
	var list cliCipherList
	require.NoError(t, json.Unmarshal(out, &list), "parse list: %s", string(out))
	require.Len(t, list.Items, 1)
	assert.Equal(t, "Updated Login", list.Items[0].Name)

	// 6. Delete cipher
	t.Log("Step: cipher delete")
	out = runCLI(t, email, password, "cipher", "delete", cipherID)
	var delMsg cliMessage
	require.NoError(t, json.Unmarshal(out, &delMsg))
	assert.Equal(t, cipherID, delMsg.ID)

	// 7. Verify deletion
	out = runCLI(t, email, password, "cipher", "list")
	require.NoError(t, json.Unmarshal(out, &list))
	assert.Empty(t, list.Items)
}

// ==========================================================================
// CIPHER IN COLLECTION TESTS
// ==========================================================================

func TestCLICipherInCollection(t *testing.T) {
	t.Parallel()
	email, password := setupCLIUser(t)

	// 1. Create an organization with a default collection
	orgName := fmt.Sprintf("CipherCol Org %d", time.Now().UnixNano())
	t.Log("Step: create org for collection cipher")
	out := runCLI(t, email, password, "org", "create",
		"--name", orgName,
		"--billing-email", email,
		"--collection-name", "TestCol",
	)
	var orgMsg cliMessage
	require.NoError(t, json.Unmarshal(out, &orgMsg), "parse org create: %s", string(out))
	orgID := orgMsg.ID

	// 2. List collections to get the collection ID
	t.Log("Step: list collections")
	out = runCLI(t, email, password, "collection", "list", "--org-id", orgID)
	var colList cliCollectionList
	require.NoError(t, json.Unmarshal(out, &colList), "parse collection list: %s", string(out))
	require.NotEmpty(t, colList.Items, "should have at least one collection")
	colID := colList.Items[0].ID

	// 3. Create a cipher in the collection
	t.Log("Step: create cipher in collection")
	out = runCLI(t, email, password, "cipher", "create",
		"--name", "Collection Cipher",
		"--org-id", orgID,
		"--collection-id", colID,
		"--login-username", "coluser",
		"--login-password", "colpass",
	)
	var cipherMsg cliMessage
	require.NoError(t, json.Unmarshal(out, &cipherMsg), "parse cipher create: %s", string(out))
	require.NotEmpty(t, cipherMsg.ID)
	cipherID := cipherMsg.ID
	t.Logf("Created cipher in collection: %s", cipherID)

	// 4. Get the cipher and verify it's readable (org key decryption works)
	t.Log("Step: get cipher from collection")
	out = runCLI(t, email, password, "cipher", "get", cipherID)
	var gotCipher cliCipher
	require.NoError(t, json.Unmarshal(out, &gotCipher), "parse cipher get: %s", string(out))
	assert.Equal(t, "Collection Cipher", gotCipher.Name)
	assert.Equal(t, "coluser", gotCipher.Username)
	assert.Equal(t, "colpass", gotCipher.Password)
}

// ==========================================================================
// FOLDER TESTS
// ==========================================================================

func TestCLIFolderLifecycle(t *testing.T) {
	t.Parallel()
	email, password := setupCLIUser(t)

	// 1. List folders (should be empty)
	t.Log("Step: folder list (empty)")
	out := runCLI(t, email, password, "folder", "list")
	assert.Contains(t, string(out), "No folders found")

	// 2. Create folder
	t.Log("Step: folder create")
	out = runCLI(t, email, password, "folder", "create", "--name", "Work")
	var msg cliMessage
	require.NoError(t, json.Unmarshal(out, &msg), "parse create: %s", string(out))
	require.NotEmpty(t, msg.ID)
	folderID := msg.ID
	t.Logf("Created folder: %s", folderID)

	// 3. List folders (should have one)
	t.Log("Step: folder list")
	out = runCLI(t, email, password, "folder", "list")
	var list cliFolderList
	require.NoError(t, json.Unmarshal(out, &list))
	require.Len(t, list.Items, 1)
	assert.Equal(t, "Work", list.Items[0].Name)

	// 4. Update folder
	t.Log("Step: folder update")
	runCLI(t, email, password, "folder", "update", "--id", folderID, "--name", "Personal")

	// 5. Verify update
	out = runCLI(t, email, password, "folder", "list")
	require.NoError(t, json.Unmarshal(out, &list))
	require.Len(t, list.Items, 1)
	assert.Equal(t, "Personal", list.Items[0].Name)

	// 6. Delete folder
	t.Log("Step: folder delete")
	runCLI(t, email, password, "folder", "delete", folderID)

	// 7. Verify deletion
	out = runCLI(t, email, password, "folder", "list")
	assert.Contains(t, string(out), "No folders found")
}

// ==========================================================================
// SEND TESTS
// ==========================================================================

func TestCLISendLifecycle(t *testing.T) {
	t.Parallel()
	email, password := setupCLIUser(t)

	// 1. Create text send
	t.Log("Step: send create (text)")
	out := runCLI(t, email, password, "send", "create", "--name", "CLI Send", "--text", "hello world")
	var msg cliMessage
	require.NoError(t, json.Unmarshal(out, &msg), "parse create: %s", string(out))
	require.NotEmpty(t, msg.ID)
	sendID := msg.ID
	t.Logf("Created send: %s", sendID)

	// 2. List sends
	t.Log("Step: send list")
	out = runCLI(t, email, password, "send", "list")
	var list cliSendList
	require.NoError(t, json.Unmarshal(out, &list), "parse list: %s", string(out))
	require.NotEmpty(t, list.Items)
	found := false
	for _, s := range list.Items {
		if s.ID == sendID {
			found = true
			assert.Equal(t, "CLI Send", s.Name)
		}
	}
	assert.True(t, found, "send not found in list")

	// 3. Get send
	t.Log("Step: send get")
	out = runCLI(t, email, password, "send", "get", sendID)
	var gotSend cliSend
	require.NoError(t, json.Unmarshal(out, &gotSend), "parse get: %s", string(out))
	assert.Equal(t, sendID, gotSend.ID)
	assert.Equal(t, "CLI Send", gotSend.Name)

	// 4. Create file send
	t.Log("Step: send create (file)")
	tmpFile := filepath.Join(t.TempDir(), "test-upload.txt")
	require.NoError(t, os.WriteFile(tmpFile, []byte("file content"), 0644))
	out = runCLI(t, email, password, "send", "create", "--file", tmpFile)
	var fileMsg cliMessage
	require.NoError(t, json.Unmarshal(out, &fileMsg), "parse file create: %s", string(out))
	require.NotEmpty(t, fileMsg.ID)

	// 5. Delete send
	t.Log("Step: send delete")
	runCLI(t, email, password, "send", "delete", sendID)
}

// ==========================================================================
// ACCOUNT TESTS
// ==========================================================================

func TestCLIAccount(t *testing.T) {
	t.Parallel()
	email, password := setupCLIUser(t)

	// 1. Change name
	t.Log("Step: account change-name")
	out := runCLI(t, email, password, "account", "change-name", "--name", "CLI Test Name")
	assert.Contains(t, string(out), "Name changed to: CLI Test Name")

	// 2. Get API key
	t.Log("Step: account get-api-key")
	out = runCLI(t, email, password, "account", "get-api-key")
	var apiKey cliAPIKey
	require.NoError(t, json.Unmarshal(out, &apiKey), "parse api key: %s", string(out))
	assert.NotEmpty(t, apiKey.ClientID)
	assert.NotEmpty(t, apiKey.ClientSecret)
	t.Logf("Got API key: client_id=%s", apiKey.ClientID)
}

// ==========================================================================
// REGISTER TESTS
// ==========================================================================

func TestCLIRegister(t *testing.T) {
	t.Parallel()
	email := fmt.Sprintf("test-cli-register-%d@example.com", time.Now().UnixNano())
	password := "cli-pass-123"

	t.Log("Step: register")
	out := runCLI(t, email, password, "register")
	assert.Contains(t, string(out), "successfully registered")

	// Verify by logging in via CLI
	t.Log("Step: verify login after register")
	out = runCLI(t, email, password, "cipher", "list")
	var list cliCipherList
	require.NoError(t, json.Unmarshal(out, &list))
	assert.Empty(t, list.Items)
}

// ==========================================================================
// ORG TESTS
// ==========================================================================

func TestCLIOrgLifecycle(t *testing.T) {
	t.Parallel()
	email, password := setupCLIUser(t)

	// 1. Create org
	orgName := fmt.Sprintf("CLI Org %d", time.Now().UnixNano())
	t.Log("Step: org create")
	out := runCLI(t, email, password, "org", "create",
		"--name", orgName,
		"--billing-email", email,
		"--collection-name", "CLI Collection",
	)
	var msg cliMessage
	require.NoError(t, json.Unmarshal(out, &msg), "parse org create: %s", string(out))
	require.NotEmpty(t, msg.ID)
	orgID := msg.ID
	t.Logf("Created org: %s", orgID)

	// 2. List orgs
	t.Log("Step: org list")
	out = runCLI(t, email, password, "org", "list")
	var orgList cliOrgList
	require.NoError(t, json.Unmarshal(out, &orgList), "parse org list: %s", string(out))
	found := false
	for _, o := range orgList.Items {
		if o.ID == orgID {
			found = true
			assert.Equal(t, orgName, o.Name)
		}
	}
	assert.True(t, found, "org not in list")

	// 3. List org members
	t.Log("Step: org members")
	out = runCLI(t, email, password, "org", "members", "--id", orgID)
	var members cliOrgMemberList
	require.NoError(t, json.Unmarshal(out, &members), "parse members: %s", string(out))
	require.NotEmpty(t, members.Items, "should have at least the owner")

	// 4. Invite user to org
	inviteeEmail := fmt.Sprintf("org-invitee-%d@example.com", time.Now().UnixNano())
	t.Log("Step: org invite")
	out = runCLI(t, email, password, "org", "invite", "--id", orgID, "--email", inviteeEmail)
	assert.Contains(t, string(out), "Invited")

	// 5. Get org API key
	t.Log("Step: org get-api-key")
	out = runCLI(t, email, password, "org", "get-api-key", "--id", orgID)
	var apiKey cliAPIKey
	require.NoError(t, json.Unmarshal(out, &apiKey), "parse org api key: %s", string(out))
	assert.NotEmpty(t, apiKey.ClientID)
	assert.NotEmpty(t, apiKey.ClientSecret)
}

// ==========================================================================
// COLLECTION TESTS
// ==========================================================================

func TestCLICollectionLifecycle(t *testing.T) {
	t.Parallel()
	email, password := setupCLIUser(t)

	// Setup: create an org first
	orgName := fmt.Sprintf("CLI Col Org %d", time.Now().UnixNano())
	out := runCLI(t, email, password, "org", "create", "--name", orgName, "--billing-email", email)
	var orgMsg cliMessage
	require.NoError(t, json.Unmarshal(out, &orgMsg))
	orgID := orgMsg.ID

	// 1. List collections (org already has "Default Collection" from create)
	t.Log("Step: collection list")
	out = runCLI(t, email, password, "collection", "list", "--org-id", orgID)
	var colList cliCollectionList
	require.NoError(t, json.Unmarshal(out, &colList), "parse col list: %s", string(out))
	// Org create creates one default collection
	require.NotEmpty(t, colList.Items)

	// 2. Create collection
	t.Log("Step: collection create")
	out = runCLI(t, email, password, "collection", "create", "--org-id", orgID, "--name", "CLI Collection")
	var colMsg cliMessage
	require.NoError(t, json.Unmarshal(out, &colMsg), "parse col create: %s", string(out))
	require.NotEmpty(t, colMsg.ID)
	colID := colMsg.ID
	t.Logf("Created collection: %s", colID)

	// 3. Verify it shows in list
	out = runCLI(t, email, password, "collection", "list", "--org-id", orgID)
	require.NoError(t, json.Unmarshal(out, &colList))
	found := false
	for _, c := range colList.Items {
		if c.ID == colID {
			found = true
			assert.Equal(t, "CLI Collection", c.Name)
		}
	}
	assert.True(t, found, "new collection not in list")

	// 4. Delete collection
	t.Log("Step: collection delete")
	runCLI(t, email, password, "collection", "delete", "--org-id", orgID, "--id", colID)

	// 5. Verify deletion
	out = runCLI(t, email, password, "collection", "list", "--org-id", orgID)
	require.NoError(t, json.Unmarshal(out, &colList))
	for _, c := range colList.Items {
		assert.NotEqual(t, colID, c.ID, "deleted collection should not appear")
	}
}

// ==========================================================================
// GROUP TESTS
// ==========================================================================

func TestCLIGroupLifecycle(t *testing.T) {
	t.Parallel()
	t.Skip("Vaultwarden returns 422 for group create API — skipping until server-side support is verified")
	email, password := setupCLIUser(t)

	// Setup: create an org
	out := runCLI(t, email, password, "org", "create", "--name", fmt.Sprintf("CLI Grp Org %d", time.Now().UnixNano()), "--billing-email", email)
	var orgMsg cliMessage
	require.NoError(t, json.Unmarshal(out, &orgMsg))
	orgID := orgMsg.ID

	// 1. List groups (empty)
	t.Log("Step: group list (empty)")
	out = runCLI(t, email, password, "group", "list", "--org-id", orgID)
	assert.Contains(t, string(out), "No groups found")

	// 2. Create group
	t.Log("Step: group create")
	out = runCLI(t, email, password, "group", "create", "--org-id", orgID, "--name", "Developers")
	var grpMsg cliMessage
	require.NoError(t, json.Unmarshal(out, &grpMsg), "parse group create: %s", string(out))
	require.NotEmpty(t, grpMsg.ID)
	groupID := grpMsg.ID
	t.Logf("Created group: %s", groupID)

	// 3. List groups
	t.Log("Step: group list")
	out = runCLI(t, email, password, "group", "list", "--org-id", orgID)
	var grpList cliGroupList
	require.NoError(t, json.Unmarshal(out, &grpList), "parse group list: %s", string(out))
	require.Len(t, grpList.Items, 1)
	assert.Equal(t, "Developers", grpList.Items[0].Name)

	// 4. Update group
	t.Log("Step: group update")
	runCLI(t, email, password, "group", "update", "--org-id", orgID, "--id", groupID, "--name", "Engineers")

	// 5. Verify update
	out = runCLI(t, email, password, "group", "list", "--org-id", orgID)
	require.NoError(t, json.Unmarshal(out, &grpList))
	require.Len(t, grpList.Items, 1)
	assert.Equal(t, "Engineers", grpList.Items[0].Name)

	// 6. Delete group
	t.Log("Step: group delete")
	runCLI(t, email, password, "group", "delete", "--org-id", orgID, "--id", groupID)

	// 7. Verify deletion
	out = runCLI(t, email, password, "group", "list", "--org-id", orgID)
	assert.Contains(t, string(out), "No groups found")
}

// ==========================================================================
// EMERGENCY ACCESS TESTS
// ==========================================================================

func TestCLIEmergencyAccess(t *testing.T) {
	t.Parallel()
	grantorEmail, grantorPass := setupCLIUser(t)
	granteeEmail, granteePass := setupCLIUser(t)

	// 1. Grantor invites grantee
	t.Log("Step: emergency invite")
	out := runCLI(t, grantorEmail, grantorPass, "emergency", "invite",
		"--email", granteeEmail, "--type", "0", "--wait", "0")
	assert.Contains(t, string(out), "Invited")

	// 2. Grantor lists trusted contacts
	t.Log("Step: emergency trusted")
	out = runCLI(t, grantorEmail, grantorPass, "emergency", "trusted")
	var trusted cliEmergencyList
	require.NoError(t, json.Unmarshal(out, &trusted), "parse trusted: %s", string(out))
	require.NotEmpty(t, trusted.Items)
	eaID := trusted.Items[0].ID
	t.Logf("Emergency Access ID: %s", eaID)

	// 3. Grantee accepts via API (need the invite token from email)
	granteeVault := APILogin(t, testServer, granteeEmail, granteePass)
	token := GetInviteToken(t, granteeEmail)
	require.NotEmpty(t, token)
	err := granteeVault.AcceptEmergencyAccess(eaID, token)
	require.NoError(t, err, "AcceptEmergencyAccess")
	t.Log("Grantee accepted invitation")

	// 4. Grantee lists granted contacts via CLI
	t.Log("Step: emergency granted")
	out = runCLI(t, granteeEmail, granteePass, "emergency", "granted")
	var granted cliEmergencyList
	require.NoError(t, json.Unmarshal(out, &granted), "parse granted: %s", string(out))
	require.NotEmpty(t, granted.Items)

	// 5. Grantor confirms via CLI
	t.Log("Step: emergency confirm")
	runCLI(t, grantorEmail, grantorPass, "emergency", "confirm", "--id", eaID)

	// 6. Grantee initiates via CLI
	t.Log("Step: emergency initiate")
	runCLI(t, granteeEmail, granteePass, "emergency", "initiate", "--id", eaID)

	// 7. Grantor approves via CLI
	t.Log("Step: emergency approve")
	runCLI(t, grantorEmail, grantorPass, "emergency", "approve", "--id", eaID)

	// 8. Grantee views vault via CLI
	t.Log("Step: emergency view")
	out = runCLI(t, granteeEmail, granteePass, "emergency", "view", "--id", eaID)
	// Should get a list (possibly empty if no ciphers)
	var viewList cliCipherList
	require.NoError(t, json.Unmarshal(out, &viewList), "parse view: %s", string(out))
}

// ==========================================================================
// ADMIN TESTS
// ==========================================================================

func TestCLIAdminUserLifecycle(t *testing.T) {
	t.Parallel()
	email := fmt.Sprintf("cli-admin-user-%d@example.com", time.Now().UnixNano())
	password := "cli-pass-123"
	RegisterTestUser(t, testServer, email, password)

	adminArgs := func(args ...string) []string {
		return append([]string{
			"--server", testServer, "--insecure-skip-verify", "--output=json",
			"admin", "--admin-token", testAdminToken,
		}, args...)
	}

	bin := getCLIBin(t)

	// 1. List users
	t.Log("Step: admin user list")
	cmd := exec.Command(bin, adminArgs("user", "list")...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "admin user list: %s", string(out))
	var userList cliAdminUserList
	require.NoError(t, json.Unmarshal(out, &userList), "parse user list: %s", string(out))
	require.NotEmpty(t, userList.Items)

	var userID string
	for _, u := range userList.Items {
		if u.Email == email {
			userID = u.ID
			break
		}
	}
	require.NotEmpty(t, userID, "registered user not found in admin list")

	// 2. Get user
	t.Log("Step: admin user get")
	cmd = exec.Command(bin, adminArgs("user", "get", userID)...)
	out, err = cmd.CombinedOutput()
	require.NoError(t, err, "admin user get: %s", string(out))
	var adminUser cliAdminUser
	require.NoError(t, json.Unmarshal(out, &adminUser))
	assert.Equal(t, email, adminUser.Email)

	// 3. Disable user
	t.Log("Step: admin user disable")
	cmd = exec.Command(bin, adminArgs("user", "disable", "--id", userID)...)
	out, err = cmd.CombinedOutput()
	require.NoError(t, err, "admin user disable: %s", string(out))
	assert.Contains(t, string(out), "disabled")

	// 4. Enable user
	t.Log("Step: admin user enable")
	cmd = exec.Command(bin, adminArgs("user", "enable", "--id", userID)...)
	out, err = cmd.CombinedOutput()
	require.NoError(t, err, "admin user enable: %s", string(out))
	assert.Contains(t, string(out), "enabled")

	// 5. Deauth user
	t.Log("Step: admin user deauth")
	cmd = exec.Command(bin, adminArgs("user", "deauth", "--id", userID)...)
	out, err = cmd.CombinedOutput()
	require.NoError(t, err, "admin user deauth: %s", string(out))
	assert.Contains(t, string(out), "deauthorized")

	// 6. Invite user
	inviteEmail := fmt.Sprintf("cli-admin-invite-%d@example.com", time.Now().UnixNano())
	t.Log("Step: admin user invite")
	cmd = exec.Command(bin, adminArgs("user", "invite", "--email", inviteEmail)...)
	out, err = cmd.CombinedOutput()
	require.NoError(t, err, "admin user invite: %s", string(out))
	assert.Contains(t, string(out), "Invited")

	// 7. Delete user
	t.Log("Step: admin user delete")
	cmd = exec.Command(bin, adminArgs("user", "delete", "--id", userID)...)
	out, err = cmd.CombinedOutput()
	require.NoError(t, err, "admin user delete: %s", string(out))
	assert.Contains(t, string(out), "deleted")
}

func TestCLIAdminOrgLifecycle(t *testing.T) {
	t.Parallel()
	email, password := setupCLIUser(t)

	// Create org via regular CLI
	orgName := fmt.Sprintf("CLI Admin Org %d", time.Now().UnixNano())
	out := runCLI(t, email, password, "org", "create", "--name", orgName, "--billing-email", email)
	var orgMsg cliMessage
	require.NoError(t, json.Unmarshal(out, &orgMsg))
	orgID := orgMsg.ID

	bin := getCLIBin(t)
	adminArgs := func(args ...string) []string {
		return append([]string{
			"--server", testServer, "--insecure-skip-verify", "--output=json",
			"admin", "--admin-token", testAdminToken,
		}, args...)
	}

	// 1. List orgs via admin
	t.Log("Step: admin org list")
	cmd := exec.Command(bin, adminArgs("org", "list")...)
	out2, err := cmd.CombinedOutput()
	require.NoError(t, err, "admin org list: %s", string(out2))
	var adminOrgList cliAdminOrgList
	require.NoError(t, json.Unmarshal(out2, &adminOrgList))
	found := false
	for _, o := range adminOrgList.Items {
		if o.ID == orgID {
			found = true
			assert.Equal(t, orgName, o.Name)
		}
	}
	assert.True(t, found, "org not found in admin list")

	// 2. Delete org via admin
	t.Log("Step: admin org delete")
	cmd = exec.Command(bin, adminArgs("org", "delete", "--id", orgID)...)
	out2, err = cmd.CombinedOutput()
	require.NoError(t, err, "admin org delete: %s", string(out2))
	assert.Contains(t, string(out2), "deleted")
}

// ==========================================================================
// PUBLIC API TESTS
// ==========================================================================

func TestCLIPublicImport(t *testing.T) {
	t.Parallel()
	email, password := setupCLIUser(t)

	// Create org and get API key
	orgName := fmt.Sprintf("CLI Public Org %d", time.Now().UnixNano())
	out := runCLI(t, email, password, "org", "create", "--name", orgName, "--billing-email", email)
	var orgMsg cliMessage
	require.NoError(t, json.Unmarshal(out, &orgMsg))
	orgID := orgMsg.ID

	out = runCLI(t, email, password, "org", "get-api-key", "--id", orgID)
	var apiKey cliAPIKey
	require.NoError(t, json.Unmarshal(out, &apiKey))

	bin := getCLIBin(t)
	importEmail := fmt.Sprintf("cli-public-import-%d@example.com", time.Now().UnixNano())

	// Use the public import command
	t.Log("Step: public import")
	cmd := exec.Command(bin,
		"--server", testServer, "--insecure-skip-verify", "--output=json",
		"public",
		"--client-id", apiKey.ClientID,
		"--client-secret", apiKey.ClientSecret,
		"import",
		"--member", importEmail,
	)
	out2, err := cmd.CombinedOutput()
	require.NoError(t, err, "public import: %s", string(out2))
	assert.Contains(t, string(out2), "Imported")

	// Verify member appears in org
	out = runCLI(t, email, password, "org", "members", "--id", orgID)
	var members cliOrgMemberList
	require.NoError(t, json.Unmarshal(out, &members))
	found := false
	for _, m := range members.Items {
		if m.Email == importEmail {
			found = true
		}
	}
	assert.True(t, found, "imported member not found in org members")
}

// ==========================================================================
// CACHE TESTS
// ==========================================================================

func TestCLICacheLifecycle(t *testing.T) {
	t.Parallel()
	email, password := setupCLIUser(t)

	// Create some data first
	t.Log("Step: create test cipher and org for cache")
	out := runCLI(t, email, password, "cipher", "create", "--name", "Cache Test Cipher", "--login-username", "cacheuser", "--login-password", "cachepass")
	var cipherMsg cliMessage
	require.NoError(t, json.Unmarshal(out, &cipherMsg))
	cipherID := cipherMsg.ID

	orgName := fmt.Sprintf("Cache Org %d", time.Now().UnixNano())
	out = runCLI(t, email, password, "org", "create", "--name", orgName, "--billing-email", email, "--collection-name", "Cache Col")
	var orgMsg cliMessage
	require.NoError(t, json.Unmarshal(out, &orgMsg))
	orgID := orgMsg.ID

	// 1. Cache sync
	cacheFile := filepath.Join(t.TempDir(), "test-cache.json")
	t.Logf("Step: cache sync (file: %s)", cacheFile)
	runCLI(t, email, password, "--cache-file", cacheFile, "cache", "sync")

	// Verify cache file was created
	_, err := os.Stat(cacheFile)
	require.NoError(t, err, "cache file should exist")
	t.Log("Cache file created successfully")

	// 2. Cache cipher list (offline)
	t.Log("Step: cache cipher list")
	out = runCLI(t, email, password, "--cache-file", cacheFile, "cache", "cipher", "list")
	var cipherList cliCipherList
	require.NoError(t, json.Unmarshal(out, &cipherList), "parse cache cipher list: %s", string(out))
	require.NotEmpty(t, cipherList.Items)
	found := false
	for _, c := range cipherList.Items {
		if c.ID == cipherID {
			found = true
			assert.Equal(t, "Cache Test Cipher", c.Name)
		}
	}
	assert.True(t, found, "cipher not found in cache list")

	// 3. Cache cipher get (offline)
	t.Log("Step: cache cipher get")
	out = runCLI(t, email, password, "--cache-file", cacheFile, "cache", "cipher", "get", cipherID)
	var gotCipher cliCipher
	require.NoError(t, json.Unmarshal(out, &gotCipher), "parse cache cipher get: %s", string(out))
	assert.Equal(t, cipherID, gotCipher.ID)
	assert.Equal(t, "Cache Test Cipher", gotCipher.Name)
	assert.Equal(t, "cacheuser", gotCipher.Username)
	assert.Equal(t, "cachepass", gotCipher.Password)

	// 4. Cache org list (offline)
	t.Log("Step: cache org list")
	out = runCLI(t, email, password, "--cache-file", cacheFile, "cache", "org", "list")
	var orgList cliOrgList
	require.NoError(t, json.Unmarshal(out, &orgList), "parse cache org list: %s", string(out))
	require.NotEmpty(t, orgList.Items)
	found = false
	for _, o := range orgList.Items {
		if o.ID == orgID {
			found = true
			assert.Equal(t, orgName, o.Name)
		}
	}
	assert.True(t, found, "org not found in cache list")

	// 5. Cache collection list (offline)
	t.Log("Step: cache collection list")
	out = runCLI(t, email, password, "--cache-file", cacheFile, "cache", "collection", "list", "--org-id", orgID)
	var colList cliCollectionList
	require.NoError(t, json.Unmarshal(out, &colList), "parse cache col list: %s", string(out))
	require.NotEmpty(t, colList.Items)
	// Should have at least the "Cache Col" collection from org create
	found = false
	for _, c := range colList.Items {
		if c.Name == "Cache Col" {
			found = true
		}
	}
	assert.True(t, found, "collection 'Cache Col' not found in cache list")
}
