//go:build integration

package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

func runCLI(t *testing.T, email, password string, args ...string) []byte {
	bin := getCLIBin(t)
	cmdArgs := []string{"--server", testServer, "--insecure-skip-verify", "--output=json"}
	if email != "" {
		cmdArgs = append(cmdArgs, "--email", email, "--password", password)
	}
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.Command(bin, cmdArgs...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "CLI command failed: %v\nOutput: %s", cmdArgs, string(out))
	return out
}

func TestCLICipherLifecycle(t *testing.T) {
	t.Parallel()
	email := fmt.Sprintf("test-cli-%d@example.com", time.Now().UnixNano())
	password := "cli-pass-123"

	// 1. Register
	RegisterTestUser(t, testServer, email, password)

	// Verify email (setup requirement for vault)
	v := APILogin(t, testServer, email, password)
	VerifyUserEmail(t, v, email)

	// 2. Create cipher
	out := runCLI(t, email, password, "cipher", "create", "--name", "Test CLI Cipher", "--login-username", "user1", "--login-password", "pass1")
	var createResult struct {
		Message string `json:"Message"`
		ID      string `json:"ID"`
	}
	err := json.Unmarshal(out, &createResult)
	require.NoError(t, err, "parse create output")
	require.NotEmpty(t, createResult.ID, "cipher ID missing")

	// 3. Get cipher
	out = runCLI(t, email, password, "cipher", "get", createResult.ID)
	var getResult struct {
		ID       string `json:"ID"`
		Name     string `json:"Name"`
		Username string `json:"Username"`
		Password string `json:"Password"`
	}
	err = json.Unmarshal(out, &getResult)
	require.NoError(t, err, "parse get output: %s", string(out))
	assert.Equal(t, createResult.ID, getResult.ID)
	assert.Equal(t, "Test CLI Cipher", getResult.Name)
	assert.Equal(t, "user1", getResult.Username)
	assert.Equal(t, "pass1", getResult.Password)

	// 4. Update cipher
	out = runCLI(t, email, password, "cipher", "update", "--id", createResult.ID, "--name", "Updated CLI Cipher")
	var updateResult struct {
		ID string `json:"ID"`
	}
	err = json.Unmarshal(out, &updateResult)
	require.NoError(t, err, "parse update output")

	// 5. List ciphers
	out = runCLI(t, email, password, "cipher", "list")
	var listResult struct {
		Items []struct {
			ID   string `json:"ID"`
			Name string `json:"Name"`
		} `json:"items"`
	}
	err = json.Unmarshal(out, &listResult)
	require.NoError(t, err, "parse list output: %s", string(out))
	require.Len(t, listResult.Items, 1)
	assert.Equal(t, "Updated CLI Cipher", listResult.Items[0].Name)

	// 6. Delete cipher
	out = runCLI(t, email, password, "cipher", "delete", createResult.ID)
	var deleteResult struct {
		ID string `json:"ID"`
	}
	err = json.Unmarshal(out, &deleteResult)
	require.NoError(t, err, "parse delete output")
	assert.Equal(t, createResult.ID, deleteResult.ID)
}

func TestCLIAccount(t *testing.T) {
	t.Parallel()
	email := fmt.Sprintf("test-cli-account-%d@example.com", time.Now().UnixNano())
	password := "cli-pass-123"

	// Register & setup
	RegisterTestUser(t, testServer, email, password)
	v := APILogin(t, testServer, email, password)
	VerifyUserEmail(t, v, email)

	// change-name
	out := runCLI(t, email, password, "account", "change-name", "--name", "New Account Name")
	assert.Contains(t, string(out), "Name changed to: New Account Name")
}
