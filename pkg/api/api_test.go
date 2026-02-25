package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestPrelogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/identity/accounts/prelogin", r.URL.Path, "unexpected path")
		require.Equal(t, http.MethodPost, r.Method, "unexpected method")

		var req PreloginRequest
		json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, "test@example.com", req.Email, "unexpected email")

		json.NewEncoder(w).Encode(PreloginResponse{
			Kdf:           0,
			KdfIterations: 600000,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, testLogger())
	resp, err := client.Prelogin("test@example.com")
	require.NoError(t, err, "Prelogin")
	assert.Equal(t, 0, resp.Kdf, "expected kdf 0")
	assert.Equal(t, 600000, resp.KdfIterations, "expected 600000 iterations")
}

func TestLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/identity/connect/token", r.URL.Path, "unexpected path")
		r.ParseForm()
		assert.Equal(t, "password", r.Form.Get("grant_type"), "expected grant_type=password")
		assert.Equal(t, "test@example.com", r.Form.Get("username"), "unexpected username")
		assert.Equal(t, "web", r.Form.Get("client_id"), "unexpected client_id")

		json.NewEncoder(w).Encode(LoginResponse{
			AccessToken:  "test-access-token",
			RefreshToken: "test-refresh-token",
			Key:          "2.iv|ct|mac",
			PrivateKey:   "2.iv|ct|mac",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, testLogger())
	resp, err := client.Login("test@example.com", "passwordhash", "device-id")
	require.NoError(t, err, "Login")
	assert.Equal(t, "test-access-token", resp.AccessToken, "unexpected access token")
	assert.Equal(t, "test-access-token", client.accessToken, "client token not set after login")
}

func TestCipherCRUD(t *testing.T) {
	var lastMethod, lastPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastMethod = r.Method
		lastPath = r.URL.Path
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/ciphers":
			json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{
					{"id": "cipher-1", "name": "Test"},
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/ciphers/cipher-1":
			json.NewEncoder(w).Encode(map[string]any{"id": "cipher-1"})
		case r.Method == http.MethodPost && r.URL.Path == "/api/ciphers":
			json.NewEncoder(w).Encode(map[string]any{"id": "new-cipher"})
		case r.Method == http.MethodPut && r.URL.Path == "/api/ciphers/cipher-1":
			json.NewEncoder(w).Encode(map[string]any{"id": "cipher-1"})
		case r.Method == http.MethodDelete && r.URL.Path == "/api/ciphers/cipher-1":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, testLogger())

	// List
	ciphers, err := client.GetCiphers()
	require.NoError(t, err, "GetCiphers")
	assert.Len(t, ciphers, 1, "expected 1 cipher")

	// Get
	cipher, err := client.GetCipher("cipher-1")
	require.NoError(t, err, "GetCipher")
	assert.Equal(t, "cipher-1", cipher["id"], "unexpected cipher id")

	// Create
	created, err := client.CreateCipher(map[string]any{"name": "New"})
	require.NoError(t, err, "CreateCipher")
	assert.Equal(t, "new-cipher", created["id"], "unexpected created id")

	// Update
	_, err = client.UpdateCipher("cipher-1", map[string]any{"name": "Updated"})
	require.NoError(t, err, "UpdateCipher")

	// Delete
	err = client.DeleteCipher("cipher-1")
	require.NoError(t, err, "DeleteCipher")
	assert.Equal(t, http.MethodDelete, lastMethod, "unexpected delete method")
	assert.Equal(t, "/api/ciphers/cipher-1", lastPath, "unexpected delete path")
}

func TestSync(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/sync", r.URL.Path, "unexpected path")
		require.Equal(t, http.MethodGet, r.Method, "unexpected method")

		json.NewEncoder(w).Encode(SyncResponse{
			Profile: SyncProfile{Email: "test@example.com"},
			Ciphers: []map[string]any{{"id": "c1"}},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, testLogger())
	resp, err := client.Sync()
	require.NoError(t, err, "Sync")
	assert.Equal(t, "test@example.com", resp.Profile.Email, "unexpected email")
	assert.Len(t, resp.Ciphers, 1, "expected 1 cipher")
}

func TestAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, testLogger())
	_, err := client.Prelogin("test@example.com")
	require.Error(t, err, "expected error for 401")

	_, ok := err.(*APIError)
	assert.False(t, ok, "error is wrapped, shouldn't be directly castable to *APIError")
}

func TestListSends(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/sends", r.URL.Path, "unexpected path")
		json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"id": "send-1", "type": 0, "name": "enc-name"},
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, testLogger())
	sends, err := client.ListSends()
	require.NoError(t, err, "ListSends")
	assert.Len(t, sends, 1, "expected 1 send")
}

func TestEmergencyAccessList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"id": "ea-1", "type": 0, "status": 2},
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, testLogger())
	trusted, err := client.ListTrustedEmergencyAccess()
	require.NoError(t, err, "ListTrustedEmergencyAccess")
	assert.Len(t, trusted, 1, "expected 1 entry")
}

func TestListCollections(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"id": "col-1", "name": "enc-name", "organizationId": "org-1"},
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, testLogger())
	cols, err := client.ListCollections("org-1")
	require.NoError(t, err, "ListCollections")
	assert.Len(t, cols, 1, "expected 1 collection")
}
