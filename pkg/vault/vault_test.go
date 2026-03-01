package vault

import (
	"testing"

	"github.com/jabdr/govault/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testKey(t *testing.T) *crypto.SymmetricKey {
	t.Helper()
	key, err := crypto.GenerateSymmetricKey()
	require.NoError(t, err, "GenerateSymmetricKey")
	return key
}

func TestCipherNewAndAccessors(t *testing.T) {
	t.Parallel()
	c, err := NewCipher(CipherTypeLogin, "Test Login", testKey(t))
	require.NoError(t, err)
	assert.Equal(t, CipherTypeLogin, c.Type(), "expected type")
	assert.Equal(t, "Test Login", c.Name(), "expected name")
	assert.Empty(t, c.OrganizationID(), "expected empty org ID")
}

func TestCipherSetGetField(t *testing.T) {
	t.Parallel()
	c, err := NewCipher(CipherTypeLogin, "Test", testKey(t))
	require.NoError(t, err)
	err = c.SetField("customField", "customValue")
	require.NoError(t, err, "SetField")

	val, err := c.GetField("customField")
	require.NoError(t, err, "GetField")
	assert.Equal(t, "customValue", val, "expected 'customValue'")

	_, err = c.GetField("nonexistent")
	require.Error(t, err, "expected error for nonexistent field")
}

func TestCipherLoginGetSet(t *testing.T) {
	t.Parallel()
	c, err := NewCipher(CipherTypeLogin, "Login Entry", testKey(t))
	require.NoError(t, err)
	c.SetLoginUsername("user@example.com")
	c.SetLoginPassword("s3cret!")

	username, password, err := c.GetLogin()
	require.NoError(t, err, "GetLogin")
	assert.Equal(t, "user@example.com", username, "expected username")
	assert.Equal(t, "s3cret!", password, "expected password")
}

func TestCipherEncryptDecryptRoundtrip(t *testing.T) {
	t.Parallel()
	key := testKey(t)

	// Create a cipher with plaintext fields
	original, err := NewCipher(CipherTypeLogin, "My Login", key)
	require.NoError(t, err)
	original.SetLoginUsername("admin")
	original.SetLoginPassword("password123")
	original.SetNotes("some notes")

	// Encrypt
	encrypted, err := original.Encrypt(key)
	require.NoError(t, err, "Encrypt")

	// Verify encrypted fields are EncStrings
	encName, ok := encrypted["name"].(string)
	require.True(t, ok, "name should be a string")

	_, err = crypto.ParseEncString(encName)
	require.NoError(t, err, "encrypted name is not a valid EncString")

	// Decrypt
	decrypted := NewCipherFromMap(encrypted, key)
	assert.Equal(t, "My Login", decrypted.Name(), "decrypted name")

	username, password, err := decrypted.GetLogin()
	require.NoError(t, err, "GetLogin")
	assert.Equal(t, "admin", username, "username")
	assert.Equal(t, "password123", password, "password")
}

func TestCipherRaw(t *testing.T) {
	t.Parallel()
	c, err := NewCipher(CipherTypeSecureNote, "Note", testKey(t))
	require.NoError(t, err)
	raw := c.Raw()
	require.NotNil(t, raw, "Raw() returned nil")
	assert.NotEqual(t, "Note", raw["name"], "expected name to be encrypted")
}

func TestDecryptString(t *testing.T) {
	t.Parallel()
	key := testKey(t)

	// Encrypt a string
	enc, err := crypto.EncryptToEncString([]byte("hello"), key)
	require.NoError(t, err, "EncryptToEncString")

	// Decrypt
	result := decryptString(enc.String(), key)
	assert.Equal(t, "hello", result, "expected 'hello'")

	// Non-encrypted string returns as-is
	result = decryptString("plain text", key)
	assert.Equal(t, "plain text", result, "expected 'plain text'")
}

func TestSymmetricKeyBytesRoundtrip(t *testing.T) {
	t.Parallel()
	key := testKey(t)
	b := key.Bytes()
	assert.Len(t, b, 64, "expected 64 bytes")

	recovered, err := crypto.MakeSymmetricKey(b)
	require.NoError(t, err, "MakeSymmetricKey")
	assert.Equal(t, key.EncKey, recovered.EncKey, "EncKey mismatch")
	assert.Equal(t, key.MacKey, recovered.MacKey, "MacKey mismatch")
}
