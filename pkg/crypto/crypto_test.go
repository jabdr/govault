package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeriveKeyPBKDF2(t *testing.T) {
	key, err := DeriveKey([]byte("password"), []byte("user@example.com"), KdfTypePBKDF2, 600000, nil, nil)
	require.NoError(t, err, "DeriveKey PBKDF2")
	assert.Len(t, key, 32, "expected 32 bytes")

	// Verify determinism
	key2, _ := DeriveKey([]byte("password"), []byte("user@example.com"), KdfTypePBKDF2, 600000, nil, nil)
	assert.True(t, bytes.Equal(key, key2), "PBKDF2 not deterministic")
}

func TestDeriveKeyArgon2(t *testing.T) {
	salt := make([]byte, 32) // 32-byte salt
	mem := 64 * 1024         // 64 MB
	par := 4
	key, err := DeriveKey([]byte("password"), salt, KdfTypeArgon2, 3, &mem, &par)
	require.NoError(t, err, "DeriveKey Argon2")
	assert.Len(t, key, 32, "expected 32 bytes")
}

func TestDeriveKeyArgon2MissingParams(t *testing.T) {
	_, err := DeriveKey([]byte("password"), make([]byte, 32), KdfTypeArgon2, 3, nil, nil)
	require.Error(t, err, "expected error for missing argon2 params")
}

func TestStretchKey(t *testing.T) {
	masterKey := make([]byte, 32)
	stretched, err := StretchKey(masterKey)
	require.NoError(t, err, "StretchKey")
	assert.Len(t, stretched, 64, "expected 64 bytes")

	// Verify determinism
	stretched2, _ := StretchKey(masterKey)
	assert.True(t, bytes.Equal(stretched, stretched2), "StretchKey not deterministic")
}

func TestStretchKeyInvalidLength(t *testing.T) {
	_, err := StretchKey(make([]byte, 16))
	require.Error(t, err, "expected error for non-32-byte key")
}

func TestHashPassword(t *testing.T) {
	masterKey := make([]byte, 32)
	hash := HashPassword("password", masterKey)
	assert.NotEmpty(t, hash, "HashPassword returned empty string")

	// Verify determinism
	hash2 := HashPassword("password", masterKey)
	assert.Equal(t, hash, hash2, "HashPassword not deterministic")
}

func TestAESEncryptDecryptRoundtrip(t *testing.T) {
	plaintext := []byte("hello, bitwarden!")
	encKey := make([]byte, 32)
	macKey := make([]byte, 32)
	rand.Read(encKey)
	rand.Read(macKey)

	iv, ct, mac, err := Encrypt(plaintext, encKey, macKey)
	require.NoError(t, err, "Encrypt")

	decrypted, err := Decrypt(iv, ct, mac, encKey, macKey)
	require.NoError(t, err, "Decrypt")

	assert.Equal(t, plaintext, decrypted, "roundtrip failed")
}

func TestAESEmptyPlaintext(t *testing.T) {
	encKey := make([]byte, 32)
	macKey := make([]byte, 32)
	rand.Read(encKey)
	rand.Read(macKey)

	iv, ct, mac, err := Encrypt([]byte{}, encKey, macKey)
	require.NoError(t, err, "Encrypt empty")

	decrypted, err := Decrypt(iv, ct, mac, encKey, macKey)
	require.NoError(t, err, "Decrypt empty")

	assert.Empty(t, decrypted, "expected empty result")
}

func TestAESHMACRejection(t *testing.T) {
	plaintext := []byte("test data")
	encKey := make([]byte, 32)
	macKey := make([]byte, 32)
	rand.Read(encKey)
	rand.Read(macKey)

	iv, ct, mac, err := Encrypt(plaintext, encKey, macKey)
	require.NoError(t, err, "Encrypt")

	// Tamper with ciphertext
	ct[0] ^= 0xff
	_, err = Decrypt(iv, ct, mac, encKey, macKey)
	require.Error(t, err, "expected HMAC verification error for tampered data")
}

func TestEncStringParseSerializeRoundtrip(t *testing.T) {
	// Create a real encrypted string
	key, _ := GenerateSymmetricKey()
	original := []byte("secret vault item")

	enc, err := EncryptToEncString(original, key)
	require.NoError(t, err, "EncryptToEncString")

	// Serialize
	s := enc.String()
	assert.NotEmpty(t, s, "String() returned empty")

	// Parse
	parsed, err := ParseEncString(s)
	require.NoError(t, err, "ParseEncString")

	assert.Equal(t, 2, parsed.Type, "expected type 2")
	assert.Equal(t, enc.IV, parsed.IV, "IV mismatch")
	assert.Equal(t, enc.CT, parsed.CT, "CT mismatch")
	assert.Equal(t, enc.MAC, parsed.MAC, "MAC mismatch")

	// Decrypt
	decrypted, err := parsed.Decrypt(key)
	require.NoError(t, err, "Decrypt")
	assert.Equal(t, original, decrypted, "decrypted content mismatch")
}

func TestEncStringParseType4(t *testing.T) {
	// Type 4 is just "4.base64data"
	s := "4.dGVzdGRhdGE="
	enc, err := ParseEncString(s)
	require.NoError(t, err, "ParseEncString type 4")

	assert.Equal(t, 4, enc.Type, "expected type 4")
	assert.Equal(t, "testdata", string(enc.CT), "CT mismatch")

	// Round-trip
	assert.Equal(t, s, enc.String(), "String() mismatch")
}

func TestEncStringParseErrors(t *testing.T) {
	cases := []string{
		"",
		"missing_dot",
		"3.unsupported",
		"2.only_one_part",
		"2.two|parts",
	}
	for _, c := range cases {
		_, err := ParseEncString(c)
		assert.Error(t, err, "expected error for %q", c)
	}
}

func TestRSAEncryptDecryptRoundtrip(t *testing.T) {
	pub, priv, err := GenerateRSAKeyPair()
	require.NoError(t, err, "GenerateRSAKeyPair")

	plaintext := []byte("organization secret key data")

	encrypted, err := RSAEncrypt(plaintext, pub)
	require.NoError(t, err, "RSAEncrypt")

	decrypted, err := RSADecrypt(encrypted, priv)
	require.NoError(t, err, "RSADecrypt")

	assert.Equal(t, plaintext, decrypted, "RSA roundtrip failed")
}

func TestRSADecryptEncString(t *testing.T) {
	pub, priv, err := GenerateRSAKeyPair()
	require.NoError(t, err, "GenerateRSAKeyPair")

	plaintext := []byte("test")
	encrypted, _ := RSAEncrypt(plaintext, pub)
	enc := EncString{Type: 4, CT: encrypted}

	decrypted, err := RSADecryptEncString(enc, priv)
	require.NoError(t, err, "RSADecryptEncString")
	assert.Equal(t, plaintext, decrypted, "mismatch")
}

func TestEncryptOrgKeyForMember(t *testing.T) {
	pub, priv, err := GenerateRSAKeyPair()
	require.NoError(t, err, "GenerateRSAKeyPair")

	orgKey, _ := GenerateSymmetricKey()

	encKeyStr, err := EncryptOrgKeyForMember(orgKey, pub)
	require.NoError(t, err, "EncryptOrgKeyForMember")

	enc, err := ParseEncString(encKeyStr)
	require.NoError(t, err, "ParseEncString")

	decrypted, err := RSADecryptEncString(enc, priv)
	require.NoError(t, err, "RSADecryptEncString")

	recoveredKey, err := MakeSymmetricKey(decrypted)
	require.NoError(t, err, "MakeSymmetricKey")

	assert.Equal(t, orgKey.EncKey, recoveredKey.EncKey, "org key enc roundtrip failed")
	assert.Equal(t, orgKey.MacKey, recoveredKey.MacKey, "org key mac roundtrip failed")
}

func TestSymmetricKeyRoundtrip(t *testing.T) {
	// Generate a symmetric key, encrypt it with a stretched key, decrypt
	symKey, err := GenerateSymmetricKey()
	require.NoError(t, err, "GenerateSymmetricKey")

	// Create a master key and stretch it
	masterKey := make([]byte, 32)
	rand.Read(masterKey)
	stretched, err := StretchKey(masterKey)
	require.NoError(t, err, "StretchKey")

	stretchedKey, err := MakeSymmetricKey(stretched)
	require.NoError(t, err, "MakeSymmetricKey")

	// Encrypt the symmetric key
	protectedKey, err := EncryptToEncString(symKey.Bytes(), stretchedKey)
	require.NoError(t, err, "EncryptToEncString")

	// Decrypt
	recovered, err := DecryptSymmetricKey(protectedKey, stretched)
	require.NoError(t, err, "DecryptSymmetricKey")

	assert.Equal(t, symKey.EncKey, recovered.EncKey, "symmetric enc key roundtrip mismatch")
	assert.Equal(t, symKey.MacKey, recovered.MacKey, "symmetric mac key roundtrip mismatch")
}

func TestSendKeyDerivation(t *testing.T) {
	secret, err := GenerateSendSecret()
	require.NoError(t, err, "GenerateSendSecret")
	assert.Len(t, secret, SendSecretSize, "expected SendSecretSize bytes")

	key, err := DeriveSendKey(secret)
	require.NoError(t, err, "DeriveSendKey")
	assert.Len(t, key.EncKey, 32, "invalid enc key size")
	assert.Len(t, key.MacKey, 32, "invalid mac key size")

	// Determinism
	key2, _ := DeriveSendKey(secret)
	assert.Equal(t, key.EncKey, key2.EncKey, "DeriveSendKey not deterministic (EncKey)")
	assert.Equal(t, key.MacKey, key2.MacKey, "DeriveSendKey not deterministic (MacKey)")
}

func TestSendKeyFromAccessURL(t *testing.T) {
	secret, _ := GenerateSendSecret()
	encoded := EncodeSendSecret(secret)

	key1, _ := DeriveSendKey(secret)
	key2, err := SendKeyFromAccessURL(encoded)
	require.NoError(t, err, "SendKeyFromAccessURL")

	assert.Equal(t, key1.EncKey, key2.EncKey, "send enc key from URL mismatch")
	assert.Equal(t, key1.MacKey, key2.MacKey, "send mac key from URL mismatch")
}

func TestSendEncryptDecryptRoundtrip(t *testing.T) {
	secret, _ := GenerateSendSecret()
	sendKey, _ := DeriveSendKey(secret)

	plaintext := []byte("this is a secret send message")
	enc, err := EncryptToEncString(plaintext, sendKey)
	require.NoError(t, err, "EncryptToEncString")

	decrypted, err := enc.Decrypt(sendKey)
	require.NoError(t, err, "Decrypt")

	assert.Equal(t, plaintext, decrypted, "send roundtrip failed")
}
