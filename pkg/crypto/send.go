package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// SendSecretSize is the size in bytes of the random secret generated for
// each Bitwarden Send (128 bits).
const SendSecretSize = 16

// GenerateSendSecret generates a 16-byte (128-bit) cryptographically random
// secret for a new Send.
func GenerateSendSecret() ([]byte, error) {
	secret := make([]byte, SendSecretSize)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("crypto: generate send secret: %w", err)
	}
	return secret, nil
}

// DeriveSendKey derives a 64-byte SymmetricKey from a 16-byte Send secret
// using HKDF-SHA256 with "bitwarden-send" as the salt and "send" as the info parameter.
// The first 32 bytes are the encryption key, the second 32 bytes the MAC key.
func DeriveSendKey(secret []byte) (*SymmetricKey, error) {
	if len(secret) != SendSecretSize {
		return nil, fmt.Errorf("crypto: send secret must be %d bytes, got %d", SendSecretSize, len(secret))
	}

	r := hkdf.New(sha256.New, secret, []byte("bitwarden-send"), []byte("send"))
	key := make([]byte, 64)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("crypto: HKDF derive send key: %w", err)
	}

	return MakeSymmetricKey(key)
}

// SendKeyFromAccessURL decodes a base64url-encoded secret from a Send
// access URL fragment and derives the Send encryption key.
func SendKeyFromAccessURL(urlFragment string) (*SymmetricKey, error) {
	secret, err := base64.RawURLEncoding.DecodeString(urlFragment)
	if err != nil {
		return nil, fmt.Errorf("crypto: decode send URL fragment: %w", err)
	}
	return DeriveSendKey(secret)
}

// EncodeSendSecret encodes a Send secret as a base64url string suitable
// for use in a Send access URL fragment.
func EncodeSendSecret(secret []byte) string {
	return base64.RawURLEncoding.EncodeToString(secret)
}
