package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// SymmetricKey holds a 64-byte key split into a 32-byte encryption key and
// a 32-byte MAC key. This is used for both the user's vault encryption key
// and organization keys.
type SymmetricKey struct {
	EncKey []byte // 32 bytes – AES-256 key
	MacKey []byte // 32 bytes – HMAC-SHA256 key
}

// StretchKey stretches a 32-byte master key into a 64-byte key using
// HKDF-SHA256. The first 32 bytes are the encryption key ("enc"), the
// second 32 bytes are the MAC key ("mac").
func StretchKey(masterKey []byte) ([]byte, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("crypto: master key must be 32 bytes, got %d", len(masterKey))
	}

	stretched := make([]byte, 64)

	// Derive encryption key
	encReader := hkdf.Expand(sha256.New, masterKey, []byte("enc"))
	if _, err := io.ReadFull(encReader, stretched[:32]); err != nil {
		return nil, fmt.Errorf("crypto: HKDF expand enc: %w", err)
	}

	// Derive MAC key
	macReader := hkdf.Expand(sha256.New, masterKey, []byte("mac"))
	if _, err := io.ReadFull(macReader, stretched[32:]); err != nil {
		return nil, fmt.Errorf("crypto: HKDF expand mac: %w", err)
	}

	return stretched, nil
}

// MakeSymmetricKey creates a SymmetricKey from a 64-byte stretched key.
func MakeSymmetricKey(stretched []byte) (*SymmetricKey, error) {
	if len(stretched) != 64 {
		return nil, fmt.Errorf("crypto: stretched key must be 64 bytes, got %d", len(stretched))
	}
	key := &SymmetricKey{
		EncKey: make([]byte, 32),
		MacKey: make([]byte, 32),
	}
	copy(key.EncKey, stretched[:32])
	copy(key.MacKey, stretched[32:])
	return key, nil
}

// HashPassword produces the master password hash sent to the server for
// authentication. It computes PBKDF2-SHA256(masterKey, password, 1) and
// returns the base64-encoded result.
func HashPassword(password string, masterKey []byte) string {
	hash := pbkdf2.Key(masterKey, []byte(password), 1, 32, sha256.New)
	return base64.StdEncoding.EncodeToString(hash)
}

// DecryptSymmetricKey decrypts the server-stored protected symmetric key
// using the stretched master key.
func DecryptSymmetricKey(protectedKey EncString, stretchedKey []byte) (*SymmetricKey, error) {
	sk, err := MakeSymmetricKey(stretchedKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: make symmetric key from stretched: %w", err)
	}

	decrypted, err := protectedKey.Decrypt(sk)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt protected symmetric key: %w", err)
	}

	// The decrypted value is 64 bytes: 32-byte enc key + 32-byte mac key
	if len(decrypted) != 64 {
		return nil, fmt.Errorf("crypto: decrypted symmetric key expected 64 bytes, got %d", len(decrypted))
	}

	return MakeSymmetricKey(decrypted)
}

// GenerateSymmetricKey creates a new random 64-byte symmetric key using
// a cryptographically secure random number generator.
func GenerateSymmetricKey() (*SymmetricKey, error) {
	buf := make([]byte, 64)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("crypto: generate random key: %w", err)
	}
	return MakeSymmetricKey(buf)
}

// Bytes returns the full 64-byte key (enc + mac concatenated).
func (sk *SymmetricKey) Bytes() []byte {
	buf := make([]byte, 64)
	copy(buf[:32], sk.EncKey)
	copy(buf[32:], sk.MacKey)
	return buf
}
