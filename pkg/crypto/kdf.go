// Package crypto implements the Bitwarden client-side encryption primitives.
// It covers key derivation (PBKDF2, Argon2id), key stretching (HKDF),
// AES-256-CBC + HMAC-SHA256 encryption, RSA-OAEP key exchange,
// the Bitwarden EncString format, and Send key derivation.
package crypto

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// KDF type constants matching the Bitwarden API.
const (
	KdfTypePBKDF2 = 0
	KdfTypeArgon2 = 1
)

// DeriveKey derives a 32-byte master key from a password and salt using the
// specified KDF algorithm. For PBKDF2 the salt is typically the user's email
// (lowercased). For Argon2id the salt is a raw 32-byte value returned by
// the server.
func DeriveKey(password, salt []byte, kdfType, iterations int, memory, parallelism *int) ([]byte, error) {
	switch kdfType {
	case KdfTypePBKDF2:
		return derivePBKDF2(password, salt, iterations)
	case KdfTypeArgon2:
		if memory == nil || parallelism == nil {
			return nil, fmt.Errorf("crypto: argon2id requires memory and parallelism parameters")
		}
		return deriveArgon2(password, salt, iterations, *memory, *parallelism)
	default:
		return nil, fmt.Errorf("crypto: unsupported KDF type %d", kdfType)
	}
}

func derivePBKDF2(password, salt []byte, iterations int) ([]byte, error) {
	if iterations < 1 {
		return nil, fmt.Errorf("crypto: PBKDF2 iterations must be >= 1, got %d", iterations)
	}
	key := pbkdf2.Key(password, salt, iterations, 32, sha256.New)
	return key, nil
}

func deriveArgon2(password, salt []byte, iterations, memoryKB, parallelism int) ([]byte, error) {
	if len(salt) < 16 {
		return nil, fmt.Errorf("crypto: argon2id salt must be at least 16 bytes, got %d", len(salt))
	}
	key := argon2.IDKey(password, salt, uint32(iterations), uint32(memoryKB), uint8(parallelism), 32)
	return key, nil
}
