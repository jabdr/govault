package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

// Encrypt encrypts data using AES-256-CBC with PKCS7 padding and produces
// an HMAC-SHA256 MAC over (iv || ciphertext).
func Encrypt(data, encKey, macKey []byte) (iv, ct, mac []byte, err error) {
	if len(encKey) != 32 {
		return nil, nil, nil, fmt.Errorf("crypto: AES enc key must be 32 bytes, got %d", len(encKey))
	}
	if len(macKey) != 32 {
		return nil, nil, nil, fmt.Errorf("crypto: AES mac key must be 32 bytes, got %d", len(macKey))
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("crypto: new AES cipher: %w", err)
	}

	// Generate random IV
	iv = make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, nil, fmt.Errorf("crypto: generate IV: %w", err)
	}

	// PKCS7 pad
	padded := pkcs7Pad(data, aes.BlockSize)

	// CBC encrypt
	ct = make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ct, padded)

	// HMAC-SHA256 over iv || ct
	mac = computeMAC(iv, ct, macKey)

	return iv, ct, mac, nil
}

// Decrypt verifies the HMAC-SHA256 MAC and then decrypts AES-256-CBC
// ciphertext, removing PKCS7 padding.
func Decrypt(iv, ct, mac, encKey, macKey []byte) ([]byte, error) {
	if len(encKey) != 32 {
		return nil, fmt.Errorf("crypto: AES enc key must be 32 bytes, got %d", len(encKey))
	}
	if len(macKey) != 32 {
		return nil, fmt.Errorf("crypto: AES mac key must be 32 bytes, got %d", len(macKey))
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("crypto: IV must be %d bytes, got %d", aes.BlockSize, len(iv))
	}
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("crypto: ciphertext length %d is not a multiple of block size", len(ct))
	}

	// Verify MAC
	expectedMAC := computeMAC(iv, ct, macKey)
	if subtle.ConstantTimeCompare(mac, expectedMAC) != 1 {
		return nil, fmt.Errorf("crypto: HMAC verification failed")
	}

	// CBC decrypt
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: new AES cipher: %w", err)
	}

	plaintext := make([]byte, len(ct))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ct)

	// Remove PKCS7 padding
	plaintext, err = pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("crypto: %w", err)
	}

	return plaintext, nil
}

func computeMAC(iv, ct, macKey []byte) []byte {
	h := hmac.New(sha256.New, macKey)
	h.Write(iv)
	h.Write(ct)
	return h.Sum(nil)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("pkcs7 unpad: empty data")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize || padding > len(data) {
		return nil, fmt.Errorf("pkcs7 unpad: invalid padding value %d", padding)
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("pkcs7 unpad: invalid padding byte at position %d", i)
		}
	}
	return data[:len(data)-padding], nil
}
