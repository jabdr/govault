package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"fmt"
)

// RSAKeySize is the key size used by Bitwarden for RSA key pairs.
const RSAKeySize = 2048

// GenerateRSAKeyPair generates a new RSA-2048 key pair and returns the
// public key in PKIX DER format and private key in PKCS8 DER format.
func GenerateRSAKeyPair() (publicKeyDER, privateKeyDER []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: generate RSA key: %w", err)
	}

	publicKeyDER, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: marshal public key: %w", err)
	}

	privateKeyDER, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: marshal private key: %w", err)
	}

	return publicKeyDER, privateKeyDER, nil
}

// RSAEncrypt encrypts data using RSA-OAEP with SHA-1 (as Bitwarden uses).
func RSAEncrypt(data, publicKeyDER []byte) ([]byte, error) {
	pub, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("crypto: not an RSA public key")
	}

	encrypted, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, rsaPub, data, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: RSA encrypt: %w", err)
	}
	return encrypted, nil
}

// RSADecrypt decrypts data using RSA-OAEP with SHA-1.
func RSADecrypt(data, privateKeyDER []byte) ([]byte, error) {
	privKey, err := parsePrivateKey(privateKeyDER)
	if err != nil {
		return nil, err
	}

	decrypted, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, privKey, data, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: RSA decrypt: %w", err)
	}
	return decrypted, nil
}

// DecryptPrivateKey decrypts an RSA private key that is stored encrypted
// in the vault (as a type 2 EncString).
func DecryptPrivateKey(encPrivateKey EncString, symKey *SymmetricKey) ([]byte, error) {
	return encPrivateKey.Decrypt(symKey)
}

// RSADecryptEncString decrypts a type 4 EncString using an RSA private key.
func RSADecryptEncString(enc EncString, privateKeyDER []byte) ([]byte, error) {
	if enc.Type != 4 {
		return nil, fmt.Errorf("crypto: RSADecryptEncString requires type 4, got type %d", enc.Type)
	}
	return RSADecrypt(enc.CT, privateKeyDER)
}

// EncryptOrgKeyForMember RSA-encrypts an organization's symmetric key
// using a member's public key. Returns the encrypted key as a type 4
// EncString in its string form.
func EncryptOrgKeyForMember(orgKey *SymmetricKey, memberPublicKeyDER []byte) (string, error) {
	encrypted, err := RSAEncrypt(orgKey.Bytes(), memberPublicKeyDER)
	if err != nil {
		return "", fmt.Errorf("crypto: encrypt org key for member: %w", err)
	}
	enc := EncString{Type: 4, CT: encrypted}
	return enc.String(), nil
}

func parsePrivateKey(der []byte) (*rsa.PrivateKey, error) {
	// Try PKCS8 first (Bitwarden standard)
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("crypto: PKCS8 key is not RSA")
		}
		return rsaKey, nil
	}

	// Fall back to PKCS1
	rsaKey, err2 := x509.ParsePKCS1PrivateKey(der)
	if err2 != nil {
		return nil, fmt.Errorf("crypto: parse private key (PKCS8: %v, PKCS1: %v)", err, err2)
	}
	return rsaKey, nil
}

// PublicKeyFromPrivate extracts the public key in DER format from a private key DER.
func PublicKeyFromPrivate(privateKeyDER []byte) ([]byte, error) {
	key, err := parsePrivateKey(privateKeyDER)
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKIXPublicKey(&key.PublicKey)
}
