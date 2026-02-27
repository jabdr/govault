package crypto

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// EncString represents a Bitwarden encrypted string.
//
// Format:
//   - Type 2 (AES-CBC-256 + HMAC): "2.base64(iv)|base64(ct)|base64(mac)"
//   - Type 4 (RSA-OAEP-SHA1):      "4.base64(rsaEncryptedData)"
type EncString struct {
	Type int
	IV   []byte // only for type 2
	CT   []byte
	MAC  []byte // only for type 2
}

// ParseEncString parses a Bitwarden encrypted string into its components.
func ParseEncString(s string) (EncString, error) {
	if s == "" {
		return EncString{}, fmt.Errorf("crypto: empty encrypted string")
	}

	// Split type prefix from data
	dotIdx := strings.IndexByte(s, '.')
	if dotIdx < 0 {
		return EncString{}, fmt.Errorf("crypto: missing type prefix in encrypted string")
	}

	typeStr := s[:dotIdx]
	data := s[dotIdx+1:]

	var encType int
	switch typeStr {
	case "2":
		encType = 2
	case "4":
		encType = 4
	default:
		return EncString{}, fmt.Errorf("crypto: unsupported encryption type %q", typeStr)
	}

	switch encType {
	case 2:
		return parseType2(data)
	case 4:
		return parseType4(data)
	default:
		return EncString{}, fmt.Errorf("crypto: unsupported encryption type %d", encType)
	}
}

func parseType2(data string) (EncString, error) {
	parts := strings.SplitN(data, "|", 3)
	if len(parts) != 3 {
		return EncString{}, fmt.Errorf("crypto: type 2 encrypted string must have 3 parts (iv|ct|mac), got %d", len(parts))
	}

	iv, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return EncString{}, fmt.Errorf("crypto: decode IV: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return EncString{}, fmt.Errorf("crypto: decode ciphertext: %w", err)
	}
	mac, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return EncString{}, fmt.Errorf("crypto: decode MAC: %w", err)
	}

	return EncString{Type: 2, IV: iv, CT: ct, MAC: mac}, nil
}

func parseType4(data string) (EncString, error) {
	ct, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return EncString{}, fmt.Errorf("crypto: decode RSA ciphertext: %w", err)
	}
	return EncString{Type: 4, CT: ct}, nil
}

// String serializes the EncString back to its Bitwarden wire format.
func (e EncString) String() string {
	switch e.Type {
	case 2:
		return fmt.Sprintf("2.%s|%s|%s",
			base64.StdEncoding.EncodeToString(e.IV),
			base64.StdEncoding.EncodeToString(e.CT),
			base64.StdEncoding.EncodeToString(e.MAC),
		)
	case 4:
		return fmt.Sprintf("4.%s",
			base64.StdEncoding.EncodeToString(e.CT),
		)
	default:
		return ""
	}
}

// Decrypt decrypts a type 2 EncString using the given SymmetricKey.
// For type 4 (RSA), use RSADecryptEncString instead.
func (e EncString) Decrypt(key *SymmetricKey) ([]byte, error) {
	if e.Type != 2 {
		return nil, fmt.Errorf("crypto: EncString.Decrypt only supports type 2, got type %d", e.Type)
	}
	return Decrypt(e.IV, e.CT, e.MAC, key.EncKey, key.MacKey)
}

// EncryptToEncString encrypts plaintext and returns a type 2 EncString.
func EncryptToEncString(plaintext []byte, key *SymmetricKey) (EncString, error) {
	iv, ct, mac, err := Encrypt(plaintext, key.EncKey, key.MacKey)
	if err != nil {
		return EncString{}, err
	}
	return EncString{Type: 2, IV: iv, CT: ct, MAC: mac}, nil
}

// IsZero returns true if the EncString is uninitialized.
func (e EncString) IsZero() bool {
	return e.Type == 0 && len(e.CT) == 0
}

// ToBytes packs the EncString into Bitwarden's binary format.
// Format for type 2: Type (1 byte) + IV (16) + MAC (32) + CT
func (e EncString) ToBytes() []byte {
	if e.Type != 2 {
		return nil
	}
	buf := make([]byte, 1+len(e.IV)+len(e.MAC)+len(e.CT))
	buf[0] = byte(e.Type)
	copy(buf[1:], e.IV)
	copy(buf[1+len(e.IV):], e.MAC)
	copy(buf[1+len(e.IV)+len(e.MAC):], e.CT)
	return buf
}

// ParseEncBytes parses a Bitwarden encrypted string from its binary format.
func ParseEncBytes(data []byte) (EncString, error) {
	if len(data) < 1 {
		return EncString{}, fmt.Errorf("crypto: empty binary encrypted string")
	}
	if data[0] == 2 {
		if len(data) < 1+16+32 {
			return EncString{}, fmt.Errorf("crypto: binary data too short for type 2")
		}
		iv := make([]byte, 16)
		copy(iv, data[1:17])
		mac := make([]byte, 32)
		copy(mac, data[17:49])
		ct := make([]byte, len(data)-49)
		copy(ct, data[49:])
		return EncString{Type: 2, IV: iv, MAC: mac, CT: ct}, nil
	}
	return EncString{}, fmt.Errorf("crypto: unsupported binary type %d", data[0])
}
