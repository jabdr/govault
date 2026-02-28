package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// generateTestCerts creates a temporary directory with certs.pem and key.pem.
// Returns the directory path and cleanup function.
func generateTestCerts() (string, error) {
	dir, err := os.MkdirTemp("", "govault-certs-*")
	if err != nil {
		return "", err
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		os.RemoveAll(dir)
		return "", err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		os.RemoveAll(dir)
		return "", err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"GoVault Test"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		os.RemoveAll(dir)
		return "", err
	}

	certOut, err := os.Create(filepath.Join(dir, "certs.pem"))
	if err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		os.RemoveAll(dir)
		return "", err
	}

	keyOut, err := os.Create(filepath.Join(dir, "key.pem"))
	if err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	defer keyOut.Close()

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		os.RemoveAll(dir)
		return "", err
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		os.RemoveAll(dir)
		return "", err
	}

	return dir, nil
}
