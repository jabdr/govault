package api

import (
	"crypto/tls"
	"net/http"
)

// NewTLSTransport creates an http.Transport with sensible TLS defaults.
// It clones the default transport and sets TLS 1.2 as the minimum version.
// If insecureSkipVerify is true, certificate verification is disabled.
func NewTLSTransport(insecureSkipVerify bool) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{} // nolint:gosec
	}
	t.TLSClientConfig.MinVersion = tls.VersionTLS12
	t.TLSClientConfig.InsecureSkipVerify = insecureSkipVerify
	return t
}
