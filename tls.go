package applemusic

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"time"
)

// Apple Root CA G3 is present in the supplied APK's res/raw/apple_ca.pem.
// Independently matched to https://www.apple.com/certificateauthority/AppleRootCA-G3.cer.
// This adds app-local trust only; it never modifies the system certificate store.
//
//go:embed apple_root_g3.pem
var appleRootG3 []byte

func defaultHTTPClient() (*http.Client, error) {
	block, _ := pem.Decode(appleRootG3)
	if block == nil {
		return nil, errors.New("Apple trust anchor unavailable")
	}
	digest := sha256.Sum256(block.Bytes)
	if hex.EncodeToString(digest[:]) != "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179" {
		return nil, errors.New("Apple trust anchor does not match the supplied APK")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid Apple trust anchor")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, errors.New("system trust store unavailable")
	}
	roots.AddCert(cert)
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 15 * time.Second, IdleConnTimeout: 90 * time.Second,
		ForceAttemptHTTP2: true,
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}, nil
}
