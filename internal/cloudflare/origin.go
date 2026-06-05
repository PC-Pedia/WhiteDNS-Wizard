package cloudflare

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"

	"github.com/whitedns/wdns-wizard/pkg/types"
)

func BuildOriginCertRequest(domain string) (types.OriginCertRequest, string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return types.OriginCertRequest{}, "", fmt.Errorf("generate origin private key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain, "*." + domain},
	}, privateKey)
	if err != nil {
		return types.OriginCertRequest{}, "", fmt.Errorf("generate origin CSR: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return types.OriginCertRequest{}, "", fmt.Errorf("marshal origin private key: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if csrPEM == nil || keyPEM == nil {
		return types.OriginCertRequest{}, "", fmt.Errorf("encode origin certificate material")
	}

	return types.OriginCertRequest{
		Hostnames:         []string{domain, "*." + domain},
		RequestType:       "origin-ecc",
		RequestedValidity: 5475,
		CSRPEM:            string(csrPEM),
	}, string(keyPEM), nil
}
